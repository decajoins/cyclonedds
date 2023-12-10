// Copyright(c) 2006 to 2023 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <assert.h>
#include <string.h>
#include <math.h>

#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/avl.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_unused.h"
#include "ddsi__entity_index.h"
#include "ddsi__xmsg.h"
#include "ddsi__misc.h"
#include "ddsi__xevent.h"
#include "ddsi__transmit.h"
#include "ddsi__hbcontrol.h"
#include "ddsi__security_omg.h"
#include "ddsi__sysdeps.h"
#include "ddsi__endpoint.h"
#include "ddsi__endpoint_match.h"
#include "ddsi__protocol.h"

static const struct ddsi_wr_prd_match *root_rdmatch (const struct ddsi_writer *wr)
{
  return ddsrt_avl_root (&ddsi_wr_readers_treedef, &wr->readers);
}

void ddsi_writer_hbcontrol_init (struct ddsi_hbcontrol *hbc)
{
  hbc->t_of_last_write.v = 0;
  hbc->t_of_last_hb.v = 0;
  hbc->t_of_last_ackhb.v = 0;
  hbc->tsched = DDSRT_MTIME_NEVER;
  hbc->hbs_since_last_write = 0;
  hbc->last_packetid = 0;
}

static void writer_hbcontrol_note_hb (struct ddsi_writer *wr, ddsrt_mtime_t tnow, enum ddsi_hbcontrol_ack_required ansreq)
{
  struct ddsi_hbcontrol * const hbc = &wr->hbcontrol;

  if (ansreq != DDSI_HBC_ACK_REQ_NO)
    hbc->t_of_last_ackhb = tnow;
  hbc->t_of_last_hb = tnow;

  /* Count number of heartbeats since last write, used to lower the
     heartbeat rate.  Overflow doesn't matter, it'll just revert to a
     highish rate for a short while. */
  hbc->hbs_since_last_write++;
}

int64_t ddsi_writer_hbcontrol_intv (const struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, UNUSED_ARG (ddsrt_mtime_t tnow))
{
  struct ddsi_domaingv const * const gv = wr->e.gv;
  struct ddsi_hbcontrol const * const hbc = &wr->hbcontrol;
  int64_t ret = gv->config.const_hb_intv_sched;
  size_t n_unacked;

  if (hbc->hbs_since_last_write > 5)
  {
    unsigned cnt = (hbc->hbs_since_last_write - 5) / 2;
    while (cnt-- != 0 && 2 * ret < gv->config.const_hb_intv_sched_max)
      ret *= 2;
  }

  n_unacked = whcst->unacked_bytes;
  if (n_unacked >= wr->whc_low + 3 * (wr->whc_high - wr->whc_low) / 4)
    ret /= 2;
  if (n_unacked >= wr->whc_low + (wr->whc_high - wr->whc_low) / 2)
    ret /= 2;
  if (wr->throttling)
    ret /= 2;
  if (ret < gv->config.const_hb_intv_sched_min)
    ret = gv->config.const_hb_intv_sched_min;
  return ret;
}

void ddsi_writer_hbcontrol_note_asyncwrite (struct ddsi_writer *wr, ddsrt_mtime_t tnow)
{
  struct ddsi_domaingv const * const gv = wr->e.gv;
  struct ddsi_hbcontrol * const hbc = &wr->hbcontrol;
  ddsrt_mtime_t tnext;

  /* Reset number of heartbeats since last write: that means the
     heartbeat rate will go back up to the default */
  hbc->hbs_since_last_write = 0;

  /* We know this is new data, so we want a heartbeat event after one
     base interval */
  tnext.v = tnow.v + gv->config.const_hb_intv_sched;
  if (tnext.v < hbc->tsched.v)
  {
    /* Insertion of a message with WHC locked => must now have at
       least one unacked msg if there are reliable readers, so must
       have a heartbeat scheduled.  Do so now */
    hbc->tsched = tnext;
    (void) ddsi_resched_xevent_if_earlier (wr->heartbeat_xevent, tnext);
  }
}

int ddsi_writer_hbcontrol_must_send (const struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, ddsrt_mtime_t tnow /* monotonic */)
{
  struct ddsi_hbcontrol const * const hbc = &wr->hbcontrol;
  return (tnow.v >= hbc->t_of_last_hb.v + ddsi_writer_hbcontrol_intv (wr, whcst, tnow));
}

struct ddsi_xmsg *ddsi_writer_hbcontrol_create_heartbeat (struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, ddsrt_mtime_t tnow, enum ddsi_hbcontrol_ack_required hbansreq, int issync)
{
  struct ddsi_domaingv const * const gv = wr->e.gv;
  struct ddsi_xmsg *msg;
  const ddsi_guid_t *prd_guid;

  ASSERT_MUTEX_HELD (&wr->e.lock);
  assert (wr->reliable);

  if ((msg = ddsi_xmsg_new (gv->xmsgpool, &wr->e.guid, wr->c.pp, sizeof (ddsi_rtps_info_ts_t) + sizeof (ddsi_rtps_heartbeat_t), DDSI_XMSG_KIND_CONTROL)) == NULL)
    /* out of memory at worst slows down traffic */
    return NULL;

  if (ddsrt_avl_is_empty (&wr->readers) || wr->num_reliable_readers == 0)
  {
    /* Not really supposed to come here, at least not for the first
       case. Secondly, there really seems to be little use for
       optimising reliable writers with only best-effort readers. And
       in any case, it is always legal to multicast a heartbeat from a
       reliable writer. */
    prd_guid = NULL;
  }
  else if (wr->seq != root_rdmatch (wr)->max_seq)
  {
    /* If the writer is ahead of its readers, multicast. Couldn't care
       less about the pessimal cases such as multicasting when there
       is one reliable reader & multiple best-effort readers. See
       comment above. */
    prd_guid = NULL;
  }
  else
  {
    const uint32_t n_unacked = wr->num_reliable_readers - root_rdmatch (wr)->num_reliable_readers_where_seq_equals_max;
    if (n_unacked == 0)
      prd_guid = NULL;
    else
    {
      assert (root_rdmatch (wr)->arbitrary_unacked_reader.entityid.u != DDSI_ENTITYID_UNKNOWN);
      if (n_unacked > 1)
        prd_guid = NULL;
      else
        prd_guid = &(root_rdmatch (wr)->arbitrary_unacked_reader);
    }
  }

  ETRACE (wr, "writer_hbcontrol: wr "PGUIDFMT" ", PGUID (wr->e.guid));
  if (prd_guid == NULL)
    ETRACE (wr, "multicasting ");
  else
    ETRACE (wr, "unicasting to prd "PGUIDFMT" ", PGUID (*prd_guid));
  if (ddsrt_avl_is_empty (&wr->readers))
  {
    ETRACE (wr, "(rel-prd %"PRId32" seq-eq-max [none] seq %"PRId64" maxseq [none])\n",
            wr->num_reliable_readers, wr->seq);
  }
  else
  {
    ETRACE (wr, "(rel-prd %"PRId32" seq-eq-max %"PRId32" seq %"PRIu64" maxseq %"PRIu64")\n",
            wr->num_reliable_readers,
            (int32_t) root_rdmatch (wr)->num_reliable_readers_where_seq_equals_max,
            wr->seq,
            root_rdmatch (wr)->max_seq);
  }

  if (prd_guid == NULL)
  {
    ddsi_xmsg_setdst_addrset (msg, wr->as);
    ddsi_add_heartbeat (msg, wr, whcst, hbansreq, 0, ddsi_to_entityid (DDSI_ENTITYID_UNKNOWN), issync);
  }
  else
  {
    struct ddsi_proxy_reader *prd;
    if ((prd = ddsi_entidx_lookup_proxy_reader_guid (gv->entity_index, prd_guid)) == NULL)
    {
      ETRACE (wr, "writer_hbcontrol: wr "PGUIDFMT" unknown prd "PGUIDFMT"\n", PGUID (wr->e.guid), PGUID (*prd_guid));
      ddsi_xmsg_free (msg);
      return NULL;
    }
    /* set the destination explicitly to the unicast destination and the fourth
       param of ddsi_add_heartbeat needs to be the guid of the reader */
    ddsi_xmsg_setdst_prd (msg, prd);
    // send to all readers in the participant: whether or not the entityid is set affects
    // the retransmit requests
    ddsi_add_heartbeat (msg, wr, whcst, hbansreq, 0, ddsi_to_entityid (DDSI_ENTITYID_UNKNOWN), issync);
  }

  /* It is possible that the encoding removed the submessage(s). */
  if (ddsi_xmsg_size(msg) == 0)
  {
    ddsi_xmsg_free (msg);
    msg = NULL;
  }

  writer_hbcontrol_note_hb (wr, tnow, hbansreq);
  return msg;
}

static enum ddsi_hbcontrol_ack_required writer_hbcontrol_ack_required_generic (const struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, ddsrt_mtime_t tlast, ddsrt_mtime_t tnow, int piggyback)
{
  struct ddsi_domaingv const * const gv = wr->e.gv;
  struct ddsi_hbcontrol const * const hbc = &wr->hbcontrol;
  const int64_t hb_intv_ack = gv->config.const_hb_intv_sched;
  assert(wr->heartbeat_xevent != NULL && whcst != NULL);

  if (piggyback)
  {
    /* If it is likely that a heartbeat requiring an ack will go out
       shortly after the sample was written, it is better to piggyback
       it onto the sample.  The current idea is that a write shortly
       before the next heartbeat will go out should have one
       piggybacked onto it, so that the scheduled heartbeat can be
       suppressed. */
    if (tnow.v >= tlast.v + 4 * hb_intv_ack / 5)
      return DDSI_HBC_ACK_REQ_YES_AND_FLUSH;
  }
  else
  {
    /* For heartbeat events use a slightly longer interval */
    if (tnow.v >= tlast.v + hb_intv_ack)
      return DDSI_HBC_ACK_REQ_YES_AND_FLUSH;
  }

  if (whcst->unacked_bytes >= wr->whc_low + (wr->whc_high - wr->whc_low) / 2)
  {
    if (tnow.v >= hbc->t_of_last_ackhb.v + gv->config.const_hb_intv_sched_min)
      return DDSI_HBC_ACK_REQ_YES_AND_FLUSH;
    else if (tnow.v >= hbc->t_of_last_ackhb.v + gv->config.const_hb_intv_min)
      return DDSI_HBC_ACK_REQ_YES;
  }

  return DDSI_HBC_ACK_REQ_NO;
}

enum ddsi_hbcontrol_ack_required ddsi_writer_hbcontrol_ack_required (const struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, ddsrt_mtime_t tnow)
{
  struct ddsi_hbcontrol const * const hbc = &wr->hbcontrol;
  return writer_hbcontrol_ack_required_generic (wr, whcst, hbc->t_of_last_write, tnow, 0);
}

struct ddsi_xmsg *ddsi_writer_hbcontrol_piggyback (struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, ddsrt_mtime_t tnow, uint32_t packetid, enum ddsi_hbcontrol_ack_required *hbansreq)
{
  struct ddsi_hbcontrol * const hbc = &wr->hbcontrol;
  uint32_t last_packetid;
  ddsrt_mtime_t tlast;
  ddsrt_mtime_t t_of_last_hb;
  struct ddsi_xmsg *msg;

  tlast = hbc->t_of_last_write;
  last_packetid = hbc->last_packetid;
  t_of_last_hb = hbc->t_of_last_hb;

  hbc->t_of_last_write = tnow;
  hbc->last_packetid = packetid;

  /* Update statistics, intervals, scheduling of heartbeat event,
     &c. -- there's no real difference between async and sync so we
     reuse the async version. */
  ddsi_writer_hbcontrol_note_asyncwrite (wr, tnow);

  *hbansreq = writer_hbcontrol_ack_required_generic (wr, whcst, tlast, tnow, 1);
  if (*hbansreq >= DDSI_HBC_ACK_REQ_YES_AND_FLUSH) {
    /* So we force a heartbeat in - but we also rely on our caller to
       send the packet out */
    msg = ddsi_writer_hbcontrol_create_heartbeat (wr, whcst, tnow, *hbansreq, 1);
    if (wr->test_suppress_flush_on_sync_heartbeat)
      *hbansreq = DDSI_HBC_ACK_REQ_YES;
  } else if (last_packetid != packetid && tnow.v - t_of_last_hb.v > DDS_USECS (100)) {
    /* If we crossed a packet boundary since the previous write,
       piggyback a heartbeat, with *hbansreq determining whether or
       not an ACK is needed.  We don't force the packet out either:
       this is just to ensure a regular flow of ACKs for cleaning up
       the WHC & for allowing readers to NACK missing samples.

       Still rate-limit: if there are new readers that haven't sent an
       an ACK yet, the FINAL flag will be cleared and so we get an ACK
       storm if writing at a high rate without batching which eats up
       a *large* amount of time because there are out-of-order readers
       present. */
    msg = ddsi_writer_hbcontrol_create_heartbeat (wr, whcst, tnow, *hbansreq, 1);
  } else {
    *hbansreq = DDSI_HBC_ACK_REQ_NO;
    msg = NULL;
  }

  if (msg)
  {
    if (ddsrt_avl_is_empty (&wr->readers))
    {
      ETRACE (wr, "heartbeat(wr "PGUIDFMT"%s) piggybacked, resched in %g s (min-ack [none], avail-seq %"PRIu64", xmit %"PRIu64")\n",
              PGUID (wr->e.guid),
              *hbansreq != DDSI_HBC_ACK_REQ_NO ? "" : " final",
              (hbc->tsched.v == DDS_NEVER) ? INFINITY : (double) (hbc->tsched.v - tnow.v) / 1e9,
              whcst->max_seq, ddsi_writer_read_seq_xmit(wr));
    }
    else
    {
      ETRACE (wr, "heartbeat(wr "PGUIDFMT"%s) piggybacked, resched in %g s (min-ack %"PRIu64"%s, avail-seq %"PRIu64", xmit %"PRIu64")\n",
              PGUID (wr->e.guid),
              *hbansreq != DDSI_HBC_ACK_REQ_NO ? "" : " final",
              (hbc->tsched.v == DDS_NEVER) ? INFINITY : (double) (hbc->tsched.v - tnow.v) / 1e9,
              root_rdmatch (wr)->min_seq,
              root_rdmatch (wr)->all_have_replied_to_hb ? "" : "!",
              whcst->max_seq, ddsi_writer_read_seq_xmit(wr));
    }
  }

  return msg;
}

#ifdef DDS_HAS_SECURITY
struct ddsi_xmsg *ddsi_writer_hbcontrol_p2p(struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, enum ddsi_hbcontrol_ack_required hbansreq, struct ddsi_proxy_reader *prd)
{
  struct ddsi_domaingv const * const gv = wr->e.gv;
  struct ddsi_xmsg *msg;

  ASSERT_MUTEX_HELD (&wr->e.lock);
  assert (wr->reliable);

  if ((msg = ddsi_xmsg_new (gv->xmsgpool, &wr->e.guid, wr->c.pp, sizeof (ddsi_rtps_info_ts_t) + sizeof (ddsi_rtps_heartbeat_t), DDSI_XMSG_KIND_CONTROL)) == NULL)
    return NULL;

  ETRACE (wr, "writer_hbcontrol_p2p: wr "PGUIDFMT" unicasting to prd "PGUIDFMT" ", PGUID (wr->e.guid), PGUID (prd->e.guid));
  if (ddsrt_avl_is_empty (&wr->readers))
  {
    ETRACE (wr, "(rel-prd %d seq-eq-max [none] seq %"PRIu64")\n", wr->num_reliable_readers, wr->seq);
  }
  else
  {
    ETRACE (wr, "(rel-prd %d seq-eq-max %d seq %"PRIu64" maxseq %"PRIu64")\n",
            wr->num_reliable_readers,
            (int32_t) root_rdmatch (wr)->num_reliable_readers_where_seq_equals_max,
            wr->seq,
            root_rdmatch (wr)->max_seq);
  }

  /* set the destination explicitly to the unicast destination and the fourth
     param of ddsi_add_heartbeat needs to be the guid of the reader */
  ddsi_xmsg_setdst_prd (msg, prd);
  ddsi_add_heartbeat (msg, wr, whcst, hbansreq, 0, prd->e.guid.entityid, 1);

  if (ddsi_xmsg_size(msg) == 0)
  {
    ddsi_xmsg_free (msg);
    msg = NULL;
  }

  return msg;
}
#endif

void ddsi_add_heartbeat (struct ddsi_xmsg *msg, struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, enum ddsi_hbcontrol_ack_required hbansreq, int hbliveliness, ddsi_entityid_t dst, int issync)
{
  struct ddsi_domaingv const * const gv = wr->e.gv;
  struct ddsi_xmsg_marker sm_marker;
  ddsi_rtps_heartbeat_t * hb;
  ddsi_seqno_t max, min;

  ASSERT_MUTEX_HELD (&wr->e.lock);

  assert (wr->reliable);
  assert (hbliveliness >= 0);

  if (gv->config.meas_hb_to_ack_latency)
  {
    /* If configured to measure heartbeat-to-ack latency, we must add
       a timestamp.  No big deal if it fails. */
    ddsi_xmsg_add_timestamp (msg, ddsrt_time_wallclock ());
  }

  hb = ddsi_xmsg_append (msg, &sm_marker, sizeof (ddsi_rtps_heartbeat_t));
  ddsi_xmsg_submsg_init (msg, sm_marker, DDSI_RTPS_SMID_HEARTBEAT);

  if (hbansreq == DDSI_HBC_ACK_REQ_NO)
    hb->smhdr.flags |= DDSI_HEARTBEAT_FLAG_FINAL;
  if (hbliveliness)
    hb->smhdr.flags |= DDSI_HEARTBEAT_FLAG_LIVELINESS;

  hb->readerId = ddsi_hton_entityid (dst);
  hb->writerId = ddsi_hton_entityid (wr->e.guid.entityid);
  if (DDSI_WHCST_ISEMPTY(whcst))
  {
    max = wr->seq;
    min = max + 1;
  }
  else
  {
    /* If data present in WHC, wr->seq > 0, but xmit_seq possibly still 0 */
    min = whcst->min_seq;
    max = wr->seq;
    const ddsi_seqno_t seq_xmit = ddsi_writer_read_seq_xmit (wr);
    assert (min <= max);
    /* Informing readers of samples that haven't even been transmitted makes little sense,
       but for transient-local data, we let the first heartbeat determine the time at which
       we trigger wait_for_historical_data, so it had better be correct */
    if (!issync && seq_xmit < max && !wr->handle_as_transient_local)
    {
      /* When: queue data ; queue heartbeat ; transmit data ; update
         seq_xmit, max may be < min.  But we must never advertise the
         minimum available sequence number incorrectly! */
      if (seq_xmit >= min) {
        /* Advertise some but not all data */
        max = seq_xmit;
      } else {
        /* Advertise no data yet */
        max = min - 1;
      }
    }
  }
  hb->firstSN = ddsi_to_seqno (min);
  hb->lastSN = ddsi_to_seqno (max);

  hb->count = wr->hbcount++;

  ddsi_xmsg_submsg_setnext (msg, sm_marker);
  ddsi_security_encode_datawriter_submsg(msg, sm_marker, wr);
}

#ifdef DDS_HAS_SECURITY
static bool send_heartbeat_to_all_readers_check_and_sched (struct ddsi_xevent *ev, struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, ddsrt_mtime_t tnow, ddsrt_mtime_t *t_next, enum ddsi_hbcontrol_ack_required *hbansreq)
{
  bool send_heartbeat = false;
  if (!ddsi_writer_must_have_hb_scheduled (wr, whcst))
    wr->hbcontrol.tsched = DDSRT_MTIME_NEVER;
  else if (!ddsi_writer_hbcontrol_must_send (wr, whcst, tnow))
    wr->hbcontrol.tsched = ddsrt_mtime_add_duration (tnow, ddsi_writer_hbcontrol_intv (wr, whcst, tnow));
  else
  {
    *hbansreq = ddsi_writer_hbcontrol_ack_required (wr, whcst, tnow);
    wr->hbcontrol.tsched = ddsrt_mtime_add_duration (tnow, ddsi_writer_hbcontrol_intv (wr, whcst, tnow));
    send_heartbeat = true;
  }
  ddsi_resched_xevent_if_earlier (ev, wr->hbcontrol.tsched);
  *t_next = wr->hbcontrol.tsched;
  return send_heartbeat;
}

static void send_heartbeat_to_all_readers (struct ddsi_xpack *xp, struct ddsi_xevent *ev, struct ddsi_writer *wr, ddsrt_mtime_t tnow)
{
  struct ddsi_whc_state whcst;
  ddsrt_mtime_t t_next;
  unsigned count = 0;

  ddsrt_mutex_lock (&wr->e.lock);

  ddsi_whc_get_state(wr->whc, &whcst);
  enum ddsi_hbcontrol_ack_required hbansreq;
  if (send_heartbeat_to_all_readers_check_and_sched (ev, wr, &whcst, tnow, &t_next, &hbansreq))
  {
    struct ddsi_wr_prd_match *m;
    struct ddsi_guid last_guid = { .prefix = {.u = {0,0,0}}, .entityid = {0} };

    while ((m = ddsrt_avl_lookup_succ (&ddsi_wr_readers_treedef, &wr->readers, &last_guid)) != NULL)
    {
      last_guid = m->prd_guid;
      if (m->seq < m->last_seq)
      {
        struct ddsi_proxy_reader *prd;

        prd = ddsi_entidx_lookup_proxy_reader_guid (wr->e.gv->entity_index, &m->prd_guid);
        if (prd)
        {
          ETRACE (wr, " heartbeat(wr "PGUIDFMT" rd "PGUIDFMT" %s) send, resched in %g s (min-ack %"PRIu64", avail-seq %"PRIu64")\n",
              PGUID (wr->e.guid),
              PGUID (m->prd_guid),
              hbansreq != DDSI_HBC_ACK_REQ_NO ? "" : " final",
              (double)(t_next.v - tnow.v) / 1e9,
              m->seq,
              m->last_seq);

          struct ddsi_xmsg *msg = ddsi_writer_hbcontrol_p2p (wr, &whcst, hbansreq, prd);
          if (msg != NULL)
          {
            ddsrt_mutex_unlock (&wr->e.lock);
            ddsi_xpack_addmsg (xp, msg, 0);
            ddsrt_mutex_lock (&wr->e.lock);
          }
          count++;
        }
      }
    }
  }

  if (count == 0)
  {
    if (ddsrt_avl_is_empty (&wr->readers))
    {
      ETRACE (wr, "heartbeat(wr "PGUIDFMT") suppressed, resched in %g s (min-ack [none], avail-seq %"PRIu64", xmit %"PRIu64")\n",
              PGUID (wr->e.guid),
              (t_next.v == DDS_NEVER) ? INFINITY : (double)(t_next.v - tnow.v) / 1e9,
              whcst.max_seq,
              ddsi_writer_read_seq_xmit(wr));
    }
    else
    {
      ETRACE (wr, "heartbeat(wr "PGUIDFMT") suppressed, resched in %g s (min-ack %"PRIu64"%s, avail-seq %"PRIu64", xmit %"PRIu64")\n",
              PGUID (wr->e.guid),
              (t_next.v == DDS_NEVER) ? INFINITY : (double)(t_next.v - tnow.v) / 1e9,
              ((struct ddsi_wr_prd_match *) ddsrt_avl_root (&ddsi_wr_readers_treedef, &wr->readers))->min_seq,
              ((struct ddsi_wr_prd_match *) ddsrt_avl_root (&ddsi_wr_readers_treedef, &wr->readers))->all_have_replied_to_hb ? "" : "!",
              whcst.max_seq,
              ddsi_writer_read_seq_xmit(wr));
    }
  }

  ddsrt_mutex_unlock (&wr->e.lock);
}
#endif

/*

这是一个 DDS（Data Distribution Service）中用于处理心跳（heartbeat）事件的回调函数。下面是函数的主要逻辑和功能：

获取写者（writer）实体：

通过写者的 GUID 从实体索引中查找写者实体。如果写者实体不存在，说明写者已经被删除，直接返回。
处理可靠性机制：

确保写者是可靠的。如果写者不可靠，就没有心跳机制的需求。
获取写者的状态：

使用写者的 WHC（Writer History Cache）状态来检查是否需要发送心跳消息。
判断是否需要发送心跳：

如果不需要发送心跳，设置 ACK 请求标志，并根据需要记录相关的调试信息。不发送心跳的情况包括：不需要定期发送、写者被禁用等。
创建心跳消息：

如果需要发送心跳，根据写者的状态信息创建心跳消息。设置心跳的时间戳和相应的 ACK 请求标志。
记录调试信息：

记录相关的调试信息，包括是否发送了心跳、下一次心跳的调度时间等。
重新调度心跳事件：

使用 ddsi_resched_xevent_if_earlier 函数，将心跳事件重新调度到下一次心跳时间。
释放写者锁：

释放写者锁，允许其他线程访问写者。
添加心跳消息到 XP（Xport）：

如果创建了心跳消息，将其添加到 XP 中。在添加消息时，如果测试模式中设置了 test_suppress_heartbeat 标志，则不真正发送心跳，而是打印一条调试信息。
总体而言，这个函数的目的是处理写者的心跳事件，根据写者的状态和配置情况，决定是否发送心跳消息，并在需要时将心跳消息添加到 XP 中。这是 DDS 中实现可靠通信的一部分，用于确保数据通信的可靠性和实时性。
*/
void ddsi_heartbeat_xevent_cb (struct ddsi_domaingv *gv, struct ddsi_xevent *ev, struct ddsi_xpack *xp, void *varg, ddsrt_mtime_t tnow)
{
  struct ddsi_heartbeat_xevent_cb_arg const * const arg = varg;
  struct ddsi_writer *wr;
  if ((wr = ddsi_entidx_lookup_writer_guid (gv->entity_index, &arg->wr_guid)) == NULL)
  {
    GVTRACE("heartbeat(wr "PGUIDFMT") writer gone\n", PGUID (arg->wr_guid));
    return;
  }

  struct ddsi_xmsg *msg;
  ddsrt_mtime_t t_next;
  enum ddsi_hbcontrol_ack_required hbansreq = DDSI_HBC_ACK_REQ_NO;
  struct ddsi_whc_state whcst;

#ifdef DDS_HAS_SECURITY
  if (wr->e.guid.entityid.u == DDSI_ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER)
  {
    send_heartbeat_to_all_readers(xp, ev, wr, tnow);
    return;
  }
#endif

  ddsrt_mutex_lock (&wr->e.lock);
  assert (wr->reliable);
  ddsi_whc_get_state(wr->whc, &whcst);
  if (!ddsi_writer_must_have_hb_scheduled (wr, &whcst))
  {
    hbansreq = DDSI_HBC_ACK_REQ_YES; /* just for avoiding the "final" in the trace output */
    msg = NULL; /* Need not send it now, and no need to schedule it for the future */
    t_next.v = DDS_NEVER;
  }
  else if (!ddsi_writer_hbcontrol_must_send (wr, &whcst, tnow))
  {
    hbansreq = DDSI_HBC_ACK_REQ_YES; /* just for avoiding the "final" in the trace output */
    msg = NULL;
    t_next.v = tnow.v + ddsi_writer_hbcontrol_intv (wr, &whcst, tnow);
  }
  else
  {
    hbansreq = ddsi_writer_hbcontrol_ack_required (wr, &whcst, tnow);
    msg = ddsi_writer_hbcontrol_create_heartbeat (wr, &whcst, tnow, hbansreq, 0);
    t_next.v = tnow.v + ddsi_writer_hbcontrol_intv (wr, &whcst, tnow);
  }

  /*
  
这段代码是在检查写者（wr）关联的读者（readers）是否为空。让我们逐步解释这段代码：

ddsrt_avl_is_empty 是一个函数调用，用于检查 AVL 树（一种自平衡二叉搜索树）是否为空。在这里，AVL 树用于管理与写者相关联的读者。

&wr->readers 是获取写者结构体中读者 AVL 树的地址。

所以，ddsrt_avl_is_empty (&wr->readers) 表示检查写者结构体中的读者 AVL 树是否为空。

在这个上下文中，如果 AVL 树为空，意味着写者当前没有任何关联的读者。这可能表示没有其他实体订阅该写者的数据。在心跳机制的逻辑中，如果没有关联的读者，可能会采取不同的策略，例如减少发送心跳的频率等。
  */
  if (ddsrt_avl_is_empty (&wr->readers))
  {
    GVTRACE ("heartbeat(wr "PGUIDFMT"%s) %s, resched in %g s (min-ack [none], avail-seq %"PRIu64", xmit %"PRIu64")\n",
             PGUID (wr->e.guid),
             hbansreq != DDSI_HBC_ACK_REQ_NO ? "" : " final",
             msg ? "sent" : "suppressed",
             (t_next.v == DDS_NEVER) ? INFINITY : (double)(t_next.v - tnow.v) / 1e9,
             whcst.max_seq, ddsi_writer_read_seq_xmit (wr));
  }
  else
  {
    GVTRACE ("heartbeat(wr "PGUIDFMT"%s) %s, resched in %g s (min-ack %"PRId64"%s, avail-seq %"PRIu64", xmit %"PRIu64")\n",
             PGUID (wr->e.guid),
             hbansreq != DDSI_HBC_ACK_REQ_NO ? "" : " final",
             msg ? "sent" : "suppressed",
             (t_next.v == DDS_NEVER) ? INFINITY : (double)(t_next.v - tnow.v) / 1e9,
             ((struct ddsi_wr_prd_match *) ddsrt_avl_root_non_empty (&ddsi_wr_readers_treedef, &wr->readers))->min_seq,
             ((struct ddsi_wr_prd_match *) ddsrt_avl_root_non_empty (&ddsi_wr_readers_treedef, &wr->readers))->all_have_replied_to_hb ? "" : "!",
             whcst.max_seq, ddsi_writer_read_seq_xmit (wr));
  }
  (void) ddsi_resched_xevent_if_earlier (ev, t_next);
  wr->hbcontrol.tsched = t_next;
  ddsrt_mutex_unlock (&wr->e.lock);

  /* Can't transmit synchronously with writer lock held: trying to add
     the heartbeat to the xp may cause xp to be sent out, which may
     require updating wr->seq_xmit for other messages already in xp.
     Besides, ddsi_xpack_addmsg may sleep for bandwidth-limited channels
     and we certainly don't want to hold the lock during that time. */
  if (msg)
  {
    if (!wr->test_suppress_heartbeat)
      ddsi_xpack_addmsg (xp, msg, 0);
    else
    {
      GVTRACE ("test_suppress_heartbeat\n");
      ddsi_xmsg_free (msg);
    }
  }
}
