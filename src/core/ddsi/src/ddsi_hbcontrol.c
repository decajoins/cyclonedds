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
  //记录发送数据后总共发送了多少次心跳
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
  //记录上一次心跳发送时间
  return (tnow.v >= hbc->t_of_last_hb.v + ddsi_writer_hbcontrol_intv (wr, whcst, tnow));
}

struct ddsi_xmsg *ddsi_writer_hbcontrol_create_heartbeat (struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, ddsrt_mtime_t tnow, enum ddsi_hbcontrol_ack_required hbansreq, int issync)
{
  struct ddsi_domaingv const * const gv = wr->e.gv;
  struct ddsi_xmsg *msg;
  const ddsi_guid_t *prd_guid;

  ASSERT_MUTEX_HELD (&wr->e.lock);
  assert (wr->reliable);
  //创建一个新的消息（msg），消息类型为控制消息（DDSI_XMSG_KIND_CONTROL），消息体大小为心跳信息结构体的大小。如果创建消息失败，返回空指针。
  if ((msg = ddsi_xmsg_new (gv->xmsgpool, &wr->e.guid, wr->c.pp, sizeof (ddsi_rtps_info_ts_t) + sizeof (ddsi_rtps_heartbeat_t), DDSI_XMSG_KIND_CONTROL)) == NULL)
    /* out of memory at worst slows down traffic */
    return NULL;
  //如果该writer没有订阅者（reader，不论可靠与否），或则没有可靠的reader，组播心跳
  if (ddsrt_avl_is_empty (&wr->readers) || wr->num_reliable_readers == 0)
  {
    /* Not really supposed to come here, at least not for the first
       case. Secondly, there really seems to be little use for
       optimising reliable writers with only best-effort readers. And
       in any case, it is always legal to multicast a heartbeat from a
       reliable writer. */
    prd_guid = NULL;
  }
  //如果writer的序列号比所有reader收到的包的最大序号不一致root_rdmatch (wr)->max_seq指和该writer匹配的所有reader（通过wr_prd结构体记录）收到的最大序号的报文，则组播心跳
  //如果写者比所有读者的最大序列号还要靠前，则也将心跳消息设置为组播模式；
  else if (wr->seq != root_rdmatch (wr)->max_seq)
  {
    /* If the writer is ahead of its readers, multicast. Couldn't care
       less about the pessimal cases such as multicasting when there
       is one reliable reader & multiple best-effort readers. See
       comment above. */
    prd_guid = NULL;
  }
  //否则，将心跳消息设置为单播（unicast）模式，目标地址为尚未回复ack的任意一个可靠读者。
  else
  {
    //首先获取写者的可靠读者数量 wr->num_reliable_readers，然后减去所有序列号与最大序列号相等的可靠读者数量（root_rdmatch(wr)->num_reliable_readers_where_seq_equals_max），从而得到未回复ack的可靠读者数量。
    const uint32_t n_unacked = wr->num_reliable_readers - root_rdmatch (wr)->num_reliable_readers_where_seq_equals_max;
    //如果没有未回复ack的可靠读者（n_unacked == 0），则将目标地址设置为 NULL，表示不需要单播心跳消息。
    if (n_unacked == 0)
      prd_guid = NULL;
      //否则，如果存在未回复ack的可靠读者，则进一步判断：如果未回复ack的可靠读者数量大于1（n_unacked > 1），则无法确定将心跳消息发送给哪个读者，因此将目标地址设置为 NULL。
    else
    {
      assert (root_rdmatch (wr)->arbitrary_unacked_reader.entityid.u != DDSI_ENTITYID_UNKNOWN);
      if (n_unacked > 1)
        prd_guid = NULL;
        //如果只有一个未回复ack的可靠读者，则将目标地址设置为该读者的 GUID（prd_guid = &(root_rdmatch(wr)->arbitrary_unacked_reader)）。
      else
        prd_guid = &(root_rdmatch (wr)->arbitrary_unacked_reader);
    }
  }
/*

因此，根据输出的日志信息 "writer_hbcontrol: wr 10274050:43691fa2:8ad07b22:200c2 unicasting to prd 10275e8e:72201f48:dfcf6ecb:200c7 (rel-prd 1 seq-eq-max 0 seq 1 maxseq 1)" 可以得出以下解释：

写者（writer）的 GUID 是 "10274050:43691fa2:8ad07b22:200c2"。
使用单播方式发送心跳消息给代理读者（Proxy Reader），其 GUID 是 "10275e8e:72201f48:dfcf6ecb:200c7"。
可靠代理读者的数量为 1（"rel-prd 1"）。
没有与写者序列号相同的读者（"seq-eq-max 0"）。
写者的序列号是 1（"seq 1"）。
与写者序列号相同的读者所接收到的最大序列号也是 1（"maxseq 1"）。

1 0 0 0 写者的序列号是为0，与写者序列号相同的读者所接收到的最大序列号也是 0，不需要ACK，也不需要传data(r)!!!
*/
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
  //根据目标地址的不同，设置消息的目标地址并调用ddsi_add_heartbeat函数向消息中添加心跳信息
  //组播
  if (prd_guid == NULL)
  {
    ddsi_xmsg_setdst_addrset (msg, wr->as);
    ddsi_add_heartbeat (msg, wr, whcst, hbansreq, 0, ddsi_to_entityid (DDSI_ENTITYID_UNKNOWN), issync);
  }
  //单播
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
  //如果消息编码后的大小为0，说明编码过程中可能移除了子消息（submessage），这种情况下释放消息并返回空指针。
  if (ddsi_xmsg_size(msg) == 0)
  {
    ddsi_xmsg_free (msg);
    msg = NULL;
  }
  //记录心跳发送的相关信息并返回创建的心跳消息。
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
  {//记录需要返回ack的心跳的发送时间
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

/*
heartbeat(wr 10275e8e:72201f48:dfcf6ecb:102) piggybacked, resched in 0.1 s (min-ack 9223372036854775807, avail-seq 0, xmit 6)

没有收到任何确认消息，且当前没有任何可用的消息序列号需要发送。写者已经发送了3条消息。
*/
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
  //（1，0）的情况
  //根据 WHC 状态设置心跳消息中的序列号范围：如果 WHC 为空，则写者的最小序列号为 wr->seq，最大序列号为 wr->seq + 1
  // //（2）	如果远端writer的whc里面没有缓存任何数据，则firstSN表示下一包需要发布的数据的序列号（不是当前发布数据的序列号）
       //，例如当前发布的序列号为10，则firtsSN为11，lastSN为10
  if (DDSI_WHCST_ISEMPTY(whcst))
  {
    max = wr->seq;
    min = max + 1;
  }
  //如果 WHC 不为空，则最小序列号为 WHC 的最小序列号，最大序列号为写者的当前序列号。
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
       //在某些情况下，需要根据是否同步（issync）、是否为瞬态局部数据（transient-local data）以及数据是否已传输来调整最小和最大序列号。
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
  //设置心跳消息中的序列号范围 firstSN 和 lastSN，递增心跳消息计数器，并将其设置为心跳消息的 count 字段。
  hb->firstSN = ddsi_to_seqno (min);
  hb->lastSN = ddsi_to_seqno (max);

  hb->count = wr->hbcount++;
  //在消息中设置下一个子消息。
  ddsi_xmsg_submsg_setnext (msg, sm_marker);
  //如果配置了安全功能，则在消息中编码数据写者子消息。
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

  /*内置实体先走了第三分支，再走第一分支！
  
这段代码是在检查写者（wr）关联的读者（readers）是否为空。让我们逐步解释这段代码：

ddsrt_avl_is_empty 是一个函数调用，用于检查 AVL 树（一种自平衡二叉搜索树）是否为空。在这里，AVL 树用于管理与写者相关联的读者。

&wr->readers 是获取写者结构体中读者 AVL 树的地址。

所以，ddsrt_avl_is_empty (&wr->readers) 表示检查写者结构体中的读者 AVL 树是否为空。

在这个上下文中，如果 AVL 树为空，意味着写者当前没有任何关联的读者。这可能表示没有其他实体订阅该写者的数据。在心跳机制的逻辑中，如果没有关联的读者，可能会采取不同的策略，例如减少发送心跳的频率等。
  */

 /*
 heartbeat(wr 10274050:43691fa2:8ad07b22:200c2) sent, resched in 0.1 s (min-ack 1!, avail-seq 1, xmit 1)
 
心跳消息是由写者的 GUID（"10274050:43691fa2:8ad07b22:200c2"）标识的。
心跳消息已发送（"sent"）。
下一次心跳将在 0.1 秒后重新调度。
已确认的最小序列号是 1，但有未回复心跳消息的读者（"1!"）。
可用的最大序列号是 1。
写者已发送的最大序列号是 1。
 

heartbeat(wr 10274050:43691fa2:8ad07b22:3c2) suppressed, resched in inf s (min-ack 0, avail-seq 0, xmit 0)
这条日志消息中的内容解释如下：

"heartbeat(wr 10274050:43691fa2:8ad07b22:3c2)"：表示心跳消息的标识符，其中 "10274050:43691fa2:8ad07b22:200c2" 是写者的唯一标识符，通常是 GUID。

"suppressed"：表示该心跳消息被抑制了，即没有发送出去。

"resched in inf s"：表示下一次调度心跳的时间。在这种情况下，“inf”表示无限，即无法计算下一次心跳的调度时间，因为没有未被确认的消息需要发送。

"(min-ack 0, avail-seq 0, xmit 0)"：提供了有关写者状态的额外信息：

"min-ack 0"：表示当前没有收到任何读者的确认消息。
"avail-seq 0"：表示当前没有任何可用的序列号需要发送。
"xmit 0"：表示写者尚未发送任何消息。
综上所述，这条日志消息表示写者尚未发送心跳消息，因为当前没有未被确认的消息需要发送，也没有可用的消息序列号。
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

/*
 heartbeat(wr 10275e8e:72201f48:dfcf6ecb:102) suppressed, resched in inf s (min-ack 9223372036854775807, avail-seq 0, xmit 39)是什么意思


"heartbeat(wr 10275e8e:72201f48:dfcf6ecb:102)"：表示心跳消息的标识符，其中 "10275e8e:72201f48:dfcf6ecb:102" 是写者的唯一标识符，通常是 GUID。

"suppressed"：表示该心跳消息被抑制了，即没有发送出去。

"resched in inf s"：表示下一次调度心跳的时间。在这种情况下，“inf”表示无限，即无法计算下一次心跳的调度时间，因为当前没有未被确认的消息需要发送。

"(min-ack 9223372036854775807, avail-seq 0, xmit 39)"：提供了有关写者状态的额外信息：

"min-ack 9223372036854775807"：表示当前未收到任何读者的确认消息。9223372036854775807是int64的最大值，表示没有收到任何确认消息。

"avail-seq 0"：表示当前没有任何可用的消息序列号需要发送。

"xmit 39"：表示写者已经发送了39条消息

表示写者尚未发送心跳消息，因为当前没有未被确认的消息需要发送，也没有可用的消息序列号。
*/