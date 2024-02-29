// Copyright(c) 2006 to 2022 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/log.h"
#include "dds/ddsrt/md5.h"
#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/static_assert.h"
#include "dds/ddsrt/avl.h"
#include "dds/ddsi/ddsi_unused.h"
#include "dds/ddsi/ddsi_gc.h"
#include "dds/ddsi/ddsi_proxy_participant.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_tkmap.h"
#include "dds/ddsi/ddsi_serdata.h"
#include "ddsi__log.h"
#include "ddsi__protocol.h"
#include "ddsi__misc.h"
#include "ddsi__bswap.h"
#include "ddsi__lat_estim.h"
#include "ddsi__bitset.h"
#include "ddsi__xevent.h"
#include "ddsi__addrset.h"
#include "ddsi__discovery.h"
#include "ddsi__radmin.h"
#include "ddsi__thread.h"
#include "ddsi__entity_index.h"
#include "ddsi__lease.h"
#include "ddsi__entity.h"
#include "ddsi__participant.h"
#include "ddsi__xmsg.h"
#include "ddsi__receive.h"
#include "ddsi__rhc.h"
#include "ddsi__transmit.h"
#include "ddsi__mcgroup.h"
#include "ddsi__security_omg.h"
#include "ddsi__acknack.h"
#include "ddsi__sysdeps.h"
#include "ddsi__deliver_locally.h"
#include "ddsi__endpoint.h"
#include "ddsi__endpoint_match.h"
#include "ddsi__plist.h"
#include "ddsi__proxy_endpoint.h"
#include "ddsi__tran.h"
#include "ddsi__vendor.h"
#include "ddsi__hbcontrol.h"
#include "ddsi__sockwaitset.h"

#include "dds/cdr/dds_cdrstream.h"
#include "dds__whc.h"

/*
Notes:

- for now, the safer option is usually chosen: hold a lock even if it
  isn't strictly necessary in the particular configuration we have
  (such as one receive thread vs. multiple receive threads)

- ddsi_dqueue_enqueue may be called with pwr->e.lock held

- deliver_user_data_synchronously may be called with pwr->e.lock held,
  which is needed if IN-ORDER synchronous delivery is desired when
  there are also multiple receive threads

- deliver_user_data gets passed in whether pwr->e.lock is held on entry

*/

static void deliver_user_data_synchronously (struct ddsi_rsample_chain *sc, const ddsi_guid_t *rdguid);

static void maybe_set_reader_in_sync (struct ddsi_proxy_writer *pwr, struct ddsi_pwr_rd_match *wn, ddsi_seqno_t last_deliv_seq)
{
  switch (wn->in_sync)
  {
    case PRMSS_SYNC:
      assert(0);
      break;
    case PRMSS_TLCATCHUP:
      if (last_deliv_seq >= wn->u.not_in_sync.end_of_tl_seq)
      {
        wn->in_sync = PRMSS_SYNC;
        if (--pwr->n_readers_out_of_sync == 0)
          ddsi_local_reader_ary_setfastpath_ok (&pwr->rdary, true);
      }
      break;
    case PRMSS_OUT_OF_SYNC:
      if (!wn->filtered)
      {
        if (pwr->have_seen_heartbeat && ddsi_reorder_next_seq (wn->u.not_in_sync.reorder) == ddsi_reorder_next_seq (pwr->reorder))
        {
          ETRACE (pwr, " msr_in_sync("PGUIDFMT" out-of-sync to tlcatchup)", PGUID (wn->rd_guid));
          wn->in_sync = PRMSS_TLCATCHUP;
          maybe_set_reader_in_sync (pwr, wn, last_deliv_seq);
        }
      }
      break;
  }
}

static bool valid_sequence_number_set (const ddsi_sequence_number_set_header_t *snset, ddsi_seqno_t *start)
{
  // reject sets that imply sequence numbers beyond the range of valid sequence numbers
  // (not a spec'd requirement)
  return (ddsi_validating_from_seqno (snset->bitmap_base, start) && snset->numbits <= 256 && snset->numbits <= DDSI_MAX_SEQ_NUMBER - *start);
}

static bool valid_fragment_number_set (const ddsi_fragment_number_set_header_t *fnset)
{
  // reject sets that imply fragment numbers beyond the range of valid fragment numbers
  // (not a spec'd requirement)
  return (fnset->bitmap_base > 0 && fnset->numbits <= 256 && fnset->numbits <= UINT32_MAX - fnset->bitmap_base);
}

enum validation_result {
  VR_MALFORMED,
  VR_NOT_UNDERSTOOD,
  VR_ACCEPT
};

static enum validation_result validate_writer_and_reader_entityid (ddsi_entityid_t wrid, ddsi_entityid_t rdid)
{
  if (ddsi_is_writer_entityid (wrid) && ddsi_is_reader_entityid (rdid))
    return VR_ACCEPT;
  else // vendor-specific entity kinds means ignoring it is better than saying "malformed"
    return VR_NOT_UNDERSTOOD;
}

static enum validation_result validate_writer_and_reader_or_null_entityid (ddsi_entityid_t wrid, ddsi_entityid_t rdid)
{
  // the official term is "unknown entity id" but that's too close for comfort
  // to "unknown entity" in the message validation code
  if (ddsi_is_writer_entityid (wrid) && (rdid.u == DDSI_ENTITYID_UNKNOWN || ddsi_is_reader_entityid (rdid)))
    return VR_ACCEPT;
  else // see validate_writer_and_reader_entityid
    return VR_NOT_UNDERSTOOD;
}

static enum validation_result validate_AckNack (const struct ddsi_receiver_state *rst, ddsi_rtps_acknack_t *msg, size_t size, int byteswap)
{
  ddsi_count_t *count; /* this should've preceded the bitmap */
  if (size < DDSI_ACKNACK_SIZE (0))
    return VR_MALFORMED;
  if (byteswap)
  {
    ddsi_bswap_sequence_number_set_hdr (&msg->readerSNState);
    /* bits[], count deferred until validation of fixed part */
  }
  msg->readerId = ddsi_ntoh_entityid (msg->readerId);
  msg->writerId = ddsi_ntoh_entityid (msg->writerId);
  /* Validation following 8.3.7.1.3 + 8.3.5.5 */
  ddsi_seqno_t ackseq;
  if (!valid_sequence_number_set (&msg->readerSNState, &ackseq))
  {
    /* FastRTPS, Connext send invalid pre-emptive ACKs -- patch the message to
       make it well-formed and process it as normal */
    if (! DDSI_SC_STRICT_P (rst->gv->config) &&
        (ackseq == 0 && msg->readerSNState.numbits == 0) &&
        (ddsi_vendor_is_eprosima (rst->vendor) || ddsi_vendor_is_rti (rst->vendor) || ddsi_vendor_is_rti_micro (rst->vendor)))
      msg->readerSNState.bitmap_base = ddsi_to_seqno (1);
    else
      return VR_MALFORMED;
  }
  /* Given the number of bits, we can compute the size of the AckNack
     submessage, and verify that the submessage is large enough */
  if (size < DDSI_ACKNACK_SIZE (msg->readerSNState.numbits))
    return VR_MALFORMED;
  count = (ddsi_count_t *) ((char *) &msg->bits + DDSI_SEQUENCE_NUMBER_SET_BITS_SIZE (msg->readerSNState.numbits));
  if (byteswap)
  {
    ddsi_bswap_sequence_number_set_bitmap (&msg->readerSNState, msg->bits);
    *count = ddsrt_bswap4u (*count);
  }
  // do reader/writer entity id validation last: if it returns "NOT_UNDERSTOOD" for an
  // otherwise malformed message, we still need to discard the message in its entirety
  //
  // unspecified reader makes no sense in the context of an ACKNACK
  return validate_writer_and_reader_entityid (msg->writerId, msg->readerId);
}

static enum validation_result validate_Gap (ddsi_rtps_gap_t *msg, size_t size, int byteswap)
{
  if (size < DDSI_GAP_SIZE (0))
    return VR_MALFORMED;
  if (byteswap)
  {
    ddsi_bswap_sequence_number (&msg->gapStart);
    ddsi_bswap_sequence_number_set_hdr (&msg->gapList);
  }
  msg->readerId = ddsi_ntoh_entityid (msg->readerId);
  msg->writerId = ddsi_ntoh_entityid (msg->writerId);
  ddsi_seqno_t gapstart;
  if (!ddsi_validating_from_seqno (msg->gapStart, &gapstart))
    return VR_MALFORMED;
  ddsi_seqno_t gapend;
  if (!valid_sequence_number_set (&msg->gapList, &gapend))
    return VR_MALFORMED;
  // gapstart >= gapend is not listed as malformed in spec but it really makes no sense
  // the only plausible interpretation is that the interval is empty and that only the
  // bitmap matters (which could then be all-0 in which case the message is roughly
  // equivalent to a heartbeat that says 1 .. N ...  Rewrite so at least end >= start
  if (gapend < gapstart)
    msg->gapStart = msg->gapList.bitmap_base;
  if (size < DDSI_GAP_SIZE (msg->gapList.numbits))
    return VR_MALFORMED;
  if (byteswap)
    ddsi_bswap_sequence_number_set_bitmap (&msg->gapList, msg->bits);
  // do reader/writer entity id validation last: if it returns "NOT_UNDERSTOOD" for an
  // otherwise malformed message, we still need to discard the message in its entirety
  return validate_writer_and_reader_or_null_entityid (msg->writerId, msg->readerId);
}

static enum validation_result validate_InfoDST (ddsi_rtps_info_dst_t *msg, size_t size, UNUSED_ARG (int byteswap))
{
  if (size < sizeof (*msg))
    return VR_MALFORMED;
  return VR_ACCEPT;
}

static enum validation_result validate_InfoSRC (ddsi_rtps_info_src_t *msg, size_t size, UNUSED_ARG (int byteswap))
{
  if (size < sizeof (*msg))
    return VR_MALFORMED;
  return VR_ACCEPT;
}

static enum validation_result validate_InfoTS (ddsi_rtps_info_ts_t *msg, size_t size, int byteswap)
{
  assert (sizeof (ddsi_rtps_submessage_header_t) <= size);
  if (msg->smhdr.flags & DDSI_INFOTS_INVALIDATE_FLAG)
    return VR_ACCEPT;
  else if (size < sizeof (ddsi_rtps_info_ts_t))
    return VR_MALFORMED;
  else
  {
    if (byteswap)
    {
      msg->time.seconds = ddsrt_bswap4 (msg->time.seconds);
      msg->time.fraction = ddsrt_bswap4u (msg->time.fraction);
    }
    return ddsi_is_valid_timestamp (msg->time) ? VR_ACCEPT : VR_MALFORMED;
  }
}

static enum validation_result validate_Heartbeat (ddsi_rtps_heartbeat_t *msg, size_t size, int byteswap)
{
  if (size < sizeof (*msg))
    return VR_MALFORMED;
  if (byteswap)
  {
    ddsi_bswap_sequence_number (&msg->firstSN);
    ddsi_bswap_sequence_number (&msg->lastSN);
    msg->count = ddsrt_bswap4u (msg->count);
  }
  msg->readerId = ddsi_ntoh_entityid (msg->readerId);
  msg->writerId = ddsi_ntoh_entityid (msg->writerId);
  /* Validation following 8.3.7.5.3; lastSN + 1 == firstSN: no data; test using
     firstSN-1 because lastSN+1 can overflow and we already know firstSN-1 >= 0 */
  if (ddsi_from_seqno (msg->firstSN) <= 0 || ddsi_from_seqno (msg->lastSN) < ddsi_from_seqno (msg->firstSN) - 1)
    return VR_MALFORMED;
  // do reader/writer entity id validation last: if it returns "NOT_UNDERSTOOD" for an
  // otherwise malformed message, we still need to discard the message in its entirety
  return validate_writer_and_reader_or_null_entityid (msg->writerId, msg->readerId);
}

static enum validation_result validate_HeartbeatFrag (ddsi_rtps_heartbeatfrag_t *msg, size_t size, int byteswap)
{
  if (size < sizeof (*msg))
    return VR_MALFORMED;
  if (byteswap)
  {
    ddsi_bswap_sequence_number (&msg->writerSN);
    msg->lastFragmentNum = ddsrt_bswap4u (msg->lastFragmentNum);
    msg->count = ddsrt_bswap4u (msg->count);
  }
  msg->readerId = ddsi_ntoh_entityid (msg->readerId);
  msg->writerId = ddsi_ntoh_entityid (msg->writerId);
  if (ddsi_from_seqno (msg->writerSN) <= 0 || msg->lastFragmentNum == 0)
    return VR_MALFORMED;
  // do reader/writer entity id validation last: if it returns "NOT_UNDERSTOOD" for an
  // otherwise malformed message, we still need to discard the message in its entirety
  return validate_writer_and_reader_or_null_entityid (msg->writerId, msg->readerId);
}

static enum validation_result validate_NackFrag (ddsi_rtps_nackfrag_t *msg, size_t size, int byteswap)
{
  ddsi_count_t *count; /* this should've preceded the bitmap */
  if (size < DDSI_NACKFRAG_SIZE (0))
    return VR_MALFORMED;
  if (byteswap)
  {
    ddsi_bswap_sequence_number (&msg->writerSN);
    ddsi_bswap_fragment_number_set_hdr (&msg->fragmentNumberState);
    /* bits[], count deferred until validation of fixed part */
  }
  msg->readerId = ddsi_ntoh_entityid (msg->readerId);
  msg->writerId = ddsi_ntoh_entityid (msg->writerId);
  /* Validation following 8.3.7.1.3 + 8.3.5.5 */
  if (!valid_fragment_number_set (&msg->fragmentNumberState))
    return VR_MALFORMED;
  /* Given the number of bits, we can compute the size of the Nackfrag
     submessage, and verify that the submessage is large enough */
  if (size < DDSI_NACKFRAG_SIZE (msg->fragmentNumberState.numbits))
    return VR_MALFORMED;
  count = (ddsi_count_t *) ((char *) &msg->bits + DDSI_FRAGMENT_NUMBER_SET_BITS_SIZE (msg->fragmentNumberState.numbits));
  if (byteswap)
  {
    ddsi_bswap_fragment_number_set_bitmap (&msg->fragmentNumberState, msg->bits);
    *count = ddsrt_bswap4u (*count);
  }
  // do reader/writer entity id validation last: if it returns "NOT_UNDERSTOOD" for an
  // otherwise malformed message, we still need to discard the message in its entirety
  //
  // unspecified reader makes no sense in the context of NACKFRAG
  return validate_writer_and_reader_entityid (msg->writerId, msg->readerId);
}

static void set_sampleinfo_proxy_writer (struct ddsi_rsample_info *sampleinfo, ddsi_guid_t *pwr_guid)
{
  struct ddsi_proxy_writer * pwr = ddsi_entidx_lookup_proxy_writer_guid (sampleinfo->rst->gv->entity_index, pwr_guid);
  sampleinfo->pwr = pwr;
}

static bool set_sampleinfo_bswap (struct ddsi_rsample_info *sampleinfo, struct dds_cdr_header *hdr)
{
  if (hdr)
  {
    if (!DDSI_RTPS_CDR_ENC_IS_VALID(hdr->identifier))
      return false;
    sampleinfo->bswap = !DDSI_RTPS_CDR_ENC_IS_NATIVE(hdr->identifier);
  }
  return true;
}

static enum validation_result validate_Data (const struct ddsi_receiver_state *rst, ddsi_rtps_data_t *msg, size_t size, int byteswap, struct ddsi_rsample_info *sampleinfo, const ddsi_keyhash_t **keyhashp, unsigned char **payloadp, uint32_t *payloadsz)
{
  /* on success: sampleinfo->{seq,rst,statusinfo,bswap,complex_qos} all set */
  ddsi_guid_t pwr_guid;
  unsigned char *ptr;

  if (size < sizeof (*msg))
    return VR_MALFORMED; /* too small even for fixed fields */
  /* D=1 && K=1 is invalid in this version of the protocol */
  if ((msg->x.smhdr.flags & (DDSI_DATA_FLAG_DATAFLAG | DDSI_DATA_FLAG_KEYFLAG)) ==
      (DDSI_DATA_FLAG_DATAFLAG | DDSI_DATA_FLAG_KEYFLAG))
    return VR_MALFORMED;
  if (byteswap)
  {
    msg->x.extraFlags = ddsrt_bswap2u (msg->x.extraFlags);
    msg->x.octetsToInlineQos = ddsrt_bswap2u (msg->x.octetsToInlineQos);
    ddsi_bswap_sequence_number (&msg->x.writerSN);
  }
  if ((msg->x.octetsToInlineQos % 4) != 0) {
    // Not quite clear whether this is actually required
    return VR_MALFORMED;
  }
  msg->x.readerId = ddsi_ntoh_entityid (msg->x.readerId);
  msg->x.writerId = ddsi_ntoh_entityid (msg->x.writerId);
  pwr_guid.prefix = rst->src_guid_prefix;
  pwr_guid.entityid = msg->x.writerId;

  sampleinfo->rst = (struct ddsi_receiver_state *) rst; /* drop const */
  if (!ddsi_validating_from_seqno (msg->x.writerSN, &sampleinfo->seq))
    return VR_MALFORMED;
  sampleinfo->fragsize = 0; /* for unfragmented data, fragsize = 0 works swell */

  if ((msg->x.smhdr.flags & (DDSI_DATA_FLAG_INLINE_QOS | DDSI_DATA_FLAG_DATAFLAG | DDSI_DATA_FLAG_KEYFLAG)) == 0)
  {
    /* no QoS, no payload, so octetsToInlineQos will never be used
       though one would expect octetsToInlineQos and size to be in
       agreement or octetsToInlineQos to be 0 or so */
    *payloadp = NULL;
    *keyhashp = NULL;
    sampleinfo->size = 0; /* size is full payload size, no payload & unfragmented => size = 0 */
    sampleinfo->statusinfo = 0;
    sampleinfo->complex_qos = 0;
    goto accept;
  }

  /* QoS and/or payload, so octetsToInlineQos must be within the
     msg; since the serialized data and serialized parameter lists
     have a 4 byte header, that one, too must fit */
  if (offsetof (ddsi_rtps_data_datafrag_common_t, octetsToInlineQos) + sizeof (msg->x.octetsToInlineQos) + msg->x.octetsToInlineQos + 4 > size)
    return VR_MALFORMED;

  ptr = (unsigned char *) msg + offsetof (ddsi_rtps_data_datafrag_common_t, octetsToInlineQos) + sizeof (msg->x.octetsToInlineQos) + msg->x.octetsToInlineQos;
  if (msg->x.smhdr.flags & DDSI_DATA_FLAG_INLINE_QOS)
  {
    ddsi_plist_src_t src;
    src.protocol_version = rst->protocol_version;
    src.vendorid = rst->vendor;
    src.encoding = (msg->x.smhdr.flags & DDSI_RTPS_SUBMESSAGE_FLAG_ENDIANNESS) ? DDSI_RTPS_PL_CDR_LE : DDSI_RTPS_PL_CDR_BE;
    src.buf = ptr;
    src.bufsz = (unsigned) ((unsigned char *) msg + size - src.buf); /* end of message, that's all we know */
    /* just a quick scan, gathering only what we _really_ need */
    if ((ptr = ddsi_plist_quickscan (sampleinfo, keyhashp, &src, rst->gv)) == NULL)
      return VR_MALFORMED;
  }
  else
  {
    sampleinfo->statusinfo = 0;
    sampleinfo->complex_qos = 0;
    *keyhashp = NULL;
  }

  if (!(msg->x.smhdr.flags & (DDSI_DATA_FLAG_DATAFLAG | DDSI_DATA_FLAG_KEYFLAG)))
  {
    /*TRACE (("no payload\n"));*/
    *payloadp = NULL;
    *payloadsz = 0;
    sampleinfo->size = 0;
  }
  else if ((size_t) ((char *) ptr + 4 - (char *) msg) > size)
  {
    /* no space for the header */
    return VR_MALFORMED;
  }
  else
  {
    sampleinfo->size = (uint32_t) ((char *) msg + size - (char *) ptr);
    *payloadsz = sampleinfo->size;
    *payloadp = ptr;
  }
accept:
  ;
  // do reader/writer entity id validation last: if it returns "NOT_UNDERSTOOD" for an
  // otherwise malformed message, we still need to discard the message in its entirety
  enum validation_result vr = validate_writer_and_reader_or_null_entityid (msg->x.writerId, msg->x.readerId);
  if (vr == VR_ACCEPT)
    set_sampleinfo_proxy_writer (sampleinfo, &pwr_guid);
  return vr;
}

static enum validation_result validate_DataFrag (const struct ddsi_receiver_state *rst, ddsi_rtps_datafrag_t *msg, size_t size, int byteswap, struct ddsi_rsample_info *sampleinfo, const ddsi_keyhash_t **keyhashp, unsigned char **payloadp, uint32_t *payloadsz)
{
  ddsi_guid_t pwr_guid;
  unsigned char *ptr;

  if (size < sizeof (*msg))
    return VR_MALFORMED; /* too small even for fixed fields */

  if (byteswap)
  {
    msg->x.extraFlags = ddsrt_bswap2u (msg->x.extraFlags);
    msg->x.octetsToInlineQos = ddsrt_bswap2u (msg->x.octetsToInlineQos);
    ddsi_bswap_sequence_number (&msg->x.writerSN);
    msg->fragmentStartingNum = ddsrt_bswap4u (msg->fragmentStartingNum);
    msg->fragmentsInSubmessage = ddsrt_bswap2u (msg->fragmentsInSubmessage);
    msg->fragmentSize = ddsrt_bswap2u (msg->fragmentSize);
    msg->sampleSize = ddsrt_bswap4u (msg->sampleSize);
  }
  if ((msg->x.octetsToInlineQos % 4) != 0) {
    // Not quite clear whether this is actually required
    return VR_MALFORMED;
  }
  msg->x.readerId = ddsi_ntoh_entityid (msg->x.readerId);
  msg->x.writerId = ddsi_ntoh_entityid (msg->x.writerId);
  pwr_guid.prefix = rst->src_guid_prefix;
  pwr_guid.entityid = msg->x.writerId;

  if (DDSI_SC_STRICT_P (rst->gv->config) && msg->fragmentSize <= 1024 && msg->fragmentSize < rst->gv->config.fragment_size)
  {
    /* Spec says fragments must > 1kB; not allowing 1024 bytes is IMHO
       totally ridiculous; and I really don't care how small the
       fragments anyway. And we're certainly not going too fail the
       message if it is as least as large as the configured fragment
       size. */
    return VR_MALFORMED;
  }
  if (msg->fragmentSize == 0 || msg->fragmentStartingNum == 0 || msg->fragmentsInSubmessage == 0)
    return VR_MALFORMED;
  if (msg->fragmentsInSubmessage > UINT32_MAX - msg->fragmentStartingNum)
    return VR_MALFORMED;
  if (DDSI_SC_STRICT_P (rst->gv->config) && msg->fragmentSize >= msg->sampleSize)
    /* may not fragment if not needed -- but I don't care */
    return VR_MALFORMED;
  if ((uint64_t) (msg->fragmentStartingNum + msg->fragmentsInSubmessage - 2) * msg->fragmentSize >= msg->sampleSize)
    /* starting offset of last fragment must be within sample, note:
       fragment numbers are 1-based */
    return VR_MALFORMED;

  sampleinfo->rst = (struct ddsi_receiver_state *) rst; /* drop const */
  if (!ddsi_validating_from_seqno (msg->x.writerSN, &sampleinfo->seq))
    return VR_MALFORMED;
  sampleinfo->fragsize = msg->fragmentSize;
  sampleinfo->size = msg->sampleSize;

  /* QoS and/or payload, so octetsToInlineQos must be within the msg;
     since the serialized data and serialized parameter lists have a 4
     byte header, that one, too must fit */
  if (offsetof (ddsi_rtps_data_datafrag_common_t, octetsToInlineQos) + sizeof (msg->x.octetsToInlineQos) + msg->x.octetsToInlineQos + 4 > size)
    return VR_MALFORMED;

  /* Quick check inline QoS if present, collecting a little bit of
     information on it.  The only way to find the payload offset if
     inline QoSs are present. */
  ptr = (unsigned char *) msg + offsetof (ddsi_rtps_data_datafrag_common_t, octetsToInlineQos) + sizeof (msg->x.octetsToInlineQos) + msg->x.octetsToInlineQos;
  if (msg->x.smhdr.flags & DDSI_DATAFRAG_FLAG_INLINE_QOS)
  {
    ddsi_plist_src_t src;
    src.protocol_version = rst->protocol_version;
    src.vendorid = rst->vendor;
    src.encoding = (msg->x.smhdr.flags & DDSI_RTPS_SUBMESSAGE_FLAG_ENDIANNESS) ? DDSI_RTPS_PL_CDR_LE : DDSI_RTPS_PL_CDR_BE;
    src.buf = ptr;
    src.bufsz = (unsigned) ((unsigned char *) msg + size - src.buf); /* end of message, that's all we know */
    /* just a quick scan, gathering only what we _really_ need */
    if ((ptr = ddsi_plist_quickscan (sampleinfo, keyhashp, &src, rst->gv)) == NULL)
      return VR_MALFORMED;
  }
  else
  {
    sampleinfo->statusinfo = 0;
    sampleinfo->complex_qos = 0;
    *keyhashp = NULL;
  }

  *payloadp = ptr;
  *payloadsz = (uint32_t) ((char *) msg + size - (char *) ptr);
  if ((uint32_t) msg->fragmentsInSubmessage * msg->fragmentSize <= (*payloadsz))
    ; /* all spec'd fragments fit in payload */
  else if ((uint32_t) (msg->fragmentsInSubmessage - 1) * msg->fragmentSize >= (*payloadsz))
    return VR_MALFORMED; /* I can live with a short final fragment, but _only_ the final one */
  else if ((uint32_t) (msg->fragmentStartingNum - 1) * msg->fragmentSize + (*payloadsz) >= msg->sampleSize)
    ; /* final fragment is long enough to cover rest of sample */
  else
    return VR_MALFORMED;
  if (msg->fragmentStartingNum == 1)
  {
    if ((size_t) ((char *) ptr + 4 - (char *) msg) > size)
    {
      /* no space for the header -- technically, allowing small
         fragments would also mean allowing a partial header, but I
         prefer this */
      return VR_MALFORMED;
    }
  }
  enum validation_result vr = validate_writer_and_reader_or_null_entityid (msg->x.writerId, msg->x.readerId);
  if (vr == VR_ACCEPT)
    set_sampleinfo_proxy_writer (sampleinfo, &pwr_guid);
  return vr;
}

int ddsi_add_gap (struct ddsi_xmsg *msg, struct ddsi_writer *wr, struct ddsi_proxy_reader *prd, ddsi_seqno_t start, ddsi_seqno_t base, uint32_t numbits, const uint32_t *bits)
{
  struct ddsi_xmsg_marker sm_marker;
  ddsi_rtps_gap_t *gap;
  ASSERT_MUTEX_HELD (wr->e.lock);
  gap = ddsi_xmsg_append (msg, &sm_marker, DDSI_GAP_SIZE (numbits));
  ddsi_xmsg_submsg_init (msg, sm_marker, DDSI_RTPS_SMID_GAP);
  gap->readerId = ddsi_hton_entityid (prd->e.guid.entityid);
  gap->writerId = ddsi_hton_entityid (wr->e.guid.entityid);
  gap->gapStart = ddsi_to_seqno (start);
  gap->gapList.bitmap_base = ddsi_to_seqno (base);
  gap->gapList.numbits = numbits;
  memcpy (gap->bits, bits, DDSI_SEQUENCE_NUMBER_SET_BITS_SIZE (numbits));
  ddsi_xmsg_submsg_setnext (msg, sm_marker);
  ddsi_security_encode_datawriter_submsg(msg, sm_marker, wr);
  return 0;
}

static ddsi_seqno_t grow_gap_to_next_seq (const struct ddsi_writer *wr, ddsi_seqno_t seq)
{
  ddsi_seqno_t next_seq = ddsi_whc_next_seq (wr->whc, seq - 1);
  ddsi_seqno_t seq_xmit = ddsi_writer_read_seq_xmit (wr);
  if (next_seq == DDSI_MAX_SEQ_NUMBER) /* no next sample */
    return seq_xmit + 1;
  else if (next_seq > seq_xmit)  /* next is beyond last actually transmitted */
    return seq_xmit;
  else /* next one is already visible in the outside world */
    return next_seq;
}

static int acknack_is_nack (const ddsi_rtps_acknack_t *msg)
{
  unsigned x = 0, mask;
  int i;
  if (msg->readerSNState.numbits == 0)
    /* Disallowed by the spec, but RTI appears to require them (and so
       even we generate them) */
    return 0;
  for (i = 0; i < (int) DDSI_SEQUENCE_NUMBER_SET_BITS_SIZE (msg->readerSNState.numbits) / 4 - 1; i++)
    x |= msg->bits[i];
  if ((msg->readerSNState.numbits % 32) == 0)
    mask = ~0u;
  else
    mask = ~(~0u >> (msg->readerSNState.numbits % 32));
  x |= msg->bits[i] & mask;
  return x != 0;
}

/*
函数用于决定是否接受一个新的确认消息或心跳消息。
如果新消息的序列号小于或等于之前接收的最高序列号，并且距离上次接收消息的时间不到500毫秒，并且没有强制接受的标志，则拒绝接受该消息。
否则，更新先前接收的最高序列号和最后一次接收消息的时间，并接受新消息。
*/
static int accept_ack_or_hb_w_timeout (ddsi_count_t new_count, ddsi_count_t *prev_count, ddsrt_etime_t tnow, ddsrt_etime_t *t_last_accepted, int force_accept)
{
  /* AckNacks and Heartbeats with a sequence number (called "count"
     for some reason) equal to or less than the highest one received
     so far must be dropped.  However, we provide an override
     (force_accept) for pre-emptive acks and we accept ones regardless
     of the sequence number after a few seconds.

     This allows continuing after an asymmetrical disconnection if the
     re-connecting side jumps back in its sequence numbering.  DDSI2.1
     8.4.15.7 says: "New HEARTBEATS should have Counts greater than
     all older HEARTBEATs. Then, received HEARTBEATs with Counts not
     greater than any previously received can be ignored."  But it
     isn't clear whether that is about connections or entities.

     The type is defined in the spec as signed but without limiting
     them to, e.g., positive numbers.  Instead of implementing them as
     spec'd, we implement it as unsigned to avoid integer overflow (and
     the consequence undefined behaviour).  Serial number arithmetic
     deals with the wrap-around after 2**31-1.

     Cyclone pre-emptive heartbeats have "count" bitmap_base = 1, NACK
     nothing, have count set to 0.  They're never sent more often than
     once per second, so the 500ms timeout allows them to pass through.

     This combined procedure should give the best of all worlds, and
     is not more expensive in the common case. */
  const int64_t timeout = DDS_MSECS (500);

  if ((int32_t) (new_count - *prev_count) <= 0 && tnow.v - t_last_accepted->v < timeout && !force_accept)
    return 0;

  *prev_count = new_count;
  *t_last_accepted = tnow;
  return 1;
}

void ddsi_gap_info_init(struct ddsi_gap_info *gi)
{
  gi->gapstart = 0;
  gi->gapend = 0;
  gi->gapnumbits = 0;
  memset(gi->gapbits, 0, sizeof(gi->gapbits));
}

void ddsi_gap_info_update(struct ddsi_domaingv *gv, struct ddsi_gap_info *gi, ddsi_seqno_t seqnr)
{
  assert (gi->gapend >= gi->gapstart);
  assert (seqnr >= gi->gapend);

  if (gi->gapstart == 0)
  {
    GVTRACE (" M%"PRIu64, seqnr);
    gi->gapstart = seqnr;
    gi->gapend = gi->gapstart + 1;
  }
  else if (seqnr == gi->gapend)
  {
    GVTRACE (" M%"PRIu64, seqnr);
    gi->gapend = seqnr + 1;
  }
  else if (seqnr - gi->gapend < 256)
  {
    uint32_t idx = (uint32_t) (seqnr - gi->gapend);
    GVTRACE (" M%"PRIu64, seqnr);
    gi->gapnumbits = idx + 1;
    ddsi_bitset_set (gi->gapnumbits, gi->gapbits, idx);
  }
}

struct ddsi_xmsg * ddsi_gap_info_create_gap(struct ddsi_writer *wr, struct ddsi_proxy_reader *prd, struct ddsi_gap_info *gi)
{
  struct ddsi_xmsg *m;

  if (gi->gapstart == 0)
    return NULL;

  m = ddsi_xmsg_new (wr->e.gv->xmsgpool, &wr->e.guid, wr->c.pp, 0, DDSI_XMSG_KIND_CONTROL);

  ddsi_xmsg_setdst_prd (m, prd);
  ddsi_add_gap (m, wr, prd, gi->gapstart, gi->gapend, gi->gapnumbits, gi->gapbits);
  if (ddsi_xmsg_size(m) == 0)
  {
    ddsi_xmsg_free (m);
    m = NULL;
  }
  else
  {
    ETRACE (wr, " FXGAP%"PRIu64"..%"PRIu64"/%"PRIu32":", gi->gapstart, gi->gapend, gi->gapnumbits);
    for (uint32_t i = 0; i < gi->gapnumbits; i++)
      ETRACE (wr, "%c", ddsi_bitset_isset (gi->gapnumbits, gi->gapbits, i) ? '1' : '0');
  }

  return m;
}
/*
struct ddsi_xmsg *m：

这是一个指向 ddsi_xmsg 结构体的指针。
ddsi_xmsg 通常代表 DDS（Data Distribution Service）中的消息，可能包含要发送或接收的数据。
struct ddsi_xeventq *evq：

这是一个指向 ddsi_xeventq 结构体的指针。
ddsi_xeventq 通常代表 DDS 中的事件队列，用于处理各种事件，包括定时事件、消息传递等。
enum ddsi_hbcontrol_ack_required hbansreq：

这是一个枚举类型 ddsi_hbcontrol_ack_required 的变量。
枚举类型通常用于表示一组命名的整数常量。在这里，它表示某种心跳控制的确认要求。
uint64_t wr_iid：

这是一个 64 位无符号整数，表示写入（write）实例的标识符（ID）。
uint64_t prd_iid：

这是一个 64 位无符号整数，表示生产者（producer）实例的标识符（ID）。
综合起来，这个结构体似乎用于在某个上下文中
（可能是与 DDS 通信相关的异步事件处理等）存储一些状态信息。它可能用于推迟（defer）处理心跳消息，包括要处理的消息、相关的事件队列、心跳控制的确认要求，以及与实例标识相关的信息。
*/
struct defer_hb_state {
  struct ddsi_xmsg *m;
  struct ddsi_xeventq *evq;
  enum ddsi_hbcontrol_ack_required hbansreq;
  uint64_t wr_iid;
  uint64_t prd_iid;
};

static void defer_heartbeat_to_peer (struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, struct ddsi_proxy_reader *prd, enum ddsi_hbcontrol_ack_required hbansreq, struct defer_hb_state *defer_hb_state)
{
  ETRACE (wr, "defer_heartbeat_to_peer: "PGUIDFMT" -> "PGUIDFMT" - queue for transmit\n", PGUID (wr->e.guid), PGUID (prd->e.guid));

  if (defer_hb_state->m != NULL)
  {
    if (wr->e.iid == defer_hb_state->wr_iid && prd->e.iid == defer_hb_state->prd_iid)
    {
      if (hbansreq <= defer_hb_state->hbansreq)
        return;
      else
        ddsi_xmsg_free (defer_hb_state->m);
    }
    else
    {
      ddsi_qxev_msg (wr->evq, defer_hb_state->m);
    }
  }

  ASSERT_MUTEX_HELD (&wr->e.lock);
  assert (wr->reliable);

  defer_hb_state->m = ddsi_xmsg_new (wr->e.gv->xmsgpool, &wr->e.guid, wr->c.pp, 0, DDSI_XMSG_KIND_CONTROL);
  ddsi_xmsg_setdst_prd (defer_hb_state->m, prd);
  ddsi_add_heartbeat (defer_hb_state->m, wr, whcst, hbansreq, 0, prd->e.guid.entityid, 0);
  defer_hb_state->evq = wr->evq;
  defer_hb_state->hbansreq = hbansreq;
  defer_hb_state->wr_iid = wr->e.iid;
  defer_hb_state->prd_iid = prd->e.iid;
}

static void force_heartbeat_to_peer (struct ddsi_writer *wr, const struct ddsi_whc_state *whcst, struct ddsi_proxy_reader *prd, enum ddsi_hbcontrol_ack_required hbansreq, struct defer_hb_state *defer_hb_state)
{
  defer_heartbeat_to_peer (wr, whcst, prd, hbansreq, defer_hb_state);
  ddsi_qxev_msg (wr->evq, defer_hb_state->m);
  defer_hb_state->m = NULL;
}

static void defer_hb_state_init (struct defer_hb_state *defer_hb_state)
{
  defer_hb_state->m = NULL;
}

static void defer_hb_state_fini (struct ddsi_domaingv * const gv, struct defer_hb_state *defer_hb_state)
{
  if (defer_hb_state->m)
  {
    GVTRACE ("send_deferred_heartbeat: %"PRIx64" -> %"PRIx64" - queue for transmit\n", defer_hb_state->wr_iid, defer_hb_state->prd_iid);
    ddsi_qxev_msg (defer_hb_state->evq, defer_hb_state->m);
    defer_hb_state->m = NULL;
  }
}

static int handle_AckNack (struct ddsi_receiver_state *rst, ddsrt_etime_t tnow, const ddsi_rtps_acknack_t *msg, ddsrt_wctime_t timestamp, ddsi_rtps_submessage_kind_t prev_smid, struct defer_hb_state *defer_hb_state)
{
  struct ddsi_proxy_reader *prd;
  struct ddsi_wr_prd_match *rn;
  struct ddsi_writer *wr;
  struct ddsi_lease *lease;
  ddsi_guid_t src, dst;
  ddsi_seqno_t seqbase;
  ddsi_seqno_t seq_xmit;
  ddsi_count_t *countp;
  struct ddsi_gap_info gi;
  int accelerate_rexmit = 0;
  int is_pure_ack;
  int is_pure_nonhist_ack;
  int is_preemptive_ack;
  int enqueued;
  unsigned numbits;
  uint32_t msgs_sent, msgs_lost;
  ddsi_seqno_t max_seq_in_reply;
  struct ddsi_whc_node *deferred_free_list = NULL;
  struct ddsi_whc_state whcst;
  int hb_sent_in_response = 0;
  //这行代码计算了 countp 的值，它是一个指向消息中确认/否认位的指针，用于统计消息。
  countp = (ddsi_count_t *) ((char *) msg + offsetof (ddsi_rtps_acknack_t, bits) + DDSI_SEQUENCE_NUMBER_SET_BITS_SIZE (msg->readerSNState.numbits));
  //这里设置了消息的源地址 src 和目标地址 dst。
  src.prefix = rst->src_guid_prefix;
  src.entityid = msg->readerId;
  dst.prefix = rst->dst_guid_prefix;
  dst.entityid = msg->writerId;
  //这行代码打印了一条日志，包含了收到的 AckNack 消息的一些信息。
  RSTTRACE ("ACKNACK(%s#%"PRId32":%"PRIu64"/%"PRIu32":", msg->smhdr.flags & DDSI_ACKNACK_FLAG_FINAL ? "F" : "",
            *countp, ddsi_from_seqno (msg->readerSNState.bitmap_base), msg->readerSNState.numbits);
            //这个循环打印了消息中的确认/否认位。
  for (uint32_t i = 0; i < msg->readerSNState.numbits; i++)
    RSTTRACE ("%c", ddsi_bitset_isset (msg->readerSNState.numbits, msg->bits, i) ? '1' : '0');
  seqbase = ddsi_from_seqno (msg->readerSNState.bitmap_base);
  //这里将消息中的序列号转换为可用的 seqbase，并确保它大于 0。
  assert (seqbase > 0); // documentation, really, to make it obvious that subtracting 1 is ok

  if (!rst->forme)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" not-for-me)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((wr = ddsi_entidx_lookup_writer_guid (rst->gv->entity_index, &dst)) == NULL)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT"?)", PGUID (src), PGUID (dst));
    return 1;
  }
  /* Always look up the proxy reader -- even though we don't need for
     the normal pure ack steady state. If (a big "if"!) this shows up
     as a significant portion of the time, we can always rewrite it to
     only retrieve it when needed. */
     //这段代码尝试查找代理读者（proxy reader），即消息的接收者。即使在正常的纯确认稳定状态下我们不需要它，但还是会尝试查找。如果发现这是一个时间消耗较大的操作，可以考虑在需要时才检索。
  if ((prd = ddsi_entidx_lookup_proxy_reader_guid (rst->gv->entity_index, &src)) == NULL)
  {
    RSTTRACE (" "PGUIDFMT"? -> "PGUIDFMT")", PGUID (src), PGUID (dst));
    return 1;
  }

  if (!ddsi_security_validate_msg_decoding(&(prd->e), &(prd->c), prd->c.proxypp, rst, prev_smid))
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" clear submsg from protected src)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((lease = ddsrt_atomic_ldvoidp (&prd->c.proxypp->minl_auto)) != NULL)
    ddsi_lease_renew (lease, tnow);
  //如果写入者（writer）不是可靠的，则打印一条相应的日志，并返回 1。
  if (!wr->reliable) /* note: reliability can't be changed */
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" not a reliable writer!)", PGUID (src), PGUID (dst));
    return 1;
  }
//这段代码锁定了写入者（writer）的互斥锁，并检查是否应该忽略 AckNack 消息。
  ddsrt_mutex_lock (&wr->e.lock);
  if (wr->test_ignore_acknack)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" test_ignore_acknack)", PGUID (src), PGUID (dst));
    goto out;
  }
  //这段代码尝试查找与写入者相关的代理读者（proxy reader），如果找不到，则打印一条相应的日志，并跳转到标签 out。
  if ((rn = ddsrt_avl_lookup (&ddsi_wr_readers_treedef, &wr->readers, &src)) == NULL)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" not a connection)", PGUID (src), PGUID (dst));
    goto out;
  }

  /* is_pure_nonhist ack differs from is_pure_ack in that it doesn't
     get set when only historical data is being acked, which is
     relevant to setting "has_replied_to_hb" and "assumed_in_sync". */
     //用于确定 AckNack 消息的类型
  is_pure_ack = !acknack_is_nack (msg);
  is_pure_nonhist_ack = is_pure_ack && seqbase - 1 >= rn->seq;
  is_preemptive_ack = seqbase < 1 || (seqbase == 1 && *countp == 0);
  //统计了收到的确认和否认消息的数量，并更新了相应的计数器。
  wr->num_acks_received++;
  if (!is_pure_ack)
  {
    wr->num_nacks_received++;
    rn->rexmit_requests++;
  }
  //这段代码根据一些条件检查了确认消息，并相应地更新了状态。
  if (!accept_ack_or_hb_w_timeout (*countp, &rn->prev_acknack, tnow, &rn->t_acknack_accepted, is_preemptive_ack))
  {
    RSTTRACE (" ["PGUIDFMT" -> "PGUIDFMT"])", PGUID (src), PGUID (dst));
    goto out;
  }
  RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT"", PGUID (src), PGUID (dst));

  /* Update latency estimates if we have a timestamp -- won't actually
     work so well if the timestamp can be a left over from some other
     submessage -- but then, it is no more than a quick hack at the
     moment. */
  if (rst->gv->config.meas_hb_to_ack_latency && timestamp.v)
  {
    ddsrt_wctime_t tstamp_now = ddsrt_time_wallclock ();
    ddsi_lat_estim_update (&rn->hb_to_ack_latency, tstamp_now.v - timestamp.v);
    if ((rst->gv->logconfig.c.mask & DDS_LC_TRACE) && tstamp_now.v > rn->hb_to_ack_latency_tlastlog.v + DDS_SECS (10))
    {
      ddsi_lat_estim_log (DDS_LC_TRACE, &rst->gv->logconfig, NULL, &rn->hb_to_ack_latency);
      rn->hb_to_ack_latency_tlastlog = tstamp_now;
    }
  }

  /* First, the ACK part: if the AckNack advances the highest sequence
     number ack'd by the remote reader, update state & try dropping
     some messages */
     //如果收到的确认消息的序列号大于当前已确认的序列号，那么更新相应的状态信息，并移除已确认的消息。
  if (seqbase - 1 > rn->seq)
  {
    const uint64_t n_ack = (seqbase - 1) - rn->seq;
    rn->seq = seqbase - 1;
    //如果当前已确认的最大序列号大于了写者（wr）的最大序列号，则将当前已确认的最大序列号设置为写者的最大序列号。这样做是为了防止读者确认未来的样本，因为我们要求读者的最大确认序列号不大于写者的最大序列号。
    if (rn->seq > wr->seq) {
      /* Prevent a reader from ACKing future samples (is only malicious because we require
         that rn->seq <= wr->seq) */
      rn->seq = wr->seq;
    }
    //更新读者节点的 AVL 树，以确保 AVL 树的正确性。
    ddsrt_avl_augment_update (&ddsi_wr_readers_treedef, rn);
    //const unsigned n = ddsi_remove_acked_messages (wr, &whcst, &deferred_free_list);：调用函数 ddsi_remove_acked_messages，将已确认的消息从写者中移除，并返回移除的消息数量。
    const unsigned n = ddsi_remove_acked_messages (wr, &whcst, &deferred_free_list);
    //获取写者（wr）的 Whc 状态信息。
    RSTTRACE (" ACK%"PRIu64" RM%u", n_ack, n);
  }
  //如果确认消息的序列号不大于当前已确认的最大序列号减一，则执行下面的逻辑。
  else
  {
    /* There's actually no guarantee that we need this information */
    ddsi_whc_get_state(wr->whc, &whcst);
  }

  /* If this reader was marked as "non-responsive" in the past, it's now responding again,
     so update its status */
     //当代理读者的序列号等于 DDSI_MAX_SEQ_NUMBER 时，意味着代理读者尚未收到任何数据，或者在某些情况下可能表示代理读者的状态已经被重置或者暂时不可用。
     //如果代理读者的序列号为 DDSI_MAX_SEQ_NUMBER，并且可靠性要求为可靠传输，则更新相关状态。
  if (rn->seq == DDSI_MAX_SEQ_NUMBER && prd->c.xqos->reliability.kind == DDS_RELIABILITY_RELIABLE)
  {
    ddsi_seqno_t oldest_seq;
    //如果 Whc 状态信息为空，则将 oldest_seq 设置为写者的最大序列号，否则设置为 Whc 状态信息中的最大序列号。
    oldest_seq = DDSI_WHCST_ISEMPTY(&whcst) ? wr->seq : whcst.max_seq;
    //将读者节点标记为已经回复心跳消息，因为此前可能为了确保心跳消息发送而暂时清除了该标志。
    rn->has_replied_to_hb = 1; /* was temporarily cleared to ensure heartbeats went out */
    //更新读者节点的序列号为接收到的确认消息中的基本序列号减一。
    rn->seq = seqbase - 1;
    //果 oldest_seq 大于读者节点的序列号，则将读者节点的序列号设置为 oldest_seq，这是为了防止读者降低 Whc 中保留的最小序列号。
    if (oldest_seq > rn->seq) {
      /* Prevent a malicious reader from lowering the min. sequence number retained in the WHC. */
      rn->seq = oldest_seq;
    }
    //if (rn->seq > wr->seq)：如果读者节点的序列号大于写者的最大序列号，则将读者节点的序列号设置为写者的最大序列号，以防止读者确认未来的样本
    if (rn->seq > wr->seq) {
      /* Prevent a reader from ACKing future samples (is only malicious because we require
         that rn->seq <= wr->seq) */
      rn->seq = wr->seq;
    }
    //记录日志，表示写者正在考虑将读者节点标记为再次响应。
    ddsrt_avl_augment_update (&ddsi_wr_readers_treedef, rn);
    DDS_CLOG (DDS_LC_THROTTLE, &rst->gv->logconfig, "writer "PGUIDFMT" considering reader "PGUIDFMT" responsive again\n", PGUID (wr->e.guid), PGUID (rn->prd_guid));
  }

  /* Second, the NACK bits (literally, that is). To do so, attempt to
     classify the AckNack for reverse-engineered compatibility with
     RTI's invalid acks and sometimes slightly odd behaviour. */

  numbits = msg->readerSNState.numbits;
  msgs_sent = 0;
  msgs_lost = 0;
  max_seq_in_reply = 0;
  //如果代理读者尚未回复心跳且收到了纯确认消息，则更新相关状态。
  if (!rn->has_replied_to_hb && is_pure_nonhist_ack)
  {
    RSTTRACE (" setting-has-replied-to-hb");
    rn->has_replied_to_hb = 1;
    /* walk the whole tree to ensure all proxy readers for this writer
       have their unack'ed info updated */
    ddsrt_avl_augment_update (&ddsi_wr_readers_treedef, rn);
  }
  //如果是预先否认消息，则根据一些条件执行相应的操作
  if (is_preemptive_ack)
  {
    /* Pre-emptive nack: RTI uses (seqbase = 0, numbits = 0), we use
       (seqbase = 1, numbits = 1, bits = {0}).  Seqbase <= 1 and not a
       NACK covers both and is otherwise a useless message.  Sent on
       reader start-up and we respond with a heartbeat and, if we have
       data in our WHC, we start sending it regardless of whether the
       remote reader asked for it */
    RSTTRACE (" preemptive-nack");
    if (DDSI_WHCST_ISEMPTY(&whcst))
    {
      RSTTRACE (" whc-empty ");
      force_heartbeat_to_peer (wr, &whcst, prd, 1, defer_hb_state);
      hb_sent_in_response = 1;
    }
    else
    {
      RSTTRACE (" rebase ");
      force_heartbeat_to_peer (wr, &whcst, prd, 1, defer_hb_state);
      hb_sent_in_response = 1;
      numbits = rst->gv->config.accelerate_rexmit_block_size;
      seqbase = whcst.min_seq;
    }
  }
  //如果代理读者尚未被认为与写入者同步，则根据条件进行相应的处理。
  else if (!rn->assumed_in_sync)
  {
    /* We assume a remote reader that hasn't ever sent a pure Ack --
       an AckNack that doesn't NACK a thing -- is still trying to
       catch up, so we try to accelerate its attempts at catching up
       by a configurable amount. FIXME: what about a pulling reader?
       that doesn't play too nicely with this. */
    if (is_pure_nonhist_ack)
    {
      RSTTRACE (" happy-now");
      rn->assumed_in_sync = 1;
    }
    else if (msg->readerSNState.numbits < rst->gv->config.accelerate_rexmit_block_size)
    {
      RSTTRACE (" accelerating");
      accelerate_rexmit = 1;
      if (accelerate_rexmit && numbits < rst->gv->config.accelerate_rexmit_block_size)
        numbits = rst->gv->config.accelerate_rexmit_block_size;
    }
    else
    {
      RSTTRACE (" complying");
    }
  }
  /* Retransmit requested messages, including whatever we decided to
     retransmit that the remote reader didn't ask for. While doing so,
     note any gaps in the sequence: if there are some, we transmit a
     Gap message as well.

     Note: ignoring retransmit requests for samples beyond the one we
     last transmitted, even though we may have more available.  If it
     hasn't been transmitted ever, the initial transmit should solve
     that issue; if it has, then the timing is terribly unlucky, but
     a future request'll fix it. */
     //如果设置了测试标志 test_suppress_retransmit 并且 numbits 大于 0，则将 numbits 设置为 0。
  if (wr->test_suppress_retransmit && numbits > 0)
  {
    RSTTRACE (" test_suppress_retransmit");
    numbits = 0;
  }
  //这段代码根据收到的 NACK 位和一些条件执行相应的操作，例如重传消息或更新间隙信息。
  enqueued = 1;
  seq_xmit = ddsi_writer_read_seq_xmit (wr);
  ddsi_gap_info_init(&gi);
  const bool gap_for_already_acked = ddsi_vendor_is_eclipse (rst->vendor) && prd->c.xqos->durability.kind == DDS_DURABILITY_VOLATILE && seqbase <= rn->seq;
  const ddsi_seqno_t min_seq_to_rexmit = gap_for_already_acked ? rn->seq + 1 : 0;
  uint32_t limit = wr->rexmit_burst_size_limit;
  for (uint32_t i = 0; i < numbits && seqbase + i <= seq_xmit && enqueued && limit > 0; i++)
  {
    /* Accelerated schedule may run ahead of sequence number set
       contained in the acknack, and assumes all messages beyond the
       set are NACK'd -- don't feel like tracking where exactly we
       left off ... */
    if (i >= msg->readerSNState.numbits || ddsi_bitset_isset (numbits, msg->bits, i))
    {
      ddsi_seqno_t seq = seqbase + i;
      struct ddsi_whc_borrowed_sample sample;
      if (seqbase + i >= min_seq_to_rexmit && ddsi_whc_borrow_sample (wr->whc, seq, &sample))
      {
        if (!wr->retransmitting && sample.unacked)
          ddsi_writer_set_retransmitting (wr);

        if (rst->gv->config.retransmit_merging != DDSI_REXMIT_MERGE_NEVER && rn->assumed_in_sync && !prd->filter)
        {
          /* send retransmit to all receivers, but skip if recently done */
          ddsrt_mtime_t tstamp = ddsrt_time_monotonic ();
          if (tstamp.v > sample.last_rexmit_ts.v + rst->gv->config.retransmit_merging_period)
          {
            RSTTRACE (" RX%"PRIu64, seqbase + i);
            //重传数据
            enqueued = (ddsi_enqueue_sample_wrlock_held (wr, seq, sample.serdata, NULL, 0) >= 0);
            if (enqueued)
            {
              max_seq_in_reply = seqbase + i;
              msgs_sent++;
              sample.last_rexmit_ts = tstamp;
              // FIXME: now ddsi_enqueue_sample_wrlock_held limits retransmit requests of a large sample to 1 fragment
              // thus we can easily figure out how much was sent, but we shouldn't have that knowledge here:
              // it should return how much it queued instead
              uint32_t sent = ddsi_serdata_size (sample.serdata);
              if (sent > wr->e.gv->config.fragment_size)
                sent = wr->e.gv->config.fragment_size;
              wr->rexmit_bytes += sent;
              limit = (sent > limit) ? 0 : limit - sent;
            }
          }
          else
          {
            RSTTRACE (" RX%"PRIu64" (merged)", seqbase + i);
          }
        }
        else
        {
          /* Is this a volatile reader with a filter?
           * If so, call the filter to see if we should re-arrange the sequence gap when needed. */
          if (prd->filter && !prd->filter (wr, prd, sample.serdata))
            ddsi_gap_info_update (rst->gv, &gi, seqbase + i);
          else
          {
            /* no merging, send directed retransmit */
            RSTTRACE (" RX%"PRIu64"", seqbase + i);
            enqueued = (ddsi_enqueue_sample_wrlock_held (wr, seq, sample.serdata, prd, 0) >= 0);
            if (enqueued)
            {
              max_seq_in_reply = seqbase + i;
              msgs_sent++;
              sample.rexmit_count++;
              // FIXME: now ddsi_enqueue_sample_wrlock_held limits retransmit requests of a large sample to 1 fragment
              // thus we can easily figure out how much was sent, but we shouldn't have that knowledge here:
              // it should return how much it queued instead
              uint32_t sent = ddsi_serdata_size (sample.serdata);
              if (sent > wr->e.gv->config.fragment_size)
                sent = wr->e.gv->config.fragment_size;
              wr->rexmit_bytes += sent;
              limit = (sent > limit) ? 0 : limit - sent;
            }
          }
        }
        ddsi_whc_return_sample(wr->whc, &sample, true);
      }
      //如果代理读者被认为已经与写入者同步，且未发送消息且未丢失任何消息，则更新间隙信息。
      else
      {
        ddsi_gap_info_update (rst->gv, &gi, seqbase + i);
        msgs_lost++;
      }
    }
  }

  if (!enqueued)
    RSTTRACE (" rexmit-limit-hit");
  /* Generate a Gap message if some of the sequence is missing */
  if (gi.gapstart > 0)
  {
    struct ddsi_xmsg *gap;

    if (gi.gapend == seqbase + msg->readerSNState.numbits)
      gi.gapend = grow_gap_to_next_seq (wr, gi.gapend);

    if (gi.gapend-1 + gi.gapnumbits > max_seq_in_reply)
      max_seq_in_reply = gi.gapend-1 + gi.gapnumbits;

    gap = ddsi_gap_info_create_gap (wr, prd, &gi);
    if (gap)
    {
      ddsi_qxev_msg (wr->evq, gap);
      msgs_sent++;
    }
  }
//收到NACK重传会携带心跳
  wr->rexmit_count += msgs_sent;
  wr->rexmit_lost_count += msgs_lost;
  //如果发送了消息，则打印相应的日志
  if (msgs_sent)
  {
    RSTTRACE (" rexmit#%"PRIu32" maxseq:%"PRIu64"<%"PRIu64"<=%"PRIu64"", msgs_sent, max_seq_in_reply, seq_xmit, wr->seq);

    defer_heartbeat_to_peer (wr, &whcst, prd, 1, defer_hb_state);
    hb_sent_in_response = 1;

    /* The primary purpose of hbcontrol_note_asyncwrite is to ensure
       heartbeats will go out at the "normal" rate again, instead of a
       gradually lowering rate.  If we just got a request for a
       retransmit, and there is more to be retransmitted, surely the
       rate should be kept up for now */
    ddsi_writer_hbcontrol_note_asyncwrite (wr, ddsrt_time_monotonic ());
  }
  /* If "final" flag not set, we must respond with a heartbeat. Do it
     now if we haven't done so already */
  if (!(msg->smhdr.flags & DDSI_ACKNACK_FLAG_FINAL) && !hb_sent_in_response)
  {
    defer_heartbeat_to_peer (wr, &whcst, prd, 0, defer_hb_state);
  }
  RSTTRACE (")");
 out:
  ddsrt_mutex_unlock (&wr->e.lock);
  ddsi_whc_free_deferred_free_list (wr->whc, deferred_free_list);
  return 1;
}

static void handle_forall_destinations (const ddsi_guid_t *dst, struct ddsi_proxy_writer *pwr, ddsrt_avl_walk_t fun, void *arg)
{
  /* prefix:  id:   to:
     0        0     all matched readers
     0        !=0   all matched readers with entityid id
     !=0      0     to all matched readers in addressed participant
     !=0      !=0   to the one addressed reader
  */
  const int haveprefix =
    !(dst->prefix.u[0] == 0 && dst->prefix.u[1] == 0 && dst->prefix.u[2] == 0);
  const int haveid = !(dst->entityid.u == DDSI_ENTITYID_UNKNOWN);

  /* must have pwr->e.lock held for safely iterating over readers */
  ASSERT_MUTEX_HELD (&pwr->e.lock);

  switch ((haveprefix << 1) | haveid)
  {
    case (0 << 1) | 0: /* all: full treewalk */
      ddsrt_avl_walk (&ddsi_pwr_readers_treedef, &pwr->readers, fun, arg);
      break;
    case (0 << 1) | 1: /* all with correct entityid: special filtering treewalk */
      {
        struct ddsi_pwr_rd_match *wn;
        for (wn = ddsrt_avl_find_min (&ddsi_pwr_readers_treedef, &pwr->readers); wn; wn = ddsrt_avl_find_succ (&ddsi_pwr_readers_treedef, &pwr->readers, wn))
        {
          if (wn->rd_guid.entityid.u == dst->entityid.u)
            fun (wn, arg);
        }
      }
      break;
    case (1 << 1) | 0: /* all within one participant: walk a range of keyvalues */
      {
        ddsi_guid_t a, b;
        a = *dst; a.entityid.u = 0;
        b = *dst; b.entityid.u = ~0u;
        ddsrt_avl_walk_range (&ddsi_pwr_readers_treedef, &pwr->readers, &a, &b, fun, arg);
      }
      break;
    case (1 << 1) | 1: /* fully addressed: dst should exist (but for removal) */
      {
        struct ddsi_pwr_rd_match *wn;
        if ((wn = ddsrt_avl_lookup (&ddsi_pwr_readers_treedef, &pwr->readers, dst)) != NULL)
          fun (wn, arg);
      }
      break;
  }
}

struct handle_Heartbeat_helper_arg {
  struct ddsi_receiver_state *rst;
  const ddsi_rtps_heartbeat_t *msg;
  struct ddsi_proxy_writer *pwr;
  ddsrt_wctime_t timestamp;
  ddsrt_etime_t tnow;
  ddsrt_mtime_t tnow_mt;
  bool directed_heartbeat;
};

static void handle_Heartbeat_helper (struct ddsi_pwr_rd_match * const wn, struct handle_Heartbeat_helper_arg * const arg)
{
  struct ddsi_receiver_state * const rst = arg->rst;
  ddsi_rtps_heartbeat_t const * const msg = arg->msg;
  struct ddsi_proxy_writer * const pwr = arg->pwr;

  ASSERT_MUTEX_HELD (&pwr->e.lock);

  if (wn->acknack_xevent == NULL)
  {
    // Ignore best-effort readers
    return;
  }

/*

accept_ack_or_hb_w_timeout 函数判断是否应该处理 ACKNACK。该函数用于判断两次处理 ACKNACK 或心跳消息的时间间隔是否足够，以防止频繁处理。

如果时间间隔不足，表示不应该处理当前的 ACKNACK 或心跳消息，直接返回。
如果时间间隔足够，继续执行后续操作*/
  if (!accept_ack_or_hb_w_timeout (msg->count, &wn->prev_heartbeat, arg->tnow, &wn->t_heartbeat_accepted, 0))
  {
    RSTTRACE (" ("PGUIDFMT")", PGUID (wn->rd_guid));
    return;
  }

  if (rst->gv->logconfig.c.mask & DDS_LC_TRACE)
  {
    ddsi_seqno_t refseq;
    if (wn->in_sync != PRMSS_OUT_OF_SYNC && !wn->filtered)
      refseq = ddsi_reorder_next_seq (pwr->reorder);
    else
      refseq = ddsi_reorder_next_seq (wn->u.not_in_sync.reorder);
    RSTTRACE (" "PGUIDFMT"@%"PRIu64"%s", PGUID (wn->rd_guid), refseq - 1, (wn->in_sync == PRMSS_SYNC) ? "(sync)" : (wn->in_sync == PRMSS_TLCATCHUP) ? "(tlcatchup)" : "");
  }

  wn->heartbeat_since_ack = 1;
  if (!(msg->smhdr.flags & DDSI_HEARTBEAT_FLAG_FINAL))
    wn->ack_requested = 1;
  if (arg->directed_heartbeat)
    wn->directed_heartbeat = 1;

  //主要用于决定是否要调度ACKNACK事件以及何时调度。
// 通过调用get_acknack_info函数获取ACKNACK信息，并根据结果决定后续的操作。
// 针对不同的结果（AANR_SUPPRESSED_ACK，AANR_SUPPRESSED_NACK等），决定是否执行后续操作或重新调度ACKNACK事件。
  ddsi_sched_acknack_if_needed (wn->acknack_xevent, pwr, wn, arg->tnow_mt, true);
}

static int handle_Heartbeat (struct ddsi_receiver_state *rst, ddsrt_etime_t tnow, struct ddsi_rmsg *rmsg, const ddsi_rtps_heartbeat_t *msg, ddsrt_wctime_t timestamp, ddsi_rtps_submessage_kind_t prev_smid)
{
  /*
  具体来说：

在处理心跳消息时，系统会对所有读者进行处理，而不管心跳消息中的目标地址是什么。这是为了处理由于心跳消息而变得可交付的具有序列号的样本。
然而，在生成应答消息（AckNacks）方面，系统会按照规范进行处理，具体的实现细节由handle_Heartbeat_helper函数负责。
心跳消息中的状态 [a,b] 被解释为可用序列号范围的最小间隔，这里将其解释为一个间隙 [1,a)。另请参阅handle_Gap函数。
总之，尽管在处理心跳消息时系统采取了一种偏离规范的行为，但在生成应答消息时仍然遵循规范。
  */
  /* We now cheat: and process the heartbeat for _all_ readers,
     always, regardless of the destination address in the Heartbeat
     sub-message. This is to take care of the samples with sequence
     numbers that become deliverable because of the heartbeat.

     We do play by the book with respect to generating AckNacks in
     response -- done by handle_Heartbeat_helper.

     A heartbeat that states [a,b] is the smallest interval in which
     the range of available sequence numbers is is interpreted here as
     a gap [1,a). See also handle_Gap.  */
  const ddsi_seqno_t firstseq = ddsi_from_seqno (msg->firstSN);
  const ddsi_seqno_t lastseq = ddsi_from_seqno (msg->lastSN);
  struct handle_Heartbeat_helper_arg arg;
  struct ddsi_proxy_writer *pwr;
  struct ddsi_lease *lease;
  ddsi_guid_t src, dst;

  src.prefix = rst->src_guid_prefix;
  src.entityid = msg->writerId;
  dst.prefix = rst->dst_guid_prefix;
  dst.entityid = msg->readerId;

  RSTTRACE ("HEARTBEAT(%s%s#%"PRId32":%"PRIu64"..%"PRIu64" ", msg->smhdr.flags & DDSI_HEARTBEAT_FLAG_FINAL ? "F" : "",
    msg->smhdr.flags & DDSI_HEARTBEAT_FLAG_LIVELINESS ? "L" : "", msg->count, firstseq, lastseq);

  if (!rst->forme)
  {
    RSTTRACE (PGUIDFMT" -> "PGUIDFMT" not-for-me)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((pwr = ddsi_entidx_lookup_proxy_writer_guid (rst->gv->entity_index, &src)) == NULL)
  {
    RSTTRACE (PGUIDFMT"? -> "PGUIDFMT")", PGUID (src), PGUID (dst));
    return 1;
  }

  if (!ddsi_security_validate_msg_decoding(&(pwr->e), &(pwr->c), pwr->c.proxypp, rst, prev_smid))
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" clear submsg from protected src)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((lease = ddsrt_atomic_ldvoidp (&pwr->c.proxypp->minl_auto)) != NULL)
    ddsi_lease_renew (lease, tnow);

  RSTTRACE (PGUIDFMT" -> "PGUIDFMT":", PGUID (src), PGUID (dst));
  ddsrt_mutex_lock (&pwr->e.lock);
  if (msg->smhdr.flags & DDSI_HEARTBEAT_FLAG_LIVELINESS &&
      pwr->c.xqos->liveliness.kind != DDS_LIVELINESS_AUTOMATIC &&
      pwr->c.xqos->liveliness.lease_duration != DDS_INFINITY)
  {
    if ((lease = ddsrt_atomic_ldvoidp (&pwr->c.proxypp->minl_man)) != NULL)
      ddsi_lease_renew (lease, tnow);
    ddsi_lease_renew (pwr->lease, tnow);
  }
  if (pwr->n_reliable_readers == 0)
  {
    RSTTRACE (PGUIDFMT" -> "PGUIDFMT" no-reliable-readers)", PGUID (src), PGUID (dst));
    ddsrt_mutex_unlock (&pwr->e.lock);
    return 1;
  }

  // Inserting a GAP for [1..gap_end_seq) is our way of implementing the processing of
  // a heartbeat that indicates some data we're still waiting for is no longer available.
  // (A no-op GAP is thrown away very quickly.)
  //
  // By definition that means we need gap_end_seq = firstseq, but the first heartbeat has
  // to be treated specially because the spec doesn't define anything for a full handshake
  // establishing a well-defined start point for a reliable session *and* it also defines
  // that one may have a transient-local writer with a volatile reader, and so the last
  // sequence number is the only one that can be used to start up a volatile reader ...
  /*
  GAP的插入和处理： 在心跳处理的过程中，通过插入GAP来处理可能缺失的数据范围。GAP表示某个范围内的数据可能在传输过程中丢失，需要进行处理。

第一次心跳特殊处理： 对于第一次接收到的心跳消息，特殊处理 gap_end_seq 以确保它等于 firstseq。这是因为在初始阶段，通信双方可能尚未建立同步，需要特殊处理以确保正确的起始点。

更新代理写者状态： 根据心跳消息中的信息更新代理写者的最后一次序列号和碎片编号。这有助于跟踪写者发布的数据状态。

GAP的过滤： 根据配置和目标GUID等条件，尝试对GAP进行过滤。过滤的目的是将消息发送到指定的读者，而不是广播给所有读者。

将GAP加入待发送队列： 将经过处理的GAP加入到待发送队列，准备发送给相应的读者。根据配置选择同步或异步地处理用户数据。

处理读者状态： 根据读者的同步状态（同步、追赶转瞬本地数据、失步）进行相应的处理。例如，在失步状态下，使用 firstseq 处理GAP，并通知相应的读者。
 
 在代码的实现中，首先确定了GAP的结束序列号（gap_end_seq），然后根据是否已经接收到过心跳消息来决定是否需要特殊处理gap_end_seq。接着，更新了代理写者的状态，包括最后一个序列号和碎片编号。最后，调用了ddsi_defrag_notegap函数来将GAP添加到缺失数据通知列表中，以便后续处理。
 
  */
  ddsi_seqno_t gap_end_seq = firstseq;
  if (!pwr->have_seen_heartbeat)
  {
    // Note: if the writer is Cyclone DDS, there will not be any data, for other implementations
    // anything goes.
    gap_end_seq = lastseq + 1;
    // validate_Heartbeat requires that 0 < firstseq <= lastseq+1 (lastseq = firstseq - 1
    // is the encoding for an empty WHC), this matters here because it guarantees changing
    // gap_end_seq doesn't lower sequence number.
    assert (gap_end_seq >= firstseq);
    pwr->have_seen_heartbeat = 1;
  }

  if (lastseq > pwr->last_seq)
  {
    pwr->last_seq = lastseq;
    pwr->last_fragnum = UINT32_MAX;
  }
  else if (pwr->last_fragnum != UINT32_MAX && lastseq == pwr->last_seq)
  {
    pwr->last_fragnum = UINT32_MAX;
  }
/*

创建GAP结构体：首先创建一个表示GAP的ddsi_rdata结构体，并将其初始化为一个新的GAP对象。

检查是否需要进行内容过滤：如果代理写者启用了内容过滤且目标GUID不为空，则需要检查是否有读者的目标GUID与之匹配。如果匹配成功且该读者启用了内容过滤，则根据该读者的重排序机制，对GAP进行重新排序处理，并将处理后的数据加入待发送队列。然后更新该读者的最后一个序列号。此时，filtered标志被设置为1。

处理未经过内容过滤的情况：如果没有进行内容过滤，或者目标GUID为空，则对GAP进行普通的重新排序处理。根据代理写者的重排序机制，将处理后的数据加入待发送队列。然后，遍历代理写者的所有读者，根据它们的同步状态进行相应的处理。

更新引用计数：最后，调整GAP的引用计数。

调用handle_forall_destinations函数：在处理所有目标的函数中，调用了handle_Heartbeat_helper函数，对于所有读者进行了处理。

这段代码的作用是根据心跳消息中的信息对GAP进行处理，并根据代理写者的配置和读者的状态将处理后的数据加入待发送队列。
*/

/*
如果读者处于PRMSS_SYNC状态，意味着读者已经与代理写者同步，不需要再处理GAP，因此跳过。

如果读者处于PRMSS_TLCATCHUP状态，表示读者正在追赶转瞬本地数据，可能需要根据代理写者的重排序机制进行相应的处理，并将数据加入待发送队列。

如果读者处于PRMSS_OUT_OF_SYNC状态，表示读者已经失步，可能需要根据读者的重排序机制进行处理，并将数据加入待发送队列。

*/
  ddsi_defrag_notegap (pwr->defrag, 1, gap_end_seq);

  {
    struct ddsi_rdata *gap;
    struct ddsi_pwr_rd_match *wn;
    struct ddsi_rsample_chain sc;
    int refc_adjust = 0;
    ddsi_reorder_result_t res;
    gap = ddsi_rdata_newgap (rmsg);
    int filtered = 0;

    if (pwr->filtered && !ddsi_is_null_guid(&dst))
    {
      for (wn = ddsrt_avl_find_min (&ddsi_pwr_readers_treedef, &pwr->readers); wn; wn = ddsrt_avl_find_succ (&ddsi_pwr_readers_treedef, &pwr->readers, wn))
      {
        if (ddsi_guid_eq(&wn->rd_guid, &dst))
        {
          if (wn->filtered)
          {
            // Content filtering on reader GUID, and the HEARTBEAT destination GUID is
            // just that one reader, so it makes sense to "trust" the heartbeat and
            // use the advertised first sequence number in the WHC
            struct ddsi_reorder *ro = wn->u.not_in_sync.reorder;
            if ((res = ddsi_reorder_gap (&sc, ro, gap, 1, firstseq, &refc_adjust)) > 0)
              ddsi_dqueue_enqueue1 (pwr->dqueue, &wn->rd_guid, &sc, res);
            if (ddsi_from_seqno (msg->lastSN) > wn->last_seq)
            {
              wn->last_seq = ddsi_from_seqno (msg->lastSN);
            }
            filtered = 1;
          }
          break;
        }
      }
    }

    if (!filtered)
    {
      if ((res = ddsi_reorder_gap (&sc, pwr->reorder, gap, 1, gap_end_seq, &refc_adjust)) > 0)
      {
        if (pwr->deliver_synchronously)
          deliver_user_data_synchronously (&sc, NULL);
        else
          ddsi_dqueue_enqueue (pwr->dqueue, &sc, res);
      }
      for (wn = ddsrt_avl_find_min (&ddsi_pwr_readers_treedef, &pwr->readers); wn; wn = ddsrt_avl_find_succ (&ddsi_pwr_readers_treedef, &pwr->readers, wn))
      {
        if (wn->in_sync == PRMSS_SYNC)
          continue;
        if (wn->u.not_in_sync.end_of_tl_seq == DDSI_MAX_SEQ_NUMBER)
        {
          wn->u.not_in_sync.end_of_tl_seq = ddsi_from_seqno (msg->lastSN);
          RSTTRACE (" end-of-tl-seq(rd "PGUIDFMT" #%"PRIu64")", PGUID(wn->rd_guid), wn->u.not_in_sync.end_of_tl_seq);
        }
        switch (wn->in_sync)
        {
          case PRMSS_SYNC:
            assert(0);
            break;
          case PRMSS_TLCATCHUP:
            assert (ddsi_reorder_next_seq (pwr->reorder) > 0);
            maybe_set_reader_in_sync (pwr, wn, ddsi_reorder_next_seq (pwr->reorder) - 1);
            break;
          case PRMSS_OUT_OF_SYNC: {
            struct ddsi_reorder *ro = wn->u.not_in_sync.reorder;
            // per-reader "out-of-sync" reorder admins need to use firstseq: they are used
            // to retrieve transient-local data, hence fast-forwarding to lastseq would
            // mean they would never need to retrieve any historical data
            if ((res = ddsi_reorder_gap (&sc, ro, gap, 1, firstseq, &refc_adjust)) > 0)
            {
              if (pwr->deliver_synchronously)
                deliver_user_data_synchronously (&sc, &wn->rd_guid);
              else
                ddsi_dqueue_enqueue1 (pwr->dqueue, &wn->rd_guid, &sc, res);
            }
            assert (ddsi_reorder_next_seq (wn->u.not_in_sync.reorder) > 0);
            maybe_set_reader_in_sync (pwr, wn, ddsi_reorder_next_seq (wn->u.not_in_sync.reorder) - 1);
          }
        }
      }
    }
    ddsi_fragchain_adjust_refcount (gap, refc_adjust);
  }

  arg.rst = rst;
  arg.msg = msg;
  arg.pwr = pwr;
  arg.timestamp = timestamp;
  arg.tnow = tnow;
  arg.tnow_mt = ddsrt_time_monotonic ();
  arg.directed_heartbeat = (dst.entityid.u != DDSI_ENTITYID_UNKNOWN && ddsi_vendor_is_eclipse (rst->vendor));
  handle_forall_destinations (&dst, pwr, (ddsrt_avl_walk_t) handle_Heartbeat_helper, &arg);
  RSTTRACE (")");

  ddsrt_mutex_unlock (&pwr->e.lock);
  return 1;
}

static int handle_HeartbeatFrag (struct ddsi_receiver_state *rst, UNUSED_ARG(ddsrt_etime_t tnow), const ddsi_rtps_heartbeatfrag_t *msg, ddsi_rtps_submessage_kind_t prev_smid)
{
  const ddsi_seqno_t seq = ddsi_from_seqno (msg->writerSN);
  const ddsi_fragment_number_t fragnum = msg->lastFragmentNum - 1; /* we do 0-based */
  ddsi_guid_t src, dst;
  struct ddsi_proxy_writer *pwr;
  struct ddsi_lease *lease;

  src.prefix = rst->src_guid_prefix;
  src.entityid = msg->writerId;
  dst.prefix = rst->dst_guid_prefix;
  dst.entityid = msg->readerId;
  const bool directed_heartbeat = (dst.entityid.u != DDSI_ENTITYID_UNKNOWN && ddsi_vendor_is_eclipse (rst->vendor));

  RSTTRACE ("HEARTBEATFRAG(#%"PRId32":%"PRIu64"/[1,%"PRIu32"]", msg->count, seq, fragnum+1);
  if (!rst->forme)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" not-for-me)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((pwr = ddsi_entidx_lookup_proxy_writer_guid (rst->gv->entity_index, &src)) == NULL)
  {
    RSTTRACE (" "PGUIDFMT"? -> "PGUIDFMT")", PGUID (src), PGUID (dst));
    return 1;
  }

  if (!ddsi_security_validate_msg_decoding(&(pwr->e), &(pwr->c), pwr->c.proxypp, rst, prev_smid))
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" clear submsg from protected src)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((lease = ddsrt_atomic_ldvoidp (&pwr->c.proxypp->minl_auto)) != NULL)
    ddsi_lease_renew (lease, tnow);

  RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT"", PGUID (src), PGUID (dst));
  ddsrt_mutex_lock (&pwr->e.lock);

  if (seq > pwr->last_seq)
  {
    pwr->last_seq = seq;
    pwr->last_fragnum = fragnum;
  }
  else if (seq == pwr->last_seq && fragnum > pwr->last_fragnum)
  {
    pwr->last_fragnum = fragnum;
  }

  if (!pwr->have_seen_heartbeat)
  {
    ddsrt_mutex_unlock(&pwr->e.lock);
    return 1;
  }

  /* Defragmenting happens at the proxy writer, readers have nothing
     to do with it.  Here we immediately respond with a NackFrag if we
     discover a missing fragment, which differs significantly from
     handle_Heartbeat's scheduling of an AckNack event when it must
     respond.  Why?  Just because. */
  if (ddsrt_avl_is_empty (&pwr->readers) || pwr->local_matching_inprogress)
    RSTTRACE (" no readers");
  else
  {
    struct ddsi_pwr_rd_match *m = NULL;

    if (ddsi_reorder_wantsample (pwr->reorder, seq))
    {
      if (directed_heartbeat)
      {
        /* Cyclone currently only ever sends a HEARTBEAT(FRAG) with the
           destination entity id set AFTER retransmitting any samples
           that reader requested.  So it makes sense to only interpret
           those for that reader, and to suppress the NackDelay in a
           response to it.  But it better be a reliable reader! */
        m = ddsrt_avl_lookup (&ddsi_pwr_readers_treedef, &pwr->readers, &dst);
        if (m && m->acknack_xevent == NULL)
          m = NULL;
      }
      else
      {
        /* Pick an arbitrary reliable reader's guid for the response --
           assuming a reliable writer -> unreliable reader is rare, and
           so scanning the readers is acceptable if the first guess
           fails */
        m = ddsrt_avl_root_non_empty (&ddsi_pwr_readers_treedef, &pwr->readers);
        if (m->acknack_xevent == NULL)
        {
          m = ddsrt_avl_find_min (&ddsi_pwr_readers_treedef, &pwr->readers);
          while (m && m->acknack_xevent == NULL)
            m = ddsrt_avl_find_succ (&ddsi_pwr_readers_treedef, &pwr->readers, m);
        }
      }
    }
    else if (seq < ddsi_reorder_next_seq (pwr->reorder))
    {
      if (directed_heartbeat)
      {
        m = ddsrt_avl_lookup (&ddsi_pwr_readers_treedef, &pwr->readers, &dst);
        if (m && !(m->in_sync == PRMSS_OUT_OF_SYNC && m->acknack_xevent != NULL && ddsi_reorder_wantsample (m->u.not_in_sync.reorder, seq)))
        {
          /* Ignore if reader is happy or not best-effort */
          m = NULL;
        }
      }
      else
      {
        /* Check out-of-sync readers -- should add a bit to cheaply test
         whether there are any (usually there aren't) */
        m = ddsrt_avl_find_min (&ddsi_pwr_readers_treedef, &pwr->readers);
        while (m)
        {
          if (m->in_sync == PRMSS_OUT_OF_SYNC && m->acknack_xevent != NULL && ddsi_reorder_wantsample (m->u.not_in_sync.reorder, seq))
          {
            /* If reader is out-of-sync, and reader is realiable, and
             reader still wants this particular sample, then use this
             reader to decide which fragments to nack */
            break;
          }
          m = ddsrt_avl_find_succ (&ddsi_pwr_readers_treedef, &pwr->readers, m);
        }
      }
    }

    if (m == NULL)
      RSTTRACE (" no interested reliable readers");
    else
    {
      if (directed_heartbeat)
        m->directed_heartbeat = 1;
      m->heartbeatfrag_since_ack = 1;

      DDSRT_STATIC_ASSERT ((DDSI_FRAGMENT_NUMBER_SET_MAX_BITS % 32) == 0);
      struct {
        struct ddsi_fragment_number_set_header set;
        uint32_t bits[DDSI_FRAGMENT_NUMBER_SET_MAX_BITS / 32];
      } nackfrag;
      const ddsi_seqno_t last_seq = m->filtered ? m->last_seq : pwr->last_seq;
      if (seq == last_seq && ddsi_defrag_nackmap (pwr->defrag, seq, fragnum, &nackfrag.set, nackfrag.bits, DDSI_FRAGMENT_NUMBER_SET_MAX_BITS) == DDSI_DEFRAG_NACKMAP_FRAGMENTS_MISSING)
      {
        // don't rush it ...
        ddsi_resched_xevent_if_earlier (m->acknack_xevent, ddsrt_mtime_add_duration (ddsrt_time_monotonic (), pwr->e.gv->config.nack_delay));
      }
    }
  }
  RSTTRACE (")");
  ddsrt_mutex_unlock (&pwr->e.lock);
  return 1;
}

static int handle_NackFrag (struct ddsi_receiver_state *rst, ddsrt_etime_t tnow, const ddsi_rtps_nackfrag_t *msg, ddsi_rtps_submessage_kind_t prev_smid, struct defer_hb_state *defer_hb_state)
{
  struct ddsi_proxy_reader *prd;
  struct ddsi_wr_prd_match *rn;
  struct ddsi_writer *wr;
  struct ddsi_lease *lease;
  struct ddsi_whc_borrowed_sample sample;
  ddsi_guid_t src, dst;
  ddsi_count_t *countp;
  ddsi_seqno_t seq = ddsi_from_seqno (msg->writerSN);

  countp = (ddsi_count_t *) ((char *) msg + offsetof (ddsi_rtps_nackfrag_t, bits) + DDSI_FRAGMENT_NUMBER_SET_BITS_SIZE (msg->fragmentNumberState.numbits));
  src.prefix = rst->src_guid_prefix;
  src.entityid = msg->readerId;
  dst.prefix = rst->dst_guid_prefix;
  dst.entityid = msg->writerId;

  RSTTRACE ("NACKFRAG(#%"PRId32":%"PRIu64"/%"PRIu32"/%"PRIu32":", *countp, seq, msg->fragmentNumberState.bitmap_base, msg->fragmentNumberState.numbits);
  for (uint32_t i = 0; i < msg->fragmentNumberState.numbits; i++)
    RSTTRACE ("%c", ddsi_bitset_isset (msg->fragmentNumberState.numbits, msg->bits, i) ? '1' : '0');

  if (!rst->forme)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" not-for-me)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((wr = ddsi_entidx_lookup_writer_guid (rst->gv->entity_index, &dst)) == NULL)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT"?)", PGUID (src), PGUID (dst));
    return 1;
  }
  /* Always look up the proxy reader -- even though we don't need for
     the normal pure ack steady state. If (a big "if"!) this shows up
     as a significant portion of the time, we can always rewrite it to
     only retrieve it when needed. */
  if ((prd = ddsi_entidx_lookup_proxy_reader_guid (rst->gv->entity_index, &src)) == NULL)
  {
    RSTTRACE (" "PGUIDFMT"? -> "PGUIDFMT")", PGUID (src), PGUID (dst));
    return 1;
  }

  if (!ddsi_security_validate_msg_decoding(&(prd->e), &(prd->c), prd->c.proxypp, rst, prev_smid))
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" clear submsg from protected src)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((lease = ddsrt_atomic_ldvoidp (&prd->c.proxypp->minl_auto)) != NULL)
    ddsi_lease_renew (lease, tnow);

  if (!wr->reliable) /* note: reliability can't be changed */
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" not a reliable writer)", PGUID (src), PGUID (dst));
    return 1;
  }

  ddsrt_mutex_lock (&wr->e.lock);
  if ((rn = ddsrt_avl_lookup (&ddsi_wr_readers_treedef, &wr->readers, &src)) == NULL)
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" not a connection", PGUID (src), PGUID (dst));
    goto out;
  }

  /* Ignore old NackFrags (see also handle_AckNack) */
  if (!accept_ack_or_hb_w_timeout (*countp, &rn->prev_nackfrag, tnow, &rn->t_nackfrag_accepted, false))
  {
    RSTTRACE (" ["PGUIDFMT" -> "PGUIDFMT"]", PGUID (src), PGUID (dst));
    goto out;
  }
  RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT"", PGUID (src), PGUID (dst));

  /* Resend the requested fragments if we still have the sample, send
     a Gap if we don't have them anymore. */
  if (ddsi_whc_borrow_sample (wr->whc, seq, &sample))
  {
    const uint32_t base = msg->fragmentNumberState.bitmap_base - 1;
    assert (wr->rexmit_burst_size_limit <= UINT32_MAX - UINT16_MAX);
    uint32_t nfrags_lim = (wr->rexmit_burst_size_limit + wr->e.gv->config.fragment_size - 1) / wr->e.gv->config.fragment_size;
    bool sent = false;
    RSTTRACE (" scheduling requested frags ...\n");
    for (uint32_t i = 0; i < msg->fragmentNumberState.numbits && nfrags_lim > 0; i++)
    {
      if (ddsi_bitset_isset (msg->fragmentNumberState.numbits, msg->bits, i))
      {
        struct ddsi_xmsg *reply;
        if (ddsi_create_fragment_message (wr, seq, sample.serdata, base + i, 1, prd, &reply, 0, 0) < 0)
          nfrags_lim = 0;
        else if (ddsi_qxev_msg_rexmit_wrlock_held (wr->evq, reply, 0) == DDSI_QXEV_MSG_REXMIT_DROPPED)
          nfrags_lim = 0;
        else
        {
          sent = true;
          nfrags_lim--;
          wr->rexmit_bytes += wr->e.gv->config.fragment_size;
        }
      }
    }
    if (sent && sample.unacked)
    {
      if (!wr->retransmitting)
        ddsi_writer_set_retransmitting (wr);
    }
    ddsi_whc_return_sample (wr->whc, &sample, false);
  }
  else
  {
    static uint32_t zero = 0;
    struct ddsi_xmsg *m;
    RSTTRACE (" msg not available: scheduling Gap\n");
    m = ddsi_xmsg_new (rst->gv->xmsgpool, &wr->e.guid, wr->c.pp, 0, DDSI_XMSG_KIND_CONTROL);
    ddsi_xmsg_setdst_prd (m, prd);
    /* length-1 bitmap with the bit clear avoids the illegal case of a length-0 bitmap */
    ddsi_add_gap (m, wr, prd, seq, seq+1, 0, &zero);
    ddsi_qxev_msg (wr->evq, m);
  }
  if (seq <= ddsi_writer_read_seq_xmit (wr))
  {
    /* Not everything was retransmitted yet, so force a heartbeat out
       to give the reader a chance to nack the rest and make sure
       hearbeats will go out at a reasonably high rate for a while */
    struct ddsi_whc_state whcst;
    ddsi_whc_get_state(wr->whc, &whcst);
    defer_heartbeat_to_peer (wr, &whcst, prd, 1, defer_hb_state);
    ddsi_writer_hbcontrol_note_asyncwrite (wr, ddsrt_time_monotonic ());
  }

 out:
  ddsrt_mutex_unlock (&wr->e.lock);
  RSTTRACE (")");
  return 1;
}

static int handle_InfoDST (struct ddsi_receiver_state *rst, const ddsi_rtps_info_dst_t *msg, const ddsi_guid_prefix_t *dst_prefix)
{
  rst->dst_guid_prefix = ddsi_ntoh_guid_prefix (msg->guid_prefix);
  RSTTRACE ("INFODST(%"PRIx32":%"PRIx32":%"PRIx32")", PGUIDPREFIX (rst->dst_guid_prefix));
  if (rst->dst_guid_prefix.u[0] == 0 && rst->dst_guid_prefix.u[1] == 0 && rst->dst_guid_prefix.u[2] == 0)
  {
    if (dst_prefix)
      rst->dst_guid_prefix = *dst_prefix;
    rst->forme = 1;
  }
  else
  {
    ddsi_guid_t dst;
    dst.prefix = rst->dst_guid_prefix;
    dst.entityid = ddsi_to_entityid(DDSI_ENTITYID_PARTICIPANT);
    rst->forme = (ddsi_entidx_lookup_participant_guid (rst->gv->entity_index, &dst) != NULL ||
                  ddsi_is_deleted_participant_guid (rst->gv->deleted_participants, &dst, DDSI_DELETED_PPGUID_LOCAL));
  }
  return 1;
}

static int handle_InfoSRC (struct ddsi_receiver_state *rst, const ddsi_rtps_info_src_t *msg)
{
  rst->src_guid_prefix = ddsi_ntoh_guid_prefix (msg->guid_prefix);
  rst->protocol_version = msg->version;
  rst->vendor = msg->vendorid;
  RSTTRACE ("INFOSRC(%"PRIx32":%"PRIx32":%"PRIx32" vendor %u.%u)",
          PGUIDPREFIX (rst->src_guid_prefix), rst->vendor.id[0], rst->vendor.id[1]);
  return 1;
}

static int handle_InfoTS (const struct ddsi_receiver_state *rst, const ddsi_rtps_info_ts_t *msg, ddsrt_wctime_t *timestamp)
{
  RSTTRACE ("INFOTS(");
  if (msg->smhdr.flags & DDSI_INFOTS_INVALIDATE_FLAG)
  {
    *timestamp = DDSRT_WCTIME_INVALID;
    RSTTRACE ("invalidate");
  }
  else
  {
    *timestamp = ddsi_wctime_from_ddsi_time (msg->time);
    if (rst->gv->logconfig.c.mask & DDS_LC_TRACE)
      RSTTRACE ("%d.%09d", (int) (timestamp->v / 1000000000), (int) (timestamp->v % 1000000000));
  }
  RSTTRACE (")");
  return 1;
}

static int handle_one_gap (struct ddsi_proxy_writer *pwr, struct ddsi_pwr_rd_match *wn, ddsi_seqno_t a, ddsi_seqno_t b, struct ddsi_rdata *gap, int *refc_adjust)
{
  struct ddsi_rsample_chain sc;
  ddsi_reorder_result_t res = 0;
  int gap_was_valuable = 0;
  ASSERT_MUTEX_HELD (&pwr->e.lock);
  assert (a > 0 && b >= a);

  /* Clean up the defrag admin: no fragments of a missing sample will
     be arriving in the future */
  if (!(wn && wn->filtered))
  {
    ddsi_defrag_notegap (pwr->defrag, a, b);

    /* Primary reorder: the gap message may cause some samples to become
     deliverable. */

    if ((res = ddsi_reorder_gap (&sc, pwr->reorder, gap, a, b, refc_adjust)) > 0)
    {
      if (pwr->deliver_synchronously)
        deliver_user_data_synchronously (&sc, NULL);
      else
        ddsi_dqueue_enqueue (pwr->dqueue, &sc, res);
    }
  }

  /* If the result was REJECT or TOO_OLD, then this gap didn't add
     anything useful, or there was insufficient memory to store it.
     When the result is either ACCEPT or a sample chain, it clearly
     meant something. */
  DDSRT_STATIC_ASSERT_CODE (DDSI_REORDER_ACCEPT == 0);
  if (res >= 0)
    gap_was_valuable = 1;

  /* Out-of-sync readers never deal with samples with a sequence
     number beyond end_of_tl_seq -- and so it needn't be bothered
     with gaps that start beyond that number */
  if (wn != NULL && wn->in_sync != PRMSS_SYNC)
  {
    switch (wn->in_sync)
    {
      case PRMSS_SYNC:
        assert(0);
        break;
      case PRMSS_TLCATCHUP:
        break;
      case PRMSS_OUT_OF_SYNC:
        if ((res = ddsi_reorder_gap (&sc, wn->u.not_in_sync.reorder, gap, a, b, refc_adjust)) > 0)
        {
          if (pwr->deliver_synchronously)
            deliver_user_data_synchronously (&sc, &wn->rd_guid);
          else
            ddsi_dqueue_enqueue1 (pwr->dqueue, &wn->rd_guid, &sc, res);
        }
        if (res >= 0)
          gap_was_valuable = 1;
        break;
    }

    /* Upon receipt of data a reader can only become in-sync if there
       is something to deliver; for missing data, you just don't know.
       The return value of reorder_gap _is_ sufficiently precise, but
       why not simply check?  It isn't a very expensive test. */
    maybe_set_reader_in_sync (pwr, wn, b-1);
  }

  return gap_was_valuable;
}

static int handle_Gap (struct ddsi_receiver_state *rst, ddsrt_etime_t tnow, struct ddsi_rmsg *rmsg, const ddsi_rtps_gap_t *msg, ddsi_rtps_submessage_kind_t prev_smid)
{
  /* Option 1: Process the Gap for the proxy writer and all
     out-of-sync readers: what do I care which reader is being
     addressed?  Either the sample can still be reproduced by the
     writer, or it can't be anymore.

     Option 2: Process the Gap for the proxy writer and for the
     addressed reader if it happens to be out-of-sync.

     Obviously, both options differ from the specification, but we
     don't have much choice: there is no way of addressing just a
     single in-sync reader, and if that's impossible than we might as
     well ignore the destination completely.

     Option 1 can be fairly expensive if there are many readers, so we
     do option 2. */

  struct ddsi_proxy_writer *pwr;
  struct ddsi_pwr_rd_match *wn;
  struct ddsi_lease *lease;
  ddsi_guid_t src, dst;
  ddsi_seqno_t gapstart, listbase;
  uint32_t first_excluded_rel;
  uint32_t listidx;

  src.prefix = rst->src_guid_prefix;
  src.entityid = msg->writerId;
  dst.prefix = rst->dst_guid_prefix;
  dst.entityid = msg->readerId;
  gapstart = ddsi_from_seqno (msg->gapStart);
  listbase = ddsi_from_seqno (msg->gapList.bitmap_base);
  RSTTRACE ("GAP(%"PRIu64"..%"PRIu64"/%"PRIu32" ", gapstart, listbase, msg->gapList.numbits);

  // valid_Gap guarantees this, but as we are doing sequence number
  // calculations it doesn't hurt to document it here again
  assert (listbase >= gapstart && gapstart >= 1);

  /* There is no _good_ reason for a writer to start the bitmap with a
     1 bit, but check for it just in case, to reduce the number of
     sequence number gaps to be processed. */
  for (listidx = 0; listidx < msg->gapList.numbits; listidx++)
    if (!ddsi_bitset_isset (msg->gapList.numbits, msg->bits, listidx))
      break;
  first_excluded_rel = listidx;

  if (!rst->forme)
  {
    RSTTRACE (""PGUIDFMT" -> "PGUIDFMT" not-for-me)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((pwr = ddsi_entidx_lookup_proxy_writer_guid (rst->gv->entity_index, &src)) == NULL)
  {
    RSTTRACE (""PGUIDFMT"? -> "PGUIDFMT")", PGUID (src), PGUID (dst));
    return 1;
  }

  if (!ddsi_security_validate_msg_decoding(&(pwr->e), &(pwr->c), pwr->c.proxypp, rst, prev_smid))
  {
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT" clear submsg from protected src)", PGUID (src), PGUID (dst));
    return 1;
  }

  if ((lease = ddsrt_atomic_ldvoidp (&pwr->c.proxypp->minl_auto)) != NULL)
    ddsi_lease_renew (lease, tnow);

  ddsrt_mutex_lock (&pwr->e.lock);
  if ((wn = ddsrt_avl_lookup (&ddsi_pwr_readers_treedef, &pwr->readers, &dst)) == NULL)
  {
    RSTTRACE (PGUIDFMT" -> "PGUIDFMT" not a connection)", PGUID (src), PGUID (dst));
    ddsrt_mutex_unlock (&pwr->e.lock);
    return 1;
  }
  RSTTRACE (PGUIDFMT" -> "PGUIDFMT, PGUID (src), PGUID (dst));

  if (!pwr->have_seen_heartbeat && pwr->n_reliable_readers > 0 && ddsi_vendor_is_eclipse (rst->vendor))
  {
    RSTTRACE (": no heartbeat seen yet");
    ddsrt_mutex_unlock (&pwr->e.lock);
    return 1;
  }

  /* Notify reordering in proxy writer & and the addressed reader (if
     it is out-of-sync, &c.), while delivering samples that become
     available because preceding ones are now known to be missing. */
  {
    int refc_adjust = 0;
    struct ddsi_rdata *gap;
    gap = ddsi_rdata_newgap (rmsg);
    if (gapstart < listbase + listidx)
    {
      /* sanity check on sequence numbers because a GAP message is not invalid even
         if start >= listbase (DDSI 2.1 sect 8.3.7.4.3), but only handle non-empty
         intervals */
      (void) handle_one_gap (pwr, wn, gapstart, listbase + listidx, gap, &refc_adjust);
    }
    while (listidx < msg->gapList.numbits)
    {
      if (!ddsi_bitset_isset (msg->gapList.numbits, msg->bits, listidx))
        listidx++;
      else
      {
        uint32_t j;
        for (j = listidx + 1; j < msg->gapList.numbits; j++)
          if (!ddsi_bitset_isset (msg->gapList.numbits, msg->bits, j))
            break;
        /* spec says gapList (2) identifies an additional list of sequence numbers that
           are invalid (8.3.7.4.2), so by that rule an insane start would simply mean the
           initial interval is to be ignored and the bitmap to be applied */
        (void) handle_one_gap (pwr, wn, listbase + listidx, listbase + j, gap, &refc_adjust);
        assert(j >= 1);
        first_excluded_rel = j;
        listidx = j;
      }
    }
    ddsi_fragchain_adjust_refcount (gap, refc_adjust);
  }

  /* If the last sequence number explicitly included in the set is
     beyond the last sequence number we know exists, update the
     latter.  Note that a sequence number _not_ included in the set
     doesn't tell us anything (which is something that RTI apparently
     got wrong in its interpetation of pure acks that do include a
     bitmap).  */
  const ddsi_seqno_t lastseq = { listbase + first_excluded_rel - 1 };
  if (lastseq > pwr->last_seq)
  {
    pwr->last_seq = lastseq;
    pwr->last_fragnum = UINT32_MAX;
  }

  if (wn && wn->filtered)
  {
    if (lastseq > wn->last_seq)
      wn->last_seq = lastseq;
  }
  RSTTRACE (")");
  ddsrt_mutex_unlock (&pwr->e.lock);
  return 1;
}

static struct ddsi_serdata *get_serdata (struct ddsi_sertype const * const type, const struct ddsi_rdata *fragchain, uint32_t sz, int justkey, unsigned statusinfo, ddsrt_wctime_t tstamp)
{
  struct ddsi_serdata *sd = ddsi_serdata_from_ser (type, justkey ? SDK_KEY : SDK_DATA, fragchain, sz);
  if (sd)
  {
    sd->statusinfo = statusinfo;
    sd->timestamp = tstamp;
  }
  return sd;
}

struct remote_sourceinfo {
  const struct ddsi_rsample_info *sampleinfo;
  unsigned char data_smhdr_flags;
  const ddsi_plist_t *qos;
  const struct ddsi_rdata *fragchain;
  unsigned statusinfo;
  ddsrt_wctime_t tstamp;
};

static struct ddsi_serdata *remote_make_sample (struct ddsi_tkmap_instance **tk, struct ddsi_domaingv *gv, struct ddsi_sertype const * const type, void *vsourceinfo)
{
  /* hopefully the compiler figures out that these are just aliases and doesn't reload them
     unnecessarily from memory */
  const struct remote_sourceinfo * __restrict si = vsourceinfo;
  const struct ddsi_rsample_info * __restrict sampleinfo = si->sampleinfo;
  const struct ddsi_rdata * __restrict fragchain = si->fragchain;
  const uint32_t statusinfo = si->statusinfo;
  const unsigned char data_smhdr_flags = si->data_smhdr_flags;
  const ddsrt_wctime_t tstamp = si->tstamp;
  const ddsi_plist_t * __restrict qos = si->qos;
  const char *failmsg = NULL;
  struct ddsi_serdata *sample = NULL;

  if (si->statusinfo == 0)
  {
    /* normal write */
    if (!(data_smhdr_flags & DDSI_DATA_FLAG_DATAFLAG) || sampleinfo->size == 0)
    {
      const struct ddsi_proxy_writer *pwr = sampleinfo->pwr;
      ddsi_guid_t guid;
      /* pwr can't currently be null, but that might change some day, and this being
         an error path, it doesn't hurt to survive that */
      if (pwr) guid = pwr->e.guid; else memset (&guid, 0, sizeof (guid));
      DDS_CTRACE (&gv->logconfig,
                  "data(application, vendor %u.%u): "PGUIDFMT" #%"PRIu64": write without proper payload (data_smhdr_flags 0x%x size %"PRIu32")\n",
                  sampleinfo->rst->vendor.id[0], sampleinfo->rst->vendor.id[1],
                  PGUID (guid), sampleinfo->seq,
                  si->data_smhdr_flags, sampleinfo->size);
      return NULL;
    }
    sample = get_serdata (type, fragchain, sampleinfo->size, 0, statusinfo, tstamp);
  }
  else if (sampleinfo->size)
  {
    /* dispose or unregister with included serialized key or data
       (data is a Adlink extension) -- i.e., dispose or unregister
       as one would expect to receive */
    if (data_smhdr_flags & DDSI_DATA_FLAG_KEYFLAG)
    {
      sample = get_serdata (type, fragchain, sampleinfo->size, 1, statusinfo, tstamp);
    }
    else
    {
      assert (data_smhdr_flags & DDSI_DATA_FLAG_DATAFLAG);
      sample = get_serdata (type, fragchain, sampleinfo->size, 0, statusinfo, tstamp);
    }
  }
  else if (data_smhdr_flags & DDSI_DATA_FLAG_INLINE_QOS)
  {
    /* RTI always tries to make us survive on the keyhash. RTI must
       mend its ways. */
    if (DDSI_SC_STRICT_P (gv->config))
      failmsg = "no content";
    else if (!(qos->present & PP_KEYHASH))
      failmsg = "qos present but without keyhash";
    else if (ddsi_omg_plist_keyhash_is_protected (qos))
    {
      /* If the keyhash is protected, then it is forced to be an actual MD5
       * hash. This means the keyhash can't be decoded into a sample. */
      failmsg = "keyhash is protected";
    }
    else if ((sample = ddsi_serdata_from_keyhash (type, &qos->keyhash)) == NULL)
      failmsg = "keyhash is MD5 and can't be converted to key value";
    else
    {
      sample->statusinfo = statusinfo;
      sample->timestamp = tstamp;
    }
  }
  else
  {
    failmsg = "no content whatsoever";
  }
  if (sample == NULL)
  {
    /* No message => error out */
    const struct ddsi_proxy_writer *pwr = sampleinfo->pwr;
    ddsi_guid_t guid;
    if (pwr) guid = pwr->e.guid; else memset (&guid, 0, sizeof (guid));
    DDS_CWARNING (&gv->logconfig,
                  "data(application, vendor %u.%u): "PGUIDFMT" #%"PRIu64": deserialization %s/%s failed (%s)\n",
                  sampleinfo->rst->vendor.id[0], sampleinfo->rst->vendor.id[1],
                  PGUID (guid), sampleinfo->seq,
                  pwr && (pwr->c.xqos->present & DDSI_QP_TOPIC_NAME) ? pwr->c.xqos->topic_name : "", type->type_name,
                  failmsg ? failmsg : "for reasons unknown");
  }
  else
  {
    if ((*tk = ddsi_tkmap_lookup_instance_ref (gv->m_tkmap, sample)) == NULL)
    {
      ddsi_serdata_unref (sample);
      sample = NULL;
    }
    else if (gv->logconfig.c.mask & DDS_LC_TRACE)
    {
      const struct ddsi_proxy_writer *pwr = sampleinfo->pwr;
      ddsi_guid_t guid;
      char tmp[1024];
      size_t res = 0;
      tmp[0] = 0;
      if (gv->logconfig.c.mask & DDS_LC_CONTENT)
        res = ddsi_serdata_print (sample, tmp, sizeof (tmp));
      if (pwr) guid = pwr->e.guid; else memset (&guid, 0, sizeof (guid));
      GVTRACE ("data(application, vendor %u.%u): "PGUIDFMT" #%"PRIu64": ST%"PRIx32" %s/%s:%s%s",
               sampleinfo->rst->vendor.id[0], sampleinfo->rst->vendor.id[1],
               PGUID (guid), sampleinfo->seq, statusinfo,
               pwr && (pwr->c.xqos->present & DDSI_QP_TOPIC_NAME) ? pwr->c.xqos->topic_name : "", type->type_name,
               tmp, res < sizeof (tmp) - 1 ? "" : "(trunc)");
    }
  }
  return sample;
}

unsigned char ddsi_normalize_data_datafrag_flags (const ddsi_rtps_submessage_header_t *smhdr)
{
  switch ((ddsi_rtps_submessage_kind_t) smhdr->submessageId)
  {
    case DDSI_RTPS_SMID_DATA:
      return smhdr->flags;
    case DDSI_RTPS_SMID_DATA_FRAG:
      {
        unsigned char common = smhdr->flags & DDSI_DATA_FLAG_INLINE_QOS;
        DDSRT_STATIC_ASSERT_CODE (DDSI_DATA_FLAG_INLINE_QOS == DDSI_DATAFRAG_FLAG_INLINE_QOS);
        if (smhdr->flags & DDSI_DATAFRAG_FLAG_KEYFLAG)
          return common | DDSI_DATA_FLAG_KEYFLAG;
        else
          return common | DDSI_DATA_FLAG_DATAFLAG;
      }
    default:
      assert (0);
      return 0;
  }
}

static struct ddsi_reader *proxy_writer_first_in_sync_reader (struct ddsi_entity_index *entity_index, struct ddsi_entity_common *pwrcmn, ddsrt_avl_iter_t *it)
{
  assert (pwrcmn->kind == DDSI_EK_PROXY_WRITER);
  struct ddsi_proxy_writer *pwr = (struct ddsi_proxy_writer *) pwrcmn;
  struct ddsi_pwr_rd_match *m;
  struct ddsi_reader *rd;
  for (m = ddsrt_avl_iter_first (&ddsi_pwr_readers_treedef, &pwr->readers, it); m != NULL; m = ddsrt_avl_iter_next (it))
    if (m->in_sync == PRMSS_SYNC && (rd = ddsi_entidx_lookup_reader_guid (entity_index, &m->rd_guid)) != NULL)
      return rd;
  return NULL;
}

static struct ddsi_reader *proxy_writer_next_in_sync_reader (struct ddsi_entity_index *entity_index, ddsrt_avl_iter_t *it)
{
  struct ddsi_pwr_rd_match *m;
  struct ddsi_reader *rd;
  for (m = ddsrt_avl_iter_next (it); m != NULL; m = ddsrt_avl_iter_next (it))
    if (m->in_sync == PRMSS_SYNC && (rd = ddsi_entidx_lookup_reader_guid (entity_index, &m->rd_guid)) != NULL)
      return rd;
  return NULL;
}

static dds_return_t remote_on_delivery_failure_fastpath (struct ddsi_entity_common *source_entity, bool source_entity_locked, struct ddsi_local_reader_ary *fastpath_rdary, void *vsourceinfo)
{
  (void) vsourceinfo;
  ddsrt_mutex_unlock (&fastpath_rdary->rdary_lock);
  if (source_entity_locked)
    ddsrt_mutex_unlock (&source_entity->lock);

  dds_sleepfor (DDS_MSECS (10));

  if (source_entity_locked)
    ddsrt_mutex_lock (&source_entity->lock);
  ddsrt_mutex_lock (&fastpath_rdary->rdary_lock);
  return DDS_RETCODE_TRY_AGAIN;
}

//接收到的数据传递到本地，涉及到了一系列的数据结构和处理操作
static int deliver_user_data (const struct ddsi_rsample_info *sampleinfo, const struct ddsi_rdata *fragchain, const ddsi_guid_t *rdguid, int pwr_locked)
{
  static const struct ddsi_deliver_locally_ops deliver_locally_ops = {
    .makesample = remote_make_sample,
    .first_reader = proxy_writer_first_in_sync_reader,
    .next_reader = proxy_writer_next_in_sync_reader,
    .on_failure_fastpath = remote_on_delivery_failure_fastpath
  };
  struct ddsi_receiver_state const * const rst = sampleinfo->rst;
  struct ddsi_domaingv * const gv = rst->gv;
  struct ddsi_proxy_writer * const pwr = sampleinfo->pwr;
  unsigned statusinfo;
  ddsi_rtps_data_datafrag_common_t *msg;
  unsigned char data_smhdr_flags;
  ddsi_plist_t qos;
  int need_keyhash;

  /* FIXME: fragments are now handled by copying the message to
     freshly malloced memory (see defragment()) ... that'll have to
     change eventually */
  assert (fragchain->min == 0);
  assert (!ddsi_is_builtin_entityid (pwr->e.guid.entityid, pwr->c.vendor));

  /* Luckily, the Data header (up to inline QoS) is a prefix of the
     DataFrag header, so for the fixed-position things that we're
     interested in here, both can be treated as Data submessages. */
     //从接收到的数据中提取数据子消息（Data Submessage）的指针。
     //假设 DDSI_RDATA_SUBMSG_OFF (fragchain) 返回的偏移量是 100，表示数据子消息在消息中的偏移量为 100 字节
  msg = (ddsi_rtps_data_datafrag_common_t *) DDSI_RMSG_PAYLOADOFF (fragchain->rmsg, DDSI_RDATA_SUBMSG_OFF (fragchain));
  //通过规范化数据子消息的标志获取数据子消息头标志。
  data_smhdr_flags = ddsi_normalize_data_datafrag_flags (&msg->smhdr);

  /* Extract QoS's to the extent necessary.  The expected case has all
     we need predecoded into a few bits in the sample info.

     If there is no payload, it is either a completely invalid message
     or a dispose/unregister in RTI style.  We assume the latter,
     consequently expect to need the keyhash.  Then, if sampleinfo
     says it is a complex qos, or the keyhash is required, extract all
     we need from the inline qos.

     Complex qos bit also gets set when statusinfo bits other than
     dispose/unregister are set.  They are not currently defined, but
     this may save us if they do get defined one day.  */
     //确定是否需要关键散列。？？？
  need_keyhash = (sampleinfo->size == 0 || (data_smhdr_flags & (DDSI_DATA_FLAG_KEYFLAG | DDSI_DATA_FLAG_DATAFLAG)) == 0);
  //如果条件 (sampleinfo->complex_qos || need_keyhash) || !(data_smhdr_flags & DDSI_DATA_FLAG_INLINE_QOS) 不成立，
  //表示服务质量参数已经在样本信息中预解码，直接使用；否则，需要从内联服务质量参数中提取。
  if (!(sampleinfo->complex_qos || need_keyhash) || !(data_smhdr_flags & DDSI_DATA_FLAG_INLINE_QOS))
  {
    ddsi_plist_init_empty (&qos);
    statusinfo = sampleinfo->statusinfo;
  }
  else
  {
    ddsi_plist_src_t src;
    size_t qos_offset = DDSI_RDATA_SUBMSG_OFF (fragchain) + offsetof (ddsi_rtps_data_datafrag_common_t, octetsToInlineQos) + sizeof (msg->octetsToInlineQos) + msg->octetsToInlineQos;
    dds_return_t plist_ret;
    src.protocol_version = rst->protocol_version;
    src.vendorid = rst->vendor;
    src.encoding = (msg->smhdr.flags & DDSI_RTPS_SUBMESSAGE_FLAG_ENDIANNESS) ? DDSI_RTPS_PL_CDR_LE : DDSI_RTPS_PL_CDR_BE;
    src.buf = DDSI_RMSG_PAYLOADOFF (fragchain->rmsg, qos_offset);
    src.bufsz = DDSI_RDATA_PAYLOAD_OFF (fragchain) - qos_offset;
    src.strict = DDSI_SC_STRICT_P (gv->config);
    if ((plist_ret = ddsi_plist_init_frommsg (&qos, NULL, PP_STATUSINFO | PP_KEYHASH, 0, &src, gv, DDSI_PLIST_CONTEXT_INLINE_QOS)) < 0)
    {
      if (plist_ret != DDS_RETCODE_UNSUPPORTED)
        GVWARNING ("data(application, vendor %u.%u): "PGUIDFMT" #%"PRIu64": invalid inline qos\n",
                   src.vendorid.id[0], src.vendorid.id[1], PGUID (pwr->e.guid), sampleinfo->seq);
      return 0;
    }
    statusinfo = (qos.present & PP_STATUSINFO) ? qos.statusinfo : 0;
  }

  /* FIXME: should it be 0, local wall clock time or INVALID? */
  const ddsrt_wctime_t tstamp = (sampleinfo->timestamp.v != DDSRT_WCTIME_INVALID.v) ? sampleinfo->timestamp : ((ddsrt_wctime_t) {0});
  struct ddsi_writer_info wrinfo;
  //定义写入器信息。
  ddsi_make_writer_info (&wrinfo, &pwr->e, pwr->c.xqos, statusinfo);

  //定义远程源信息，用于传递给 ddsi_deliver_locally_one 或 ddsi_deliver_locally_allinsync。
  struct remote_sourceinfo sourceinfo = {
    .sampleinfo = sampleinfo,
    .data_smhdr_flags = data_smhdr_flags,
    .qos = &qos,
    .fragchain = fragchain,
    .statusinfo = statusinfo,
    .tstamp = tstamp
  };
  if (rdguid)
    (void) ddsi_deliver_locally_one (gv, &pwr->e, pwr_locked != 0, rdguid, &wrinfo, &deliver_locally_ops, &sourceinfo);
  else
  {
    (void) ddsi_deliver_locally_allinsync (gv, &pwr->e, pwr_locked != 0, &pwr->rdary, &wrinfo, &deliver_locally_ops, &sourceinfo);
    ddsrt_atomic_st32 (&pwr->next_deliv_seq_lowword, (uint32_t) (sampleinfo->seq + 1));
  }

  ddsi_plist_fini (&qos);
  return 0;
}

int ddsi_user_dqueue_handler (const struct ddsi_rsample_info *sampleinfo, const struct ddsi_rdata *fragchain, const ddsi_guid_t *rdguid, UNUSED_ARG (void *qarg))
{
  int res;
  res = deliver_user_data (sampleinfo, fragchain, rdguid, 0);
  return res;
}

/*
while (sc->first)：循环开始，只要 sc 中仍有待传递的样本链元素（first 不为空），就会一直执行。

struct ddsi_rsample_chain_elem *e = sc->first;：将链表中的第一个元素赋值给 e，然后将 sc 的 first 指向下一个元素，以准备下一次循环。

if (e->sampleinfo != NULL)：检查样本信息是否存在。这是为了确保不尝试传递一个缺失的样本（gap）。注释中提到这可能与 sample_lost 事件有关。

deliver_user_data(e->sampleinfo, e->fragchain, rdguid, 1);：调用 deliver_user_data 函数，传递样本信息、碎片链和读者的GUID。第四个参数为1，可能表示同步传递。

ddsi_fragchain_unref(e->fragchain);：将 e 中的碎片链的引用计数减一。这是为了确保释放碎片链的资源。

循环继续，处理下一个样本链元素。
*/
static void deliver_user_data_synchronously (struct ddsi_rsample_chain *sc, const ddsi_guid_t *rdguid)
{
  while (sc->first)
  {
    struct ddsi_rsample_chain_elem *e = sc->first;
    sc->first = e->next;
    if (e->sampleinfo != NULL)
    {
      /* Must not try to deliver a gap -- possibly a FIXME for
         sample_lost events. Also note that the synchronous path is
         _never_ used for historical data, and therefore never has the
         GUID of a reader to deliver to */
      deliver_user_data (e->sampleinfo, e->fragchain, rdguid, 1);
    }
    ddsi_fragchain_unref (e->fragchain);
  }
}

static void clean_defrag (struct ddsi_proxy_writer *pwr)
{
  ddsi_seqno_t seq = ddsi_reorder_next_seq (pwr->reorder);
  if (pwr->n_readers_out_of_sync > 0)
  {
    struct ddsi_pwr_rd_match *wn;
    for (wn = ddsrt_avl_find_min (&ddsi_pwr_readers_treedef, &pwr->readers); wn != NULL; wn = ddsrt_avl_find_succ (&ddsi_pwr_readers_treedef, &pwr->readers, wn))
    {
      if (wn->in_sync == PRMSS_OUT_OF_SYNC)
      {
        ddsi_seqno_t seq1 = ddsi_reorder_next_seq (wn->u.not_in_sync.reorder);
        if (seq1 < seq)
          seq = seq1;
      }
    }
  }
  ddsi_defrag_notegap (pwr->defrag, 1, seq);
}

/**
 * 
 * 
获取目标 GUID 和代理写入器信息：

dst 保存了数据的目标 GUID 信息。
pwr 是代理写入器信息，其中包含了关于写入器的各种状态信息。
更新租约信息：

通过 ddsi_lease_renew 函数更新代理写入器相关的租约信息。
检查代理写入器的活跃状态：

如果代理写入器之前处于非活跃状态，通过 ddsi_proxy_writer_set_alive_may_unlock 函数设置为活跃状态。
检查可靠读取器的存在：

如果存在可靠读取器且尚未收到心跳消息，则中断处理，等待心跳消息。
检查读取器的存在：

如果没有读取器或者正在进行本地匹配，中断处理。
跟踪最高的序列号和片段号：

更新代理写入器的 last_seq 和 last_fragnum，以跟踪最高的序列号和片段号。
清理碎片数据：

调用 clean_defrag 函数清理碎片数据。
创建 ddsi_rsample 结构：

通过 ddsi_defrag_rsample 函数创建一个 ddsi_rsample 结构表示接收到的数据。
处理过滤的读取器：

如果存在过滤的读取器，尝试将数据发送给这些读取器。
处理正常的数据传输：

调用 ddsi_reorder_rsample 函数处理正常的数据传输，获取 ddsi_rsample_chain 结构。
如果成功，根据处理方式选择同步或异步传输，然后将数据加入到消息队列中。
处理读取器的同步状态：

对于处于同步状态但不在同步的读取器，重新处理接收到的数据。
解锁代理写入器：

解锁代理写入器，释放锁资源。
等待消息队列为空：

等待消息队列为空，以确保数据正确传输。
*/
static void handle_regular (struct ddsi_receiver_state *rst, ddsrt_etime_t tnow, struct ddsi_rmsg *rmsg, const ddsi_rtps_data_datafrag_common_t *msg, const struct ddsi_rsample_info *sampleinfo,
    uint32_t max_fragnum_in_msg, struct ddsi_rdata *rdata, struct ddsi_dqueue **deferred_wakeup, bool renew_manbypp_lease)
{
  struct ddsi_proxy_writer *pwr;
  struct ddsi_rsample *rsample;
  ddsi_guid_t dst;
  struct ddsi_lease *lease;

  dst.prefix = rst->dst_guid_prefix;
  dst.entityid = msg->readerId;

  pwr = sampleinfo->pwr;
  if (pwr == NULL)
  {
    ddsi_guid_t src;
    src.prefix = rst->src_guid_prefix;
    src.entityid = msg->writerId;
    RSTTRACE (" "PGUIDFMT"? -> "PGUIDFMT, PGUID (src), PGUID (dst));
    return;
  }

  /* Proxy participant's "automatic" lease has to be renewed always, manual-by-participant one only
     for data published by the application.  If pwr->lease exists, it is in some manual lease mode,
     so check whether it is actually in manual-by-topic mode before renewing it.  As pwr->lease is
     set once (during entity creation) we can read it outside the lock, keeping all the lease
     renewals together. */
  if ((lease = ddsrt_atomic_ldvoidp (&pwr->c.proxypp->minl_auto)) != NULL)
    ddsi_lease_renew (lease, tnow);
  if ((lease = ddsrt_atomic_ldvoidp (&pwr->c.proxypp->minl_man)) != NULL && renew_manbypp_lease)
    ddsi_lease_renew (lease, tnow);
  if (pwr->lease && pwr->c.xqos->liveliness.kind == DDS_LIVELINESS_MANUAL_BY_TOPIC)
    ddsi_lease_renew (pwr->lease, tnow);

  /* Shouldn't lock the full writer, but will do so for now */
  ddsrt_mutex_lock (&pwr->e.lock);

  /* A change in transition from not-alive to alive is relatively complicated
     and may involve temporarily unlocking the proxy writer during the process
     (to avoid unnecessarily holding pwr->e.lock while invoking listeners on
     the reader) */
  if (!pwr->alive)
    ddsi_proxy_writer_set_alive_may_unlock (pwr, true);

  /* Don't accept data when reliable readers exist and we haven't yet seen
     a heartbeat telling us what the "current" sequence number of the writer
     is. If no reliable readers are present, we can't request a heartbeat and
     therefore must not require one.

     This should be fine except for the one case where one transitions from
     having only best-effort readers to also having a reliable reader (in
     the same process): in that case, the requirement that a heartbeat has
     been seen could potentially result in a disruption of the data flow to
     the best-effort readers.  That state should last only for a very short
     time, but it is rather inelegant.  */
  if (!pwr->have_seen_heartbeat && pwr->n_reliable_readers > 0 && ddsi_vendor_is_eclipse (rst->vendor))
  {
    ddsrt_mutex_unlock (&pwr->e.lock);
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT": no heartbeat seen yet", PGUID (pwr->e.guid), PGUID (dst));
    return;
  }

  if (ddsrt_avl_is_empty (&pwr->readers) || pwr->local_matching_inprogress)
  {
    ddsrt_mutex_unlock (&pwr->e.lock);
    RSTTRACE (" "PGUIDFMT" -> "PGUIDFMT": no readers", PGUID (pwr->e.guid), PGUID (dst));
    return;
  }

  /* Track highest sequence number we know of -- we track both
     sequence number & fragment number so that the NACK generation can
     do the Right Thing. */
     /**
      * 
      * 
      * 检查读者是否存在：

      如果代理写入器（pwr）的读者列表为空或者本地匹配正在进行中，就会释放代理写入器的锁，输出相应的调试日志，然后函数返回。这是因为如果没有读者，就没有必要继续处理数据。
      跟踪最高的序列号和分片号：

      如果有读者存在，就会继续执行后续操作。
      检查传入的数据的序列号（sampleinfo->seq）是否大于代理写入器已知的最高序列号（pwr->last_seq）。
      如果是，更新代理写入器的最高序列号和最高分片号。
      如果序列号相等，检查传入的数据的最大分片号（max_fragnum_in_msg）是否大于代理写入器已知的最高分片号（pwr->last_fragnum）。
      如果是，更新代理写入器的最高分片号。
      清理碎片缓存：

      调用 clean_defrag 函数，该函数用于清理代理写入器的碎片缓存。这可能涉及将不再需要的碎片从缓存中移除，以释放资源或确保缓存不会无限增长。
     */
  if (sampleinfo->seq > pwr->last_seq)
  {
    pwr->last_seq = sampleinfo->seq;
    pwr->last_fragnum = max_fragnum_in_msg;
  }
  else if (sampleinfo->seq == pwr->last_seq && max_fragnum_in_msg > pwr->last_fragnum)
  {
    pwr->last_fragnum = max_fragnum_in_msg;
  }

  clean_defrag (pwr);

  /**
   * 
      在分布式系统中，数据的传输可能经历多个网络节点，由于网络的不确定性，数据包的到达顺序可能与其发送顺序不一致。此外，数据可能被分割成多个片段进行传输，这使得在接收端需要对这些片段进行重组。因此，为了确保接收端得到正确有序的完整数据，就需要对接收到的数据进行重新组装和排序。

      具体原因包括：

      网络不确定性： 数据包在网络中的传输可能会受到各种因素的影响，例如网络拥塞、延迟、丢包等。这可能导致数据包以不同的顺序到达接收端。

      分割和重组： 数据为了在网络上传输可能会被分割成多个片段，这些片段需要在接收端进行重组，以还原原始数据。

      保证有序性： 在分布式系统中，有时数据的有序性对于正确的应用行为非常重要。例如，对于实时应用或者需要按时间戳顺序处理的数据，确保数据的有序性是必要的。

      处理不同速率的生产者和消费者： 在发布-订阅系统中，生产者和消费者可能以不同的速率工作。为了适应这种差异，数据可能会在代理层进行排序，以确保按正确的顺序传递给消费者。

      在上述代码中，ddsi_defrag_rsample 和 ddsi_reorder_rsample 就是用来处理这些情况的函数。前者负责重组数据，后者负责对数据进行排序。通过这些操作，可以在分布式环境中保证正确的数据传输和有序性。
   * 


      调用 ddsi_defrag_rsample 函数：

      该函数用于将接收到的数据碎片重新组装成完整的数据样本（rsample）。
      如果成功组装，会继续执行后续操作。
      检查是否需要过滤：

      如果代理写入器开启了数据过滤（pwr->filtered为真）且目标 GUID（dst）非空，则遍历代理写入器的读者列表，查找与目标 GUID 匹配的读者。
      如果找到匹配的读者，检查该读者是否开启了过滤（wn->filtered为真）。
      如果需要过滤，调用 ddsi_reorder_rsample 函数对数据进行重排序，并根据情况将数据加入发送队列或同步地交付给读者。
      处理未被过滤的数据：

      如果数据不需要被过滤，再次调用 ddsi_reorder_rsample 函数进行重排序。
      如果重排序成功，根据代理写入器的配置和状态进行不同的处理：
      如果代理写入器没有可靠的读者（pwr->n_reliable_readers == 0），但是重排序缓冲接受了样本，说明这是一个具有非可靠读者的可靠代理写入器。
      插入一个 Gap（[1, sampleinfo->seq)）以强制传递此样本，并确保不会将 Gap 添加到重排序管理中。
      否则，如果数据样本满足条件，将其加入发送队列或同步地交付给读者。
      处理与代理写入器不同步的读者：

      如果代理写入器有读者不同步（pwr->n_readers_out_of_sync > 0），遍历读者列表：
      对于处于不同步状态的读者，使用 ddsi_reorder_rsample 函数对数据进行重排序。
      根据情况将数据加入发送队列或同步地交付给读者。
      如果数据被标记为太旧或被拒绝，则执行相应的处理。
  */
  if ((rsample = ddsi_defrag_rsample (pwr->defrag, rdata, sampleinfo)) != NULL)
  {
    int refc_adjust = 0;
    struct ddsi_rsample_chain sc;
    struct ddsi_rdata *fragchain = ddsi_rsample_fragchain (rsample);
    ddsi_reorder_result_t rres, rres2;
    struct ddsi_pwr_rd_match *wn;
    int filtered = 0;

    /**
背景：
      pwr 代表数据写者（writer）的信息结构。
      这段代码处理写者接收到的数据样本（rsample）。
      处理逻辑：

      if (pwr->filtered && !ddsi_is_null_guid(&dst))：这个条件判断是否开启了过滤，并且目标数据读者的 GUID 不为空。
      for (wn = ddsrt_avl_find_min(&ddsi_pwr_readers_treedef, &pwr->readers); wn != NULL; wn = ddsrt_avl_find_succ(&ddsi_pwr_readers_treedef, &pwr->readers, wn))：遍历写者的已知数据读者。
      if (ddsi_guid_eq(&wn->rd_guid, &dst))：找到目标数据读者。
      if (wn->filtered)：目标数据读者开启了过滤。
      rres2 = ddsi_reorder_rsample(&sc, wn->u.not_in_sync.reorder, rsample, &refc_adjust, ddsi_dqueue_is_full(pwr->dqueue));：对接收到的数据样本进行重新排序，如果需要。
      if (sampleinfo->seq > wn->last_seq)：检查数据序列号是否大于上次接收到的序列号。
      wn->last_seq = sampleinfo->seq;：更新数据读者的最后接收到的序列号。
      数据满足条件时：
      if (rres2 > 0)：检查重新排序是否成功。
      if (!pwr->deliver_synchronously)：如果写者不是同步交付模式。
      ddsi_dqueue_enqueue1(pwr->dqueue, &wn->rd_guid, &sc, rres2);：将数据加入写者的待处理队列。
      else：如果是同步交付模式。
      deliver_user_data_synchronously(&sc, &wn->rd_guid);：同步地将用户数据交付给数据读者。
      filtered = 1;：标记已经进行了过滤。
      这段代码的核心是在写者收到数据后，检查目标数据读者是否开启了过滤，如果是，则根据序列号和重新排序的情况进行处理。
    */

   /*
   
    在DDS（Data Distribution Service）中，数据过滤是指根据一些条件或规则，选择性地传输或接收数据。这些条件可以基于数据的内容、属性或其他元数据。过滤通常由数据写入者（Publisher）或数据读取者（Subscriber）指定。

    在你提到的上下文中，如果数据不需要被过滤，即所有产生的数据都应该被传输，就会调用 ddsi_reorder_rsample 函数进行重排序。数据的重排序可能涉及到根据序列号（sequence number）或其他标识对数据进行重新排序，以确保按照产生的顺序传输给接收方。

    如果数据需要被过滤，可能会按照一定的规则，比如只传输满足某些条件的数据，或者只接收满足某些条件的数据。过滤可以帮助系统更有效地使用网络带宽，只传输和接收那些对应用程序有意义的数据。

    所以，在这个上下文中，数据过滤就是决定哪些数据应该被传输或接收，而不是对所有的数据都执行传输或接收操作。
   */
    if (pwr->filtered && !ddsi_is_null_guid(&dst))
    {
      for (wn = ddsrt_avl_find_min (&ddsi_pwr_readers_treedef, &pwr->readers); wn != NULL; wn = ddsrt_avl_find_succ (&ddsi_pwr_readers_treedef, &pwr->readers, wn))
      {
        if (ddsi_guid_eq(&wn->rd_guid, &dst))
        {
          if (wn->filtered)
          {
            rres2 = ddsi_reorder_rsample (&sc, wn->u.not_in_sync.reorder, rsample, &refc_adjust, ddsi_dqueue_is_full (pwr->dqueue));
            if (sampleinfo->seq > wn->last_seq)
            {
              wn->last_seq = sampleinfo->seq;
            }
            if (rres2 > 0)
            {
              if (!pwr->deliver_synchronously)
                ddsi_dqueue_enqueue1 (pwr->dqueue, &wn->rd_guid, &sc, rres2);
              else
                deliver_user_data_synchronously (&sc, &wn->rd_guid);
            }
            filtered = 1;
          }
          break;
        }
      }
    }

    if (!filtered)
    {
      rres = ddsi_reorder_rsample (&sc, pwr->reorder, rsample, &refc_adjust, 0); // ddsi_dqueue_is_full (pwr->dqueue));

      /*
      rres = ddsi_reorder_rsample(&sc, pwr->reorder, rsample, &refc_adjust, 0);：这行代码尝试将接收到的数据按照序列号重新排序，以确保按正确的顺序传递给相应的消费者。rres 会包含一个值，指示重新排序的结果。

      if (rres == DDSI_REORDER_ACCEPT && pwr->n_reliable_readers == 0)：如果重新排序被接受，并且写者（数据生产者）没有可靠的读者，就会插入一个 Gap（缺失的数据序列号范围），以便确保只有不可靠的读者存在。这是为了确保即使没有可靠的读者，也能够正确传递数据。
      （即使没有可靠的读者，也要确保数据序列号的连续性。在 DDS 中，序列号的连续性对于数据的正确传递很重要。
        这个 Gap 的插入可以避免数据序列号的间隙，即便没有可靠的读者，也能够保持数据传递的有序性。）
      if (rres > 0)：如果重新排序或插入 Gap 操作成功，表示数据准备好被传递。根据写者的配置，可能有两种方式：

      pwr->deliver_synchronously 为真时，表示同步传递，数据会直接从接收线程传递给消费者。
      否则，采用异步传递，数据将会被放入传递队列 pwr->dqueue 中等待后续处理。
      这段代码的目标是确保接收到的数据被按照正确的顺序传递给相应的消费者，并根据写者和读者的配置进行适当的处理。
      */
      if (rres == DDSI_REORDER_ACCEPT && pwr->n_reliable_readers == 0)
      {
        /* If no reliable readers but the reorder buffer accepted the
           sample, it must be a reliable proxy writer with only
           unreliable readers.  "Inserting" a Gap [1, sampleinfo->seq)
           will force delivery of this sample, and not cause the gap to
           be added to the reorder admin. */
        int gap_refc_adjust = 0;
        rres = ddsi_reorder_gap (&sc, pwr->reorder, rdata, 1, sampleinfo->seq, &gap_refc_adjust);
        assert (rres > 0);
        assert (gap_refc_adjust == 0);
      }

      if (rres > 0)
      {
        /* Enqueue or deliver with pwr->e.lock held: to ensure no other
           receive thread's data gets interleaved -- arguably delivery
           needn't be exactly in-order, which would allow us to do this
           without pwr->e.lock held.
           Note that PMD is also handled here, but the pwr for PMD does not
           use no synchronous delivery, so deliver_user_data_synchronously
           (which asserts pwr is not built-in) is not used for PMD handling. */
        if (pwr->deliver_synchronously)
        {
          /* FIXME: just in case the synchronous delivery runs into a delay caused
             by the current mishandling of resource limits */
        //如果存在延迟唤醒的队列（*deferred_wakeup 不为空），则将触发延迟唤醒。
        //              延迟唤醒（Deferred Wakeup）通常是一种性能优化策略，旨在减少系统中不必要的唤醒操作，特别是在多线程环境中。唤醒操作涉及将线程从等待状态转变为可执行状态，这在涉及多线程同步的系统中可能会导致性能开销。

        // 在上下文中，延迟唤醒可能是为了合并多个唤醒事件，从而减少线程唤醒的频率，提高系统效率。在异步传递数据的情况下，将数据添加到队列而不立即唤醒等待的线程可以在某些情况下提供更好的性能。一些原因包括：

        // 减少上下文切换次数： 每次唤醒一个线程都可能导致上下文切换，而上下文切换是有一定开销的。通过延迟唤醒，系统可以尝试合并多个唤醒事件，从而减少上下文切换的次数。

        // 提高线程局部性： 当线程被唤醒时，它可能需要处理队列中的多个任务。通过延迟唤醒，可以更有效地利用线程的本地性，即在同一时间段内处理多个相关的任务。

        // 减少资源争用： 如果多个线程竞争相同的资源，频繁的唤醒可能导致不必要的争用。通过延迟唤醒，可以减少这种资源争用。
          if (*deferred_wakeup)
            ddsi_dqueue_enqueue_trigger (*deferred_wakeup);
          deliver_user_data_synchronously (&sc, NULL);
        }
        else
        {
          if (ddsi_dqueue_enqueue_deferred_wakeup (pwr->dqueue, &sc, rres))
          {
            if (*deferred_wakeup && *deferred_wakeup != pwr->dqueue)
              ddsi_dqueue_enqueue_trigger (*deferred_wakeup);
            *deferred_wakeup = pwr->dqueue;
          }
        }
      }


      /**
       * 
       * 
       * 
      pwr->n_readers_out_of_sync > 0 表达式检查的是代理写者（proxy writer）的属性 n_readers_out_of_sync 是否大于零。
      这个属性是一个计数器，表示与该代理写者相关的读者中，有多少个读者是处于不同步状态的。
      在这个上下文中，“不同步”通常指的是这些读者还没有收到或者处理完所有历史数据，或者处于某种特殊的等待状态。

      因此，当 pwr->n_readers_out_of_sync > 0 为真时，表示代理写者当前有一些相关的读者处于不同步状态。这可能会影响代理写者的行为，例如需要特殊处理这些读者的数据传输，以确保它们能够适应当前的同步状态。


      在数据通信的上下文中，“不同步”通常指的是数据生产者和数据消费者之间的状态不一致或者不同步。具体来说，对于实时数据通信系统，这可能涉及到以下几个方面：

      历史数据同步： 数据生产者可能有一些历史数据，而数据消费者可能尚未收到或者处理这些历史数据。在某些情况下，系统需要确保消费者能够追溯并处理历史数据。

      实时数据同步： 即使历史数据同步完成，仍然需要确保实时产生的数据在所有相关的消费者之间同步。如果某个消费者的处理速度较慢，可能会导致不同步状态。

      等待特定条件： 有时，消费者可能会在等待满足特定条件的数据。在等待期间，它可能被认为是不同步的，因为它尚未开始或者不能处理数据。

      在你的上下文中，pwr->n_readers_out_of_sync 表示有多少个相关的读者（数据消费者）处于不同步状态。这可能需要特殊处理，以确保这些读者能够适应当前的同步状态。可能涉及的操作包括等待这些读者完成历史数据的处理或者以某种方式处理它们的特殊状态。
      */
     //TODO_ZT
      if (pwr->n_readers_out_of_sync > 0)
      {
        /* Those readers catching up with TL but in sync with the proxy
           writer may have become in sync with the proxy writer and the
           writer; those catching up with TL all by themselves go through
           the "TOO_OLD" path below. */
        ddsrt_avl_iter_t it;
        struct ddsi_rsample *rsample_dup = NULL;
        int reuse_rsample_dup = 0;
        for (wn = ddsrt_avl_iter_first (&ddsi_pwr_readers_treedef, &pwr->readers, &it); wn != NULL; wn = ddsrt_avl_iter_next (&it))
        {
          if (wn->in_sync == PRMSS_SYNC)
            continue;
          /* only need to get a copy of the first sample, because that's the one
             that triggered delivery */
          if (!reuse_rsample_dup)
            rsample_dup = ddsi_reorder_rsample_dup_first (rmsg, rsample);
          rres2 = ddsi_reorder_rsample (&sc, wn->u.not_in_sync.reorder, rsample_dup, &refc_adjust, ddsi_dqueue_is_full (pwr->dqueue));
          switch (rres2)
          {
            case DDSI_REORDER_TOO_OLD:
            case DDSI_REORDER_REJECT:
              reuse_rsample_dup = 1;
              break;
            case DDSI_REORDER_ACCEPT:
              reuse_rsample_dup = 0;
              break;
            default:
              assert (rres2 > 0);
              /* note: can't deliver to a reader, only to a group */
              maybe_set_reader_in_sync (pwr, wn, sampleinfo->seq);
              reuse_rsample_dup = 0;
              /* No need to deliver old data to out-of-sync readers
                 synchronously -- ordering guarantees don't change
                 as fresh data will be delivered anyway and hence
                 the old data will never be guaranteed to arrive
                 in-order, and those few microseconds can't hurt in
                 catching up on transient-local data.  See also
                 DDSI_REORDER_DELIVER case in outer switch. */
              if (pwr->deliver_synchronously)
              {
                /* FIXME: just in case the synchronous delivery runs into a delay caused
                   by the current mishandling of resource limits */
                deliver_user_data_synchronously (&sc, &wn->rd_guid);
              }
              else
              {
                if (*deferred_wakeup && *deferred_wakeup != pwr->dqueue)
                {
                  ddsi_dqueue_enqueue_trigger (*deferred_wakeup);
                  *deferred_wakeup = NULL;
                }
                ddsi_dqueue_enqueue1 (pwr->dqueue, &wn->rd_guid, &sc, rres2);
              }
              break;
          }
        }
      }
    }

    ddsi_fragchain_adjust_refcount (fragchain, refc_adjust);
  }
  ddsrt_mutex_unlock (&pwr->e.lock);
  ddsi_dqueue_wait_until_empty_if_full (pwr->dqueue);
}

static int handle_SPDP (const struct ddsi_rsample_info *sampleinfo, struct ddsi_rdata *rdata)
{
  struct ddsi_domaingv * const gv = sampleinfo->rst->gv;
  struct ddsi_rsample *rsample;
  struct ddsi_rsample_chain sc;
  struct ddsi_rdata *fragchain;
  ddsi_reorder_result_t rres;
  int refc_adjust = 0;
  ddsrt_mutex_lock (&gv->spdp_lock);
  rsample = ddsi_defrag_rsample (gv->spdp_defrag, rdata, sampleinfo);
  fragchain = ddsi_rsample_fragchain (rsample);
  if ((rres = ddsi_reorder_rsample (&sc, gv->spdp_reorder, rsample, &refc_adjust, ddsi_dqueue_is_full (gv->builtins_dqueue))) > 0)
    ddsi_dqueue_enqueue (gv->builtins_dqueue, &sc, rres);
  ddsi_fragchain_adjust_refcount (fragchain, refc_adjust);
  ddsrt_mutex_unlock (&gv->spdp_lock);
  return 0;
}

static void drop_oversize (struct ddsi_receiver_state *rst, struct ddsi_rmsg *rmsg, const ddsi_rtps_data_datafrag_common_t *msg, struct ddsi_rsample_info *sampleinfo)
{
  struct ddsi_proxy_writer *pwr = sampleinfo->pwr;
  if (pwr == NULL)
  {
    /* No proxy writer means nothing really gets done with, unless it
       is SPDP.  SPDP is periodic, so oversize discovery packets would
       cause periodic warnings. */
    if ((msg->writerId.u == DDSI_ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER) ||
        (msg->writerId.u == DDSI_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER))
    {
      DDS_CWARNING (&rst->gv->logconfig, "dropping oversize (%"PRIu32" > %"PRIu32") SPDP sample %"PRIu64" from remote writer "PGUIDFMT"\n",
                    sampleinfo->size, rst->gv->config.max_sample_size, sampleinfo->seq,
                    PGUIDPREFIX (rst->src_guid_prefix), msg->writerId.u);
    }
  }
  else
  {
    /* Normal case: we actually do know the writer.  Dropping it is as
       easy as pushing a gap through the pipe, but trying to log the
       event only once is trickier.  Checking whether the gap had some
       effect seems a reasonable approach. */
    int refc_adjust = 0;
    struct ddsi_rdata *gap = ddsi_rdata_newgap (rmsg);
    ddsi_guid_t dst;
    struct ddsi_pwr_rd_match *wn;
    int gap_was_valuable;

    dst.prefix = rst->dst_guid_prefix;
    dst.entityid = msg->readerId;

    ddsrt_mutex_lock (&pwr->e.lock);
    wn = ddsrt_avl_lookup (&ddsi_pwr_readers_treedef, &pwr->readers, &dst);
    gap_was_valuable = handle_one_gap (pwr, wn, sampleinfo->seq, sampleinfo->seq+1, gap, &refc_adjust);
    ddsi_fragchain_adjust_refcount (gap, refc_adjust);
    ddsrt_mutex_unlock (&pwr->e.lock);

    if (gap_was_valuable)
    {
      const char *tname = (pwr->c.xqos->present & DDSI_QP_TOPIC_NAME) ? pwr->c.xqos->topic_name : "(null)";
      const char *ttname = (pwr->c.xqos->present & DDSI_QP_TYPE_NAME) ? pwr->c.xqos->type_name : "(null)";
      DDS_CWARNING (&rst->gv->logconfig, "dropping oversize (%"PRIu32" > %"PRIu32") sample %"PRIu64" from remote writer "PGUIDFMT" %s/%s\n",
                    sampleinfo->size, rst->gv->config.max_sample_size, sampleinfo->seq,
                    PGUIDPREFIX (rst->src_guid_prefix), msg->writerId.u,
                    tname, ttname);
    }
  }
}

/*
RSTTRACE ("DATA("PGUIDFMT" -> "PGUIDFMT" #%"PRIu64, ...)：在日志中记录处理的数据信息，包括源 GUID、目标 GUID 以及数据的序列号。

if (!rst->forme)：如果数据不是为当前实例（receiver state）而接收的，则返回 1 表示处理完成，不执行后续步骤。

if (sampleinfo->pwr)：如果存在代理写入器信息，使用安全性验证函数 ddsi_security_validate_msg_decoding 进行消息解码验证。如果验证失败，记录日志并返回 1。

if (sampleinfo->size > rst->gv->config.max_sample_size)：如果数据样本大小超过配置的最大样本大小，调用 drop_oversize 处理超大的数据。

else：处理正常大小的数据。

    a. 计算数据偏移量，即数据在消息中的位置。

    b. 如果存在 datap（数据指针），计算数据有效负载的偏移量；否则，使用整个数据子消息的大小计算。

    c. 如果存在 keyhash，计算关键哈希的偏移量；否则，偏移量为 0。

rdata = ddsi_rdata_new (rmsg, 0, sampleinfo->size, submsg_offset, payload_offset, keyhash_offset);：创建 ddsi_rdata 结构表示数据，并传递相应的偏移量和大小信息。

根据写入器 ID 的值执行不同的处理逻辑：

a. 对于 SPDP 内置写入器或 P2P 内置写入器，执行特殊处理，例如 handle_SPDP。

b. 对于其他写入器，执行一般的数据处理逻辑，包括更新租约信息等。

RSTTRACE (")");：在日志中记录处理完成。

返回 1 表示处理完成。

这个函数主要负责接收到的数据的处理，包括验证、大小检查、关键哈希计算等，并根据写入器 ID 执行相应的处理逻辑。

*/
static int handle_Data (struct ddsi_receiver_state *rst, ddsrt_etime_t tnow, struct ddsi_rmsg *rmsg, const ddsi_rtps_data_t *msg, size_t size, struct ddsi_rsample_info *sampleinfo, const ddsi_keyhash_t *keyhash, unsigned char *datap, struct ddsi_dqueue **deferred_wakeup, ddsi_rtps_submessage_kind_t prev_smid)
{
  RSTTRACE ("DATA("PGUIDFMT" -> "PGUIDFMT" #%"PRIu64,
            PGUIDPREFIX (rst->src_guid_prefix), msg->x.writerId.u,
            PGUIDPREFIX (rst->dst_guid_prefix), msg->x.readerId.u,
            ddsi_from_seqno (msg->x.writerSN));
  if (!rst->forme)
  {
    RSTTRACE (" not-for-me)");
    return 1;
  }

  if (sampleinfo->pwr)
  {
    if (!ddsi_security_validate_msg_decoding(&(sampleinfo->pwr->e), &(sampleinfo->pwr->c), sampleinfo->pwr->c.proxypp, rst, prev_smid))
    {
      RSTTRACE (" clear submsg from protected src "PGUIDFMT")", PGUID (sampleinfo->pwr->e.guid));
      return 1;
    }
  }

  if (sampleinfo->size > rst->gv->config.max_sample_size)
    drop_oversize (rst, rmsg, &msg->x, sampleinfo);
  else
  {
    struct ddsi_rdata *rdata;
    unsigned submsg_offset, payload_offset, keyhash_offset;
    submsg_offset = (unsigned) ((unsigned char *) msg - DDSI_RMSG_PAYLOAD (rmsg));
    if (datap)
      payload_offset = (unsigned) ((unsigned char *) datap - DDSI_RMSG_PAYLOAD (rmsg));
    else
      payload_offset = submsg_offset + (unsigned) size;
    if (keyhash)
      keyhash_offset = (unsigned) (keyhash->value - DDSI_RMSG_PAYLOAD (rmsg));
    else
      keyhash_offset = 0;

    rdata = ddsi_rdata_new (rmsg, 0, sampleinfo->size, submsg_offset, payload_offset, keyhash_offset);

    if ((msg->x.writerId.u & DDSI_ENTITYID_SOURCE_MASK) == DDSI_ENTITYID_SOURCE_BUILTIN)
    {
      bool renew_manbypp_lease = true;
      switch (msg->x.writerId.u)
      {
        case DDSI_ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER:
        /* fall through */
        case DDSI_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER:
          /* SPDP needs special treatment: there are no proxy writers for it and we accept data from unknown sources */
          handle_SPDP (sampleinfo, rdata);
          break;
        case DDSI_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER:
        /* fall through */
        case DDSI_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER:
          /* Handle PMD as a regular message, but without renewing the leases on proxypp */
          renew_manbypp_lease = false;
        /* fall through */
        default:
          handle_regular (rst, tnow, rmsg, &msg->x, sampleinfo, UINT32_MAX, rdata, deferred_wakeup, renew_manbypp_lease);
      }
    }
    else
    {
      handle_regular (rst, tnow, rmsg, &msg->x, sampleinfo, UINT32_MAX, rdata, deferred_wakeup, true);
    }
  }
  RSTTRACE (")");
  return 1;
}

static int handle_DataFrag (struct ddsi_receiver_state *rst, ddsrt_etime_t tnow, struct ddsi_rmsg *rmsg, const ddsi_rtps_datafrag_t *msg, size_t size, struct ddsi_rsample_info *sampleinfo, const ddsi_keyhash_t *keyhash, unsigned char *datap, struct ddsi_dqueue **deferred_wakeup, ddsi_rtps_submessage_kind_t prev_smid)
{
  RSTTRACE ("DATAFRAG("PGUIDFMT" -> "PGUIDFMT" #%"PRIu64"/[%"PRIu32"..%"PRIu32"]",
            PGUIDPREFIX (rst->src_guid_prefix), msg->x.writerId.u,
            PGUIDPREFIX (rst->dst_guid_prefix), msg->x.readerId.u,
            ddsi_from_seqno (msg->x.writerSN),
            msg->fragmentStartingNum, (ddsi_fragment_number_t) (msg->fragmentStartingNum + msg->fragmentsInSubmessage - 1));
  if (!rst->forme)
  {
    RSTTRACE (" not-for-me)");
    return 1;
  }

  if (sampleinfo->pwr)
  {
    if (!ddsi_security_validate_msg_decoding(&(sampleinfo->pwr->e), &(sampleinfo->pwr->c), sampleinfo->pwr->c.proxypp, rst, prev_smid))
    {
      RSTTRACE (" clear submsg from protected src "PGUIDFMT")", PGUID (sampleinfo->pwr->e.guid));
      return 1;
    }
  }

  if (sampleinfo->size > rst->gv->config.max_sample_size)
    drop_oversize (rst, rmsg, &msg->x, sampleinfo);
  else
  {
    struct ddsi_rdata *rdata;
    unsigned submsg_offset, payload_offset, keyhash_offset;
    uint32_t begin, endp1;
    bool renew_manbypp_lease = true;
    if ((msg->x.writerId.u & DDSI_ENTITYID_SOURCE_MASK) == DDSI_ENTITYID_SOURCE_BUILTIN)
    {
      switch (msg->x.writerId.u)
      {
        case DDSI_ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER:
        /* fall through */
        case DDSI_ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER:
          DDS_CWARNING (&rst->gv->logconfig, "DATAFRAG("PGUIDFMT" #%"PRIu64" -> "PGUIDFMT") - fragmented builtin data not yet supported\n",
                        PGUIDPREFIX (rst->src_guid_prefix), msg->x.writerId.u, ddsi_from_seqno (msg->x.writerSN),
                        PGUIDPREFIX (rst->dst_guid_prefix), msg->x.readerId.u);
          return 1;
        case DDSI_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER:
        /* fall through */
        case DDSI_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER:
          renew_manbypp_lease = false;
      }
    }

    submsg_offset = (unsigned) ((unsigned char *) msg - DDSI_RMSG_PAYLOAD (rmsg));
    if (datap)
      payload_offset = (unsigned) ((unsigned char *) datap - DDSI_RMSG_PAYLOAD (rmsg));
    else
      payload_offset = submsg_offset + (unsigned) size;
    if (keyhash)
      keyhash_offset = (unsigned) (keyhash->value - DDSI_RMSG_PAYLOAD (rmsg));
    else
      keyhash_offset = 0;

    begin = (msg->fragmentStartingNum - 1) * msg->fragmentSize;
    if ((uint32_t) msg->fragmentSize * msg->fragmentsInSubmessage > (uint32_t) ((unsigned char *) msg + size - datap)) {
      /* this happens for the last fragment (which usually is short) --
         and is included here merely as a sanity check, because that
         would mean the computed endp1'd be larger than the sample
         size */
      endp1 = begin + (uint32_t) ((unsigned char *) msg + size - datap);
    } else {
      /* most of the time we get here, but this differs from the
         preceding only when the fragment size is not a multiple of 4
         whereas all the length of CDR data always is (and even then,
         you'd be fine as the defragmenter can deal with partially
         overlapping fragments ...) */
      endp1 = begin + (uint32_t) msg->fragmentSize * msg->fragmentsInSubmessage;
    }
    if (endp1 > msg->sampleSize)
    {
      /* the sample size need not be a multiple of 4 so we can still get
         here */
      endp1 = msg->sampleSize;
    }
    RSTTRACE ("/[%"PRIu32"..%"PRIu32") of %"PRIu32, begin, endp1, msg->sampleSize);

    rdata = ddsi_rdata_new (rmsg, begin, endp1, submsg_offset, payload_offset, keyhash_offset);

    /* Fragment numbers in DDSI2 internal representation are 0-based,
       whereas in DDSI they are 1-based.  The highest fragment number in
       the sample in internal representation is therefore START+CNT-2,
       rather than the expect START+CNT-1.  Nothing will go terribly
       wrong, it'll simply generate a request for retransmitting a
       non-existent fragment.  The other side SHOULD be capable of
       dealing with that. */
    handle_regular (rst, tnow, rmsg, &msg->x, sampleinfo, msg->fragmentStartingNum + msg->fragmentsInSubmessage - 2, rdata, deferred_wakeup, renew_manbypp_lease);
  }
  RSTTRACE (")");
  return 1;
}

struct submsg_name {
  char x[32];
};

static const char *submsg_name (ddsi_rtps_submessage_kind_t id, struct submsg_name *buffer)
{
  switch (id)
  {
    case DDSI_RTPS_SMID_PAD: return "PAD";
    case DDSI_RTPS_SMID_ACKNACK: return "ACKNACK";
    case DDSI_RTPS_SMID_HEARTBEAT: return "HEARTBEAT";
    case DDSI_RTPS_SMID_GAP: return "GAP";
    case DDSI_RTPS_SMID_INFO_TS: return "INFO_TS";
    case DDSI_RTPS_SMID_INFO_SRC: return "INFO_SRC";
    case DDSI_RTPS_SMID_INFO_REPLY_IP4: return "REPLY_IP4";
    case DDSI_RTPS_SMID_INFO_DST: return "INFO_DST";
    case DDSI_RTPS_SMID_INFO_REPLY: return "INFO_REPLY";
    case DDSI_RTPS_SMID_NACK_FRAG: return "NACK_FRAG";
    case DDSI_RTPS_SMID_HEARTBEAT_FRAG: return "HEARTBEAT_FRAG";
    case DDSI_RTPS_SMID_DATA_FRAG: return "DATA_FRAG";
    case DDSI_RTPS_SMID_DATA: return "DATA";
    case DDSI_RTPS_SMID_ADLINK_MSG_LEN: return "ADLINK_MSG_LEN";
    case DDSI_RTPS_SMID_ADLINK_ENTITY_ID: return "ADLINK_ENTITY_ID";
    case DDSI_RTPS_SMID_SEC_PREFIX: return "SEC_PREFIX";
    case DDSI_RTPS_SMID_SEC_BODY: return "SEC_BODY";
    case DDSI_RTPS_SMID_SEC_POSTFIX: return "SEC_POSTFIX";
    case DDSI_RTPS_SMID_SRTPS_PREFIX: return "SRTPS_PREFIX";
    case DDSI_RTPS_SMID_SRTPS_POSTFIX: return "SRTPS_POSTFIX";
  }
  (void) snprintf (buffer->x, sizeof (buffer->x), "UNKNOWN(%x)", (unsigned) id);
  return buffer->x;
}

static void malformed_packet_received (const struct ddsi_domaingv *gv, const unsigned char *msg, const unsigned char *submsg, size_t len, ddsi_vendorid_t vendorid)
{
  char tmp[1024];
  size_t i, pos, smsize;

  struct submsg_name submsg_name_buffer;
  ddsi_rtps_submessage_kind_t smkind;
  const char *state0;
  const char *state1;
  if (submsg == NULL || (submsg < msg || submsg >= msg + len)) {
    // outside buffer shouldn't happen, but this is for dealing with junk, so better be careful
    smkind = DDSI_RTPS_SMID_PAD;
    state0 = "";
    state1 = "header";
    submsg = msg;
  } else if ((size_t) (msg + len - submsg) < DDSI_RTPS_SUBMESSAGE_HEADER_SIZE) {
    smkind = DDSI_RTPS_SMID_PAD;
    state0 = "parse:";
    state1 = (submsg == msg) ? "init" : "shortmsg";
  } else {
    smkind = (ddsi_rtps_submessage_kind_t) *submsg;
    state0 = "parse:";
    state1 = submsg_name (smkind, &submsg_name_buffer);
  }
  assert (submsg >= msg && submsg <= msg + len);

  /* Show beginning of message and of submessage (as hex dumps) */
  pos = (size_t) snprintf (tmp, sizeof (tmp), "malformed packet received from vendor %u.%u state %s%s <", vendorid.id[0], vendorid.id[1], state0, state1);
  for (i = 0; i < 32 && i < len && msg + i < submsg && pos < sizeof (tmp); i++)
    pos += (size_t) snprintf (tmp + pos, sizeof (tmp) - pos, "%s%02x", (i > 0 && (i%4) == 0) ? " " : "", msg[i]);
  if (pos < sizeof (tmp))
    pos += (size_t) snprintf (tmp + pos, sizeof (tmp) - pos, " @0x%x ", (int) (submsg - msg));
  for (i = 0; i < 64 && i < len - (size_t) (submsg - msg) && pos < sizeof (tmp); i++)
    pos += (size_t) snprintf (tmp + pos, sizeof (tmp) - pos, "%s%02x", (i > 0 && (i%4) == 0) ? " " : "", submsg[i]);
  if (pos < sizeof (tmp))
    pos += (size_t) snprintf (tmp + pos, sizeof (tmp) - pos, "> (note: maybe partially bswap'd)");
  assert (pos < (int) sizeof (tmp));

  /* Partially decode header if we have enough bytes available */
  smsize = len - (size_t) (submsg - msg);
  if (smsize >= DDSI_RTPS_SUBMESSAGE_HEADER_SIZE && pos < sizeof (tmp)) {
    const ddsi_rtps_submessage_header_t *x = (const ddsi_rtps_submessage_header_t *) submsg;
    pos += (size_t) snprintf (tmp + pos, sizeof (tmp) - pos, " smid 0x%x flags 0x%x otnh %u", x->submessageId, x->flags, x->octetsToNextHeader);
  }
  if (pos < sizeof (tmp)) {
    switch (smkind) {
      case DDSI_RTPS_SMID_ACKNACK:
        if (smsize >= sizeof (ddsi_rtps_acknack_t)) {
          const ddsi_rtps_acknack_t *x = (const ddsi_rtps_acknack_t *) submsg;
          (void) snprintf (tmp + pos, sizeof (tmp) - pos, " rid 0x%"PRIx32" wid 0x%"PRIx32" base %"PRIu64" numbits %"PRIu32,
                           x->readerId.u, x->writerId.u, ddsi_from_seqno (x->readerSNState.bitmap_base),
                           x->readerSNState.numbits);
        }
        break;
      case DDSI_RTPS_SMID_HEARTBEAT:
        if (smsize >= sizeof (ddsi_rtps_heartbeat_t)) {
          const ddsi_rtps_heartbeat_t *x = (const ddsi_rtps_heartbeat_t *) submsg;
          (void) snprintf (tmp + pos, sizeof (tmp) - pos, " rid 0x%"PRIx32" wid 0x%"PRIx32" first %"PRIu64" last %"PRIu64,
                           x->readerId.u, x->writerId.u, ddsi_from_seqno (x->firstSN), ddsi_from_seqno (x->lastSN));
        }
        break;
      case DDSI_RTPS_SMID_GAP:
        if (smsize >= sizeof (ddsi_rtps_gap_t)) {
          const ddsi_rtps_gap_t *x = (const ddsi_rtps_gap_t *) submsg;
          (void) snprintf (tmp + pos, sizeof (tmp) - pos, " rid 0x%"PRIx32" wid 0x%"PRIx32" gapstart %"PRIu64" base %"PRIu64" numbits %"PRIu32,
                           x->readerId.u, x->writerId.u, ddsi_from_seqno (x->gapStart),
                           ddsi_from_seqno (x->gapList.bitmap_base), x->gapList.numbits);
        }
        break;
      case DDSI_RTPS_SMID_NACK_FRAG:
        if (smsize >= sizeof (ddsi_rtps_nackfrag_t)) {
          const ddsi_rtps_nackfrag_t *x = (const ddsi_rtps_nackfrag_t *) submsg;
          (void) snprintf (tmp + pos, sizeof (tmp) - pos, " rid 0x%"PRIx32" wid 0x%"PRIx32" seq# %"PRIu64" base %"PRIu32" numbits %"PRIu32,
                           x->readerId.u, x->writerId.u, ddsi_from_seqno (x->writerSN),
                           x->fragmentNumberState.bitmap_base, x->fragmentNumberState.numbits);
        }
        break;
      case DDSI_RTPS_SMID_HEARTBEAT_FRAG:
        if (smsize >= sizeof (ddsi_rtps_heartbeatfrag_t)) {
          const ddsi_rtps_heartbeatfrag_t *x = (const ddsi_rtps_heartbeatfrag_t *) submsg;
          (void) snprintf (tmp + pos, sizeof (tmp) - pos, " rid 0x%"PRIx32" wid 0x%"PRIx32" seq %"PRIu64" frag %"PRIu32,
                           x->readerId.u, x->writerId.u, ddsi_from_seqno (x->writerSN),
                           x->lastFragmentNum);
        }
        break;
      case DDSI_RTPS_SMID_DATA:
        if (smsize >= sizeof (ddsi_rtps_data_t)) {
          const ddsi_rtps_data_t *x = (const ddsi_rtps_data_t *) submsg;
          (void) snprintf (tmp + pos, sizeof (tmp) - pos, " xflags %x otiq %u rid 0x%"PRIx32" wid 0x%"PRIx32" seq %"PRIu64,
                           x->x.extraFlags, x->x.octetsToInlineQos,
                           x->x.readerId.u, x->x.writerId.u, ddsi_from_seqno (x->x.writerSN));
        }
        break;
      case DDSI_RTPS_SMID_DATA_FRAG:
        if (smsize >= sizeof (ddsi_rtps_datafrag_t)) {
          const ddsi_rtps_datafrag_t *x = (const ddsi_rtps_datafrag_t *) submsg;
          (void) snprintf (tmp + pos, sizeof (tmp) - pos, " xflags %x otiq %u rid 0x%"PRIx32" wid 0x%"PRIx32" seq %"PRIu64" frag %"PRIu32"  fragsinmsg %"PRIu16" fragsize %"PRIu16" samplesize %"PRIu32,
                           x->x.extraFlags, x->x.octetsToInlineQos,
                           x->x.readerId.u, x->x.writerId.u, ddsi_from_seqno (x->x.writerSN),
                           x->fragmentStartingNum, x->fragmentsInSubmessage, x->fragmentSize, x->sampleSize);
        }
        break;
      default:
        break;
    }
  }
  GVWARNING ("%s\n", tmp);
}

static struct ddsi_receiver_state *rst_cow_if_needed (int *rst_live, struct ddsi_rmsg *rmsg, struct ddsi_receiver_state *rst)
{
  if (! *rst_live)
    return rst;
  else
  {
    struct ddsi_receiver_state *nrst = ddsi_rmsg_alloc (rmsg, sizeof (*nrst));
    *nrst = *rst;
    *rst_live = 0;
    return nrst;
  }
}

/*
struct ddsi_receiver_state *rst;：定义接收器状态结构体rst。

int rst_live, ts_for_latmeas;：定义一些辅助变量，用于追踪接收器状态的生存状态和时间戳。

ddsi_rtps_submessage_t * const sm = (ddsi_rtps_submessage_t *) submsg;：将当前消息的子消息强制转换为ddsi_rtps_submessage_t类型。

bool byteswap;：标志是否需要进行字节顺序交换。

if (byteswap) sm->smhdr.octetsToNextHeader = ddsrt_bswap2u(sm->smhdr.octetsToNextHeader);：如果需要字节交换，则对octetsToNextHeader字段进行交换。

const uint32_t octetsToNextHeader = sm->smhdr.octetsToNextHeader;：获取子消息的下一个消息头之前的字节数。

if (octetsToNextHeader != 0) { ... } else if (sm->smhdr.submessageId == DDSI_RTPS_SMID_PAD || sm->smhdr.submessageId == DDSI_RTPS_SMID_INFO_TS) { ... } else { ... }：处理不同情况下的子消息大小，考虑了DDS标准中规定的消息对齐和特殊情况。

submsg_size = DDSI_RTPS_SUBMESSAGE_HEADER_SIZE + octetsToNextHeader;：计算子消息的大小。

if (!((octetsToNextHeader % 4) == 0 || submsg_size == (size_t) (end - submsg))) { vr = VR_MALFORMED; break; }：如果字节数不是4的倍数且不是消息的最后一部分，则认为消息格式错误。

if (submsg_size > (size_t) (end - submsg)) { break; }：如果计算的子消息大小超过了消息的实际大小，则跳出循环。

ddsi_thread_state_awake_to_awake_no_nest(thrst);：将线程从休眠状态唤醒。

switch (sm->smhdr.submessageId) { case DDSI_RTPS_SMID_ACKNACK: ... }：根据子消息的ID执行不同的处理。在这里，处理了DDSI_RTPS_SMID_ACKNACK类型的子消息。

if ((vr = validate_AckNack(rst, &sm->acknack, submsg_size, byteswap)) == VR_ACCEPT)：调用validate_AckNack函数验证AckNack消息。

handle_AckNack(rst, tnowE, &sm->acknack, ts_for_latmeas ? timestamp : DDSRT_WCTIME_INVALID, prev_smid, &defer_hb_state);：处理AckNack消息。

ts_for_latmeas = 0;：重置用于延迟心跳测量的时间戳。

*/
static int handle_submsg_sequence
(
  struct ddsi_thread_state * const thrst,
  struct ddsi_domaingv *gv,
  struct ddsi_tran_conn * conn,
  const ddsi_locator_t *srcloc,
  ddsrt_wctime_t tnowWC,
  ddsrt_etime_t tnowE,
  const ddsi_guid_prefix_t * const src_prefix,
  const ddsi_guid_prefix_t * const dst_prefix,
  unsigned char * const msg /* NOT const - we may byteswap it */,
  const size_t len,
  unsigned char * submsg /* aliases somewhere in msg */,
  struct ddsi_rmsg * const rmsg,
  bool rtps_encoded /* indicate if the message was rtps encoded */
)
{
  ddsi_rtps_header_t * hdr = (ddsi_rtps_header_t *) msg;
  struct ddsi_receiver_state *rst;
  int rst_live, ts_for_latmeas;
  ddsrt_wctime_t timestamp;
  size_t submsg_size = 0;
  unsigned char * end = msg + len;
  struct ddsi_dqueue *deferred_wakeup = NULL;
  ddsi_rtps_submessage_kind_t prev_smid = DDSI_RTPS_SMID_PAD;
  struct defer_hb_state defer_hb_state;

  /* Receiver state is dynamically allocated with lifetime bound to
     the message.  Updates cause a new copy to be created if the
     current one is "live", i.e., possibly referenced by a
     submessage (for now, only Data(Frag)). */
  rst = ddsi_rmsg_alloc (rmsg, sizeof (*rst));
  memset (rst, 0, sizeof (*rst));
  rst->conn = conn;
  rst->src_guid_prefix = *src_prefix;
  if (dst_prefix)
  {
    rst->dst_guid_prefix = *dst_prefix;
  }
  /* "forme" is a whether the current submessage is intended for this
     instance of DDSI and is roughly equivalent to
       (dst_prefix == 0) ||
       (ddsi_entidx_lookup_participant_guid(dst_prefix:1c1) != 0)
     they are only roughly equivalent because the second term can become
     false at any time. That's ok: it's real purpose is to filter out
     discovery data accidentally sent by Cloud */
  rst->forme = 1;
  rst->rtps_encoded = rtps_encoded;
  rst->vendor = hdr->vendorid;
  rst->protocol_version = hdr->version;
  rst->srcloc = *srcloc;
  rst->gv = gv;
  rst_live = 0;
  ts_for_latmeas = 0;
  timestamp = DDSRT_WCTIME_INVALID;
  defer_hb_state_init (&defer_hb_state);
  assert (ddsi_thread_is_asleep ());
  ddsi_thread_state_awake_fixed_domain (thrst);
  enum validation_result vr = (len >= sizeof (ddsi_rtps_submessage_header_t)) ? VR_NOT_UNDERSTOOD : VR_MALFORMED;
  while (vr != VR_MALFORMED && submsg <= (end - sizeof (ddsi_rtps_submessage_header_t)))
  {

    /**
     * 字节序判断：
      如果子消息头部的 flags 字段中包含 SMFLAG_ENDIANNESS，则表示该消息需要进行字节序（大小端）的调整。
      根据字节序的要求，判断是否需要进行字节交换，如果需要，则对 octetsToNextHeader 字段进行交换。
      计算子消息的大小：

      获取 octetsToNextHeader 字段的值，该字段表示从当前子消息的末尾到下一个子消息头之间的字节数。
      根据规范，子消息需要按照 32 位边界对齐，因此检查 octetsToNextHeader 是否是 4 的倍数。如果不是，标记消息为 VR_MALFORMED。
      如果 octetsToNextHeader 不为零，计算整个子消息的大小，包括子消息头。
      如果 octetsToNextHeader 为零，且子消息类型是 SMID_PAD 或 SMID_INFO_TS，则子消息大小为子消息头大小。
      如果 octetsToNextHeader 为零，且子消息类型不是 SMID_PAD 或 SMID_INFO_TS，则子消息大小为剩余消息的长度。
      检查消息边界：

      检查计算得到的子消息大小是否越过了消息的边界。如果越界，可能表示消息格式不正确。


      如果 octetsToNextHeader 不为零：

      表示存在有效的数据需要被读取，因此需要计算整个子消息的大小，包括子消息头。这是因为 octetsToNextHeader 表示了从当前子消息的末尾到下一个子消息头之间的字节数。
      如果 octetsToNextHeader 为零，且子消息类型是 SMID_PAD 或 SMID_INFO_TS：

      对于一些特殊类型的子消息，如填充消息 (SMID_PAD) 或信息时间戳消息 (SMID_INFO_TS)，它们没有有效负载数据，因此不需要读取额外的字节。子消息头本身的大小就是整个子消息的大小。
      如果 octetsToNextHeader 为零，且子消息类型不是 SMID_PAD 或 SMID_INFO_TS：

      对于其他类型的子消息，如果 octetsToNextHeader 为零，表示该子消息之后没有有效数据，因此整个子消息的大小就是剩余消息的长度。
    */
    ddsi_rtps_submessage_t * const sm = (ddsi_rtps_submessage_t *) submsg;
    bool byteswap;

    DDSRT_WARNING_MSVC_OFF(6326)
    if (sm->smhdr.flags & DDSI_RTPS_SUBMESSAGE_FLAG_ENDIANNESS)
      byteswap = !(DDSRT_ENDIAN == DDSRT_LITTLE_ENDIAN);
    else
      byteswap =  (DDSRT_ENDIAN == DDSRT_LITTLE_ENDIAN);
    DDSRT_WARNING_MSVC_ON(6326)
    if (byteswap)
      sm->smhdr.octetsToNextHeader = ddsrt_bswap2u (sm->smhdr.octetsToNextHeader);

    const uint32_t octetsToNextHeader = sm->smhdr.octetsToNextHeader;
    if (octetsToNextHeader != 0) {
      // DDSI 2.5 9.4.1: The PSM aligns each Submessage on a 32-bit boundary
      // with respect to the start of the Message
      //
      // DDSI 2.5 9.4.5.1.3 - regular case:
      //
      // In case octetsToNextHeader > 0, it is the number of octets from the first octet
      // of the contents of the Submessage until the first octet of the header of the next
      // Submessage (in case the Submessage is not the last Submessage in the Message)
      //
      // DDSI 2.5 9.4.5.1.3 - the unnecessary complication:
      //
      // OR it is the number of octets remaining in the Message (in case the Submessage
      // is the last Submessage in the Message). An interpreter of the Message can distinguish
      // these two cases as it knows the total length of the Message.
      //
      // So what then if it is not 0 mod 4 and yet also not the number of octets remaining in
      // the Message?  The total length of the Message comes from elsewhere and is also not
      // necessarily trustworthy.  Following the tradition in Cyclone, we'll consider it
      // malformed.  (The alternative would be to *update* "end", because otherwise we'd be
      // interpreting misaligned data.)
      submsg_size = DDSI_RTPS_SUBMESSAGE_HEADER_SIZE + octetsToNextHeader;
      if (!((octetsToNextHeader % 4) == 0 || submsg_size == (size_t) (end - submsg))) {
        vr = VR_MALFORMED;
        break;
      }
    } else if (sm->smhdr.submessageId == DDSI_RTPS_SMID_PAD || sm->smhdr.submessageId == DDSI_RTPS_SMID_INFO_TS) {
      submsg_size = DDSI_RTPS_SUBMESSAGE_HEADER_SIZE;
    } else {
      submsg_size = (size_t) (end - submsg);
    }
    /*GVTRACE ("submsg_size %d\n", submsg_size);*/

    if (submsg_size > (size_t) (end - submsg))
    {
      GVTRACE (" BREAK (%u %"PRIuSIZE": %p %u)\n", (unsigned) (submsg - msg), submsg_size, (void *) msg, (unsigned) len);
      break;
    }

    ddsi_thread_state_awake_to_awake_no_nest (thrst);
    switch (sm->smhdr.submessageId)
    {
      case DDSI_RTPS_SMID_ACKNACK: {
        if ((vr = validate_AckNack (rst, &sm->acknack, submsg_size, byteswap)) == VR_ACCEPT)
          handle_AckNack (rst, tnowE, &sm->acknack, ts_for_latmeas ? timestamp : DDSRT_WCTIME_INVALID, prev_smid, &defer_hb_state);
        ts_for_latmeas = 0;
        break;
      }
      case DDSI_RTPS_SMID_HEARTBEAT: {
        if ((vr = validate_Heartbeat (&sm->heartbeat, submsg_size, byteswap)) == VR_ACCEPT)
          handle_Heartbeat (rst, tnowE, rmsg, &sm->heartbeat, ts_for_latmeas ? timestamp : DDSRT_WCTIME_INVALID, prev_smid);
        ts_for_latmeas = 0;
        break;
      }
      case DDSI_RTPS_SMID_GAP: {
        if ((vr = validate_Gap (&sm->gap, submsg_size, byteswap)) == VR_ACCEPT)
          handle_Gap (rst, tnowE, rmsg, &sm->gap, prev_smid);
        ts_for_latmeas = 0;
        break;
      }
      case DDSI_RTPS_SMID_INFO_TS: {
        if ((vr = validate_InfoTS (&sm->infots, submsg_size, byteswap)) == VR_ACCEPT) {
          handle_InfoTS (rst, &sm->infots, &timestamp);
          ts_for_latmeas = 1;
        }
        break;
      }
      case DDSI_RTPS_SMID_INFO_SRC: {
        if ((vr = validate_InfoSRC (&sm->infosrc, submsg_size, byteswap)) == VR_ACCEPT) {
          rst = rst_cow_if_needed (&rst_live, rmsg, rst);
          handle_InfoSRC (rst, &sm->infosrc);
        }
        /* no effect on ts_for_latmeas */
        break;
      }
      case DDSI_RTPS_SMID_INFO_DST: {
        if ((vr = validate_InfoDST (&sm->infodst, submsg_size, byteswap)) == VR_ACCEPT) {
          rst = rst_cow_if_needed (&rst_live, rmsg, rst);
          handle_InfoDST (rst, &sm->infodst, dst_prefix);
        }
        /* no effect on ts_for_latmeas */
        break;
      }
      case DDSI_RTPS_SMID_NACK_FRAG: {
        if ((vr = validate_NackFrag (&sm->nackfrag, submsg_size, byteswap)) == VR_ACCEPT)
          handle_NackFrag (rst, tnowE, &sm->nackfrag, prev_smid, &defer_hb_state);
        ts_for_latmeas = 0;
        break;
      }
      case DDSI_RTPS_SMID_HEARTBEAT_FRAG: {
        if ((vr = validate_HeartbeatFrag (&sm->heartbeatfrag, submsg_size, byteswap)) == VR_ACCEPT)
          handle_HeartbeatFrag (rst, tnowE, &sm->heartbeatfrag, prev_smid);
        ts_for_latmeas = 0;
        break;
      }
      case DDSI_RTPS_SMID_DATA_FRAG: {
        struct ddsi_rsample_info sampleinfo;
        uint32_t datasz = 0;
        unsigned char *datap;
        const ddsi_keyhash_t *keyhash;
        size_t submsg_len = submsg_size;
        if ((vr = validate_DataFrag (rst, &sm->datafrag, submsg_size, byteswap, &sampleinfo, &keyhash, &datap, &datasz)) != VR_ACCEPT) {
          // nothing to be done here if not accepted
        } else if (!ddsi_security_decode_datafrag (rst->gv, &sampleinfo, datap, datasz, &submsg_len)) {
          // payload decryption required but failed
          vr = VR_NOT_UNDERSTOOD;
        } else if (sm->datafrag.fragmentStartingNum == 1 && !set_sampleinfo_bswap (&sampleinfo, (struct dds_cdr_header *)datap)) {
          // first fragment has encoding header, tried to use that for setting sample bswap but failed
          vr = VR_MALFORMED;
        } else {
          sampleinfo.timestamp = timestamp;
          sampleinfo.reception_timestamp = tnowWC;
          handle_DataFrag (rst, tnowE, rmsg, &sm->datafrag, submsg_len, &sampleinfo, keyhash, datap, &deferred_wakeup, prev_smid);
          rst_live = 1;
        }
        ts_for_latmeas = 0;
        break;
      }
      case DDSI_RTPS_SMID_DATA: {
        struct ddsi_rsample_info sampleinfo;
        unsigned char *datap;
        const ddsi_keyhash_t *keyhash;
        uint32_t datasz = 0;
        size_t submsg_len = submsg_size;
        if ((vr = validate_Data (rst, &sm->data, submsg_size, byteswap, &sampleinfo, &keyhash, &datap, &datasz)) != VR_ACCEPT) {
          // nothing to be done here if not accepted
        } else if (!ddsi_security_decode_data (rst->gv, &sampleinfo, datap, datasz, &submsg_len)) {
          vr = VR_NOT_UNDERSTOOD;
        } else if (!set_sampleinfo_bswap (&sampleinfo, (struct dds_cdr_header *)datap)) {
          vr = VR_MALFORMED;
        } else {
          sampleinfo.timestamp = timestamp;
          sampleinfo.reception_timestamp = tnowWC;
          handle_Data (rst, tnowE, rmsg, &sm->data, submsg_len, &sampleinfo, keyhash, datap, &deferred_wakeup, prev_smid);
          rst_live = 1;
        }
        ts_for_latmeas = 0;
        break;
      }
      case DDSI_RTPS_SMID_SEC_PREFIX: {
        GVTRACE ("SEC_PREFIX ");
        if (!ddsi_security_decode_sec_prefix(rst, submsg, submsg_size, end, &rst->src_guid_prefix, &rst->dst_guid_prefix, byteswap))
          vr = VR_MALFORMED;
        break;
      }
      case DDSI_RTPS_SMID_PAD:
      case DDSI_RTPS_SMID_INFO_REPLY:
      case DDSI_RTPS_SMID_INFO_REPLY_IP4:
      case DDSI_RTPS_SMID_ADLINK_MSG_LEN:
      case DDSI_RTPS_SMID_ADLINK_ENTITY_ID:
      case DDSI_RTPS_SMID_SEC_BODY:
      case DDSI_RTPS_SMID_SEC_POSTFIX:
      case DDSI_RTPS_SMID_SRTPS_PREFIX:
      case DDSI_RTPS_SMID_SRTPS_POSTFIX: {
        struct submsg_name buffer;
        GVTRACE ("%s", submsg_name (sm->smhdr.submessageId, &buffer));
        break;
      }
      default: {
        GVTRACE ("UNDEFINED(%x)", sm->smhdr.submessageId);
        if (sm->smhdr.submessageId <= 0x7f) {
          /* Other submessages in the 0 .. 0x7f range may be added in
             future version of the protocol -- so an undefined code
             for the implemented version of the protocol indicates a
             malformed message. */
          if (rst->protocol_version.major < DDSI_RTPS_MAJOR ||
              (rst->protocol_version.major == DDSI_RTPS_MAJOR &&
               rst->protocol_version.minor < DDSI_RTPS_MINOR_MINIMUM))
            vr = VR_MALFORMED;
        } else {
          // Ignore vendor-specific messages, including our own ones
          // so we remain interoperable with newer versions that may
          // add vendor-specific messages.
        }
        ts_for_latmeas = 0;
        break;
      }
    }
    prev_smid = sm->smhdr.submessageId;
    submsg += submsg_size;
    GVTRACE ("\n");
  }
  if (vr != VR_MALFORMED && submsg != end)
  {
    GVTRACE ("short (size %"PRIuSIZE" exp %p act %p)", submsg_size, (void *) submsg, (void *) end);
    vr = VR_MALFORMED;
  }
  ddsi_thread_state_asleep (thrst);
  assert (ddsi_thread_is_asleep ());
  defer_hb_state_fini (gv, &defer_hb_state);
  if (deferred_wakeup)
    ddsi_dqueue_enqueue_trigger (deferred_wakeup);

  if (vr != VR_MALFORMED) {
    return 0;
  } else {
    malformed_packet_received (rst->gv, msg, submsg, len, hdr->vendorid);
    return -1;
  }
}

/*

static void handle_rtps_message (...): 这是一个静态函数handle_rtps_message，用于处理接收到的RTPS消息。

ddsi_rtps_header_t *hdr = (ddsi_rtps_header_t *) msg;: 将接收到的消息内容强制转换为ddsi_rtps_header_t类型的指针，以便读取RTPS消息的头部信息。

assert (ddsi_thread_is_asleep ());: 使用断言确保当前线程处于休眠状态，以防止并发处理消息。

if (sz < DDSI_RTPS_MESSAGE_HEADER_SIZE || *(uint32_t *)msg != DDSI_PROTOCOLID_AS_UINT32): 检查消息的大小是否足够包含RTPS消息头部信息，并且检查消息是否包含正确的魔术Cookie（Magic Cookie）。

else if (hdr->version.major != DDSI_RTPS_MAJOR || (hdr->version.major == DDSI_RTPS_MAJOR && hdr->version.minor < DDSI_RTPS_MINOR_MINIMUM)): 检查RTPS消息的版本号是否与当前实现兼容。

hdr->guid_prefix = ddsi_ntoh_guid_prefix (hdr->guid_prefix);: 将RTPS消息头部中的GUID前缀进行网络字节序转换，以确保正确解析GUID前缀。于将GUID前缀从网络字节序转换为主机字节序。这样做的目的是为了确保接收方能够正确识别并处理GUID前缀，以正确地标识DDS实体。通过进行字节序转换，可以保证不同计算机之间在通信过程中正确地处理RTPS消息头部中的GUID前缀。

if (gv->logconfig.c.mask & DDS_LC_TRACE): 检查是否开启了TRACE日志配置。

ddsi_rtps_msg_state_t res = ddsi_security_decode_rtps_message (...): 调用安全性解码函数以处理RTPS消息的安全性，该函数会对消息进行解密和身份验证等处理。

if (res != DDSI_RTPS_MSG_STATE_ERROR): 检查RTPS消息的处理结果是否出现错误。

handle_submsg_sequence (...): 处理RTPS消息中的子消息序列，将子消息传递给相应的处理函数。

*/
static void handle_rtps_message (struct ddsi_thread_state * const thrst, struct ddsi_domaingv *gv, struct ddsi_tran_conn * conn, const ddsi_guid_prefix_t *guidprefix, struct ddsi_rbufpool *rbpool, struct ddsi_rmsg *rmsg, size_t sz, unsigned char *msg, const ddsi_locator_t *srcloc)
{
  ddsi_rtps_header_t *hdr = (ddsi_rtps_header_t *) msg;
  assert (ddsi_thread_is_asleep ());
  if (sz < DDSI_RTPS_MESSAGE_HEADER_SIZE || *(uint32_t *)msg != DDSI_PROTOCOLID_AS_UINT32)
  {
    /* discard packets that are really too small or don't have magic cookie */
  }
  else if (hdr->version.major != DDSI_RTPS_MAJOR || (hdr->version.major == DDSI_RTPS_MAJOR && hdr->version.minor < DDSI_RTPS_MINOR_MINIMUM))
  {
    if ((hdr->version.major == DDSI_RTPS_MAJOR && hdr->version.minor < DDSI_RTPS_MINOR_MINIMUM))
      GVTRACE ("HDR(%"PRIx32":%"PRIx32":%"PRIx32" vendor %d.%d) len %lu\n, version mismatch: %d.%d\n",
               PGUIDPREFIX (hdr->guid_prefix), hdr->vendorid.id[0], hdr->vendorid.id[1], (unsigned long) sz, hdr->version.major, hdr->version.minor);
    if (DDSI_SC_PEDANTIC_P (gv->config))
      malformed_packet_received (gv, msg, NULL, (size_t) sz, hdr->vendorid);
  }
  else
  {
    hdr->guid_prefix = ddsi_ntoh_guid_prefix (hdr->guid_prefix);

    if (gv->logconfig.c.mask & DDS_LC_TRACE)
    {
      char addrstr[DDSI_LOCSTRLEN];
      ddsi_locator_to_string(addrstr, sizeof(addrstr), srcloc);
      //这段代码使用 GVTRACE 宏输出一条日志，打印消息头中的一些信息。让我们分解一下：
      // PGUIDPREFIX(hdr->guid_prefix)：打印消息头中的 GUID 前缀。
      // hdr->vendorid.id[0] 和 hdr->vendorid.id[1]：打印消息头中的 vendor id。
      // (unsigned long)sz：打印消息的长度。
      // addrstr：打印地址字符串。
      // 举个例子，假设消息头的 GUID 前缀为 0x12345678, vendor id 为 2.3，消息长度为 100 字节，地址字符串为 "192.168.1.1"。那么输出的日志信息可能类似于：
      //HDR(12345678:12345678:12345678 vendor 2.3) len 100 from 192.168.1.1

      /**
    GUID（Globally Unique Identifier）前缀的长度通常是 12 个字节（96 位）。这 96 位被划分成三个部分：

    48 位表示实体的唯一标识符（Entity ID）。
    32 位表示实体的实例标识符（Instance ID）。
    16 位表示实体的参与者标识符（Participant ID）。
    这样的划分使得 GUID 在DDS（Data Distribution Service）中能够唯一标识参与者、实体、以及实体的实例。
      */
      GVTRACE ("HDR(%"PRIx32":%"PRIx32":%"PRIx32" vendor %d.%d) len %lu from %s\n",
               PGUIDPREFIX (hdr->guid_prefix), hdr->vendorid.id[0], hdr->vendorid.id[1], (unsigned long) sz, addrstr);
    }
    ddsi_rtps_msg_state_t res = ddsi_security_decode_rtps_message (thrst, gv, &rmsg, &hdr, &msg, &sz, rbpool, conn->m_stream);
    if (res != DDSI_RTPS_MSG_STATE_ERROR)
    {
      handle_submsg_sequence (thrst, gv, conn, srcloc, ddsrt_time_wallclock (), ddsrt_time_elapsed (), &hdr->guid_prefix, guidprefix, msg, (size_t) sz, msg + DDSI_RTPS_MESSAGE_HEADER_SIZE, rmsg, res == DDSI_RTPS_MSG_STATE_ENCODED);
    }
  }
}

void ddsi_handle_rtps_message (struct ddsi_thread_state * const thrst, struct ddsi_domaingv *gv, struct ddsi_tran_conn * conn, const ddsi_guid_prefix_t *guidprefix, struct ddsi_rbufpool *rbpool, struct ddsi_rmsg *rmsg, size_t sz, unsigned char *msg, const ddsi_locator_t *srcloc)
{
  handle_rtps_message (thrst, gv, conn, guidprefix, rbpool, rmsg, sz, msg, srcloc);
}

/**
 * 
 * 
定义变量和常量：函数开始时定义了一些变量和常量，包括最大数据包大小maxsz、DDS消息长度大小ddsi_msg_len_size、流消息头大小stream_hdr_size等。

分配并初始化一个ddsi_rmsg结构：ddsi_rmsg是一个用于管理接收到的数据包的数据结构。在此函数中，通过ddsi_rmsg_new函数从接收缓冲池中获取一个空闲的ddsi_rmsg结构，用于存储接收到的数据包内容。

获取接收缓冲区：根据传输连接的类型（流模式或非流模式），读取相应大小的数据到接收缓冲区buff中。如果是流模式，会首先读取DDS消息头和消息长度，然后再根据消息长度读取完整数据包；如果是非流模式，直接读取完整数据包。

处理RTPS消息：如果成功从传输连接中读取数据，且gv->deaf标志为false（即本地不处于“聋”状态），则调用handle_rtps_message函数处理接收到的RTPS消息。

提交ddsi_rmsg结构：最后通过ddsi_rmsg_commit函数提交ddsi_rmsg结构，使其变为有效，可以继续重用或释放。

返回结果：函数返回一个布尔值，表示是否成功从传输连接中读取到数据。

总体来说，do_packet函数负责读取传输连接中的数据，解析其中的RTPS消息，并交由handle_rtps_message函数进行进一步处理。这是接收线程在多播模式下处理数据包的核心函数之一。

*/



/**
 变量初始化：

const size_t maxsz = gv->config.rmsg_chunk_size < 65536 ? gv->config.rmsg_chunk_size : 65536;：计算 UDP 数据包的最大大小，取配置值 rmsg_chunk_size 和 65536 中的较小者。
const size_t ddsi_msg_len_size = 8;：定义 DDSI 消息长度的大小。
const size_t stream_hdr_size = RTPS_MESSAGE_HEADER_SIZE + ddsi_msg_len_size;：计算流式数据的头部大小，包括 RTPS 消息头和 DDSI 消息长度。
创建消息缓冲区：

struct nn_rmsg *rmsg = nn_rmsg_new(rbpool);：使用消息池 rbpool 创建一个新的消息 rmsg。
unsigned char *buff;：定义一个无符号字符指针 buff 用于存储消息的数据。
size_t buff_len = maxsz;：初始化 buff_len 为计算得到的最大数据包大小。
读取数据：

sz = ddsi_conn_read(conn, buff, stream_hdr_size, true, &srcloc);：从连接 conn 中读取流式数据包的头部到 buff 中，返回读取的字节数，srcloc 存储了数据的来源定位器。
根据连接是否为流式，有不同的读取方式：
如果是流式连接：
读取 DDSI 消息长度信息，包含在消息的头部中。
根据消息长度信息，再次读取剩余的数据。
如果不是流式连接：
直接读取数据包。
处理数据：

如果成功读取数据（sz > 0）且系统不处于 deaf 模式，将消息的大小设置为 sz。
调用 handle_rtps_message 处理 RTPS 消息，传递了相关的参数，包括消息、消息大小、数据缓冲区和数据来源定位器。
清理：

nn_rmsg_commit(rmsg);：提交消息，释放使用的资源。
返回值为 sz > 0，表示是否成功读取和处理数据。
*/
static bool do_packet (struct ddsi_thread_state * const thrst, struct ddsi_domaingv *gv, struct ddsi_tran_conn * conn, const ddsi_guid_prefix_t *guidprefix, struct ddsi_rbufpool *rbpool)
{
  /* UDP max packet size is 64kB */

  const size_t maxsz = gv->config.rmsg_chunk_size < 65536 ? gv->config.rmsg_chunk_size : 65536;
  // DDSI_RTPS_MESSAGE_HEADER_SIZE 是 RTPS 协议消息头的大小。
  // ddsi_msg_len_size 是额外的消息长度信息所占的字节数。
  // 因此，stream_hdr_size 表示整个 RTPS 数据包头的大小。这个大小在接收数据包时用于确定应该读取多少字节的数据作为头部信息，以及在后续的处理中使用。
  // const size_t ddsi_msg_len_size = 8;
  const size_t stream_hdr_size = DDSI_RTPS_MESSAGE_HEADER_SIZE + ddsi_msg_len_size;
  ssize_t sz;
  struct ddsi_rmsg * rmsg = ddsi_rmsg_new (rbpool);
  unsigned char * buff;
  size_t buff_len = maxsz;
  ddsi_rtps_header_t * hdr;
  ddsi_locator_t srcloc;

  if (rmsg == NULL)
  {
    return false;
  }
  //静态断言 DDSRT_STATIC_ASSERT (sizeof (struct ddsi_rmsg) == offsetof (struct ddsi_rmsg, chunk) + sizeof (struct ddsi_rmsg_chunk)); 确保结构体 struct ddsi_rmsg 的大小等于其成员 chunk 的偏移量加上 struct ddsi_rmsg_chunk 结构体的大小。
  DDSRT_STATIC_ASSERT (sizeof (struct ddsi_rmsg) == offsetof (struct ddsi_rmsg, chunk) + sizeof (struct ddsi_rmsg_chunk));
  //读取的数据保存在rbpool，保存地址为rmsg地址后：buff = (unsigned char *) NN_RMSG_PAYLOAD (rmsg);
  buff = (unsigned char *) DDSI_RMSG_PAYLOAD (rmsg);
  hdr = (ddsi_rtps_header_t*) buff;

  if (conn->m_stream)
  {

    /*
    这行代码的目的是通过将 hdr（消息头的起始地址）后移一个单位，得到一个指向 ddsi_rtps_msg_len_t 类型的指针 ml。在C语言中，通过将指针后移，可以访问指针指向的类型后面的数据。在这里，hdr 是消息头的起始地址，hdr + 1 就是消息头之后的地址，而且它被强制类型转换为 ddsi_rtps_msg_len_t* 类型。

    这个技巧通常用于解析可变长度的结构。在这个特定的情况中，hdr 应该是一个结构体指针，指向消息头。通过将其后移一个单位，指针就指向了消息头之后的数据部分，即 ddsi_rtps_msg_len_t 结构。这是因为 hdr + 1 实际上是指向 hdr 后面一个单元的位置。

    所以，通过这个操作，你可以通过 ml 访问消息头之后的数据，也就是消息长度信息。这是一种处理包含可变长度数据的结构的一种常见方式。
    */
    ddsi_rtps_msg_len_t * ml = (ddsi_rtps_msg_len_t*) (hdr + 1); //消息长度

    /*
      Read in packet header to get size of packet in ddsi_rtps_msg_len_t, then read in
      remainder of packet.
    */

    /* Read in DDSI header plus MSG_LEN sub message that follows it */




    /**
    if (conn->m_stream)：检查连接是否为流式连接。

    ddsi_rtps_msg_len_t *ml = (ddsi_rtps_msg_len_t*) (hdr + 1);：将 hdr 后移一个单位，得到一个 ddsi_rtps_msg_len_t 类型的指针 ml。这是为了读取消息长度信息。

    sz = ddsi_conn_read(conn, buff, stream_hdr_size, true, &srcloc);：从连接 conn 中读取消息的头部（stream_hdr_size 大小）。这个头部包含 DDSI 头部和一个 MSG_LEN 子消息。函数返回读取的字节数。

    if (sz == 0)：如果读取的字节数为零，这表示可能发生了错误，但在这个阶段还可以继续。这是因为一些流式连接可能表现出这样的行为，不一定代表错误。

    int swap; if (ml->smhdr.flags & DDSI_RTPS_SUBMESSAGE_FLAG_ENDIANNESS)：检查消息头中的字节序标志，确定是否需要进行字节序转换。

    swap = !(DDSRT_ENDIAN == DDSRT_LITTLE_ENDIAN);：如果消息的字节序标志指示大端序，那么需要进行字节序转换。

    if (swap) { ml->length = ddsrt_bswap4u(ml->length); }：如果需要字节序转换，对消息长度进行转换。
    */

//buff：表示接收数据的缓冲区，此缓冲区大小为 buff_len，即 maxsz。 buff是rmsg的chunk，size为chunk的size!!!
//buff_len：表示接收缓冲区的大小，即我们可以接收的最大数据包大小。  
//true：表示阻塞模式，即函数会阻塞等待直到有数据可读。

    sz = ddsi_conn_read (conn, buff, stream_hdr_size, true, &srcloc);
    if (sz == 0)
    {
      /* Spurious read -- which at this point is still ok */
      //最后通过ddsi_rmsg_commit函数提交ddsi_rmsg结构，使其变为有效，可以继续重用或释放。
      ddsi_rmsg_commit (rmsg);
      return true;
    }

    /* Read in remainder of packet */

    if (sz > 0)
    {
      int swap;

      DDSRT_WARNING_MSVC_OFF(6326)
      if (ml->smhdr.flags & DDSI_RTPS_SUBMESSAGE_FLAG_ENDIANNESS)
      {
        swap = !(DDSRT_ENDIAN == DDSRT_LITTLE_ENDIAN);
      }
      else
      {
        swap =  (DDSRT_ENDIAN == DDSRT_LITTLE_ENDIAN);
      }
      DDSRT_WARNING_MSVC_ON(6326)
      if (swap)
      {
        ml->length = ddsrt_bswap4u (ml->length);
      }

      /*
      if (ml->smhdr.submessageId != DDSI_RTPS_SMID_ADLINK_MSG_LEN)：检查子消息的标识符是否符合预期的 DDSI_RTPS_SMID_ADLINK_MSG_LEN。

      malformed_packet_received(gv, buff, NULL, (size_t)sz, hdr->vendorid);：如果子消息标识符不符合预期，调用 malformed_packet_received 函数，处理消息格式错误的情况。

      sz = ddsi_conn_read(conn, buff + stream_hdr_size, ml->length - stream_hdr_size, false, NULL);：读取消息的剩余部分（除去头部）。

      if (sz > 0) { sz = (ssize_t)ml->length; }：如果成功读取消息的剩余部分，则将 sz 设置为消息的总长度，否则将 sz 设置为 -1，表示出现错误。
      
      */
      if (ml->smhdr.submessageId != DDSI_RTPS_SMID_ADLINK_MSG_LEN)
      {
        malformed_packet_received (gv, buff, NULL, (size_t) sz, hdr->vendorid);
        sz = -1;
      }
      else
      {
        //ddsi_rtps_msg_len_t * ml = (ddsi_rtps_msg_len_t*) (hdr + 1);
        //const size_t stream_hdr_size = DDSI_RTPS_MESSAGE_HEADER_SIZE + ddsi_msg_len_size;
        //buff + stream_hdr_size：表示接收剩余数据的缓冲区的起始地址，即跳过了消息头部分，从消息体开始的位置。
        //ml->length - stream_hdr_size：表示要读取的剩余数据的长度，即消息的总长度减去消息头的长度，这样就保证了只读取剩余部分的数据。
        sz = ddsi_conn_read (conn, buff + stream_hdr_size, ml->length - stream_hdr_size, false, NULL);
        if (sz > 0)
        {
          sz = (ssize_t) ml->length;
        }
      }
    }
  }
  else
  {
    /* Get next packet */

    sz = ddsi_conn_read (conn, buff, buff_len, true, &srcloc);
  }

  if (sz > 0 && !gv->deaf)
  {
    ddsi_rmsg_setsize (rmsg, (uint32_t) sz);
    handle_rtps_message(thrst, gv, conn, guidprefix, rbpool, rmsg, (size_t) sz, buff, &srcloc);
  }
  ddsi_rmsg_commit (rmsg);
  return (sz > 0);
}

struct local_participant_desc
{
  struct ddsi_tran_conn * m_conn;
  ddsi_guid_prefix_t guid_prefix;
};

static int local_participant_cmp (const void *va, const void *vb)
{
  const struct local_participant_desc *a = va;
  const struct local_participant_desc *b = vb;
  ddsrt_socket_t h1 = ddsi_conn_handle (a->m_conn);
  ddsrt_socket_t h2 = ddsi_conn_handle (b->m_conn);
  return (h1 == h2) ? 0 : (h1 < h2) ? -1 : 1;
}

static size_t dedup_sorted_array (void *base, size_t nel, size_t width, int (*compar) (const void *, const void *))
{
  if (nel <= 1)
    return nel;
  else
  {
    char * const end = (char *) base + nel * width;
    char *last_unique = base;
    char *cursor = (char *) base + width;
    size_t n_unique = 1;
    while (cursor != end)
    {
      if (compar (cursor, last_unique) != 0)
      {
        n_unique++;
        last_unique += width;
        if (last_unique != cursor)
          memcpy (last_unique, cursor, width);
      }
      cursor += width;
    }
    return n_unique;
  }
}

struct local_participant_set {
  struct local_participant_desc *ps;
  uint32_t nps;
  uint32_t gen;
};

static void local_participant_set_init (struct local_participant_set *lps, ddsrt_atomic_uint32_t *ppset_generation)
{
  lps->ps = NULL;
  lps->nps = 0;
  lps->gen = ddsrt_atomic_ld32 (ppset_generation) - 1;
}

static void local_participant_set_fini (struct local_participant_set *lps)
{
  ddsrt_free (lps->ps);
}

static void rebuild_local_participant_set (struct ddsi_thread_state * const thrst, struct ddsi_domaingv *gv, struct local_participant_set *lps)
{
  struct ddsi_entity_enum_participant est;
  struct ddsi_participant *pp;
  unsigned nps_alloc;
  GVTRACE ("pp set gen changed: local %"PRIu32" global %"PRIu32"\n", lps->gen, ddsrt_atomic_ld32 (&gv->participant_set_generation));
  ddsi_thread_state_awake_fixed_domain (thrst);
 restart:
  lps->gen = ddsrt_atomic_ld32 (&gv->participant_set_generation);
  /* Actual local set of participants may never be older than the
     local generation count => membar to guarantee the ordering */
  ddsrt_atomic_fence_acq ();
  nps_alloc = gv->nparticipants;
  ddsrt_free (lps->ps);
  lps->nps = 0;
  lps->ps = (nps_alloc == 0) ? NULL : ddsrt_malloc (nps_alloc * sizeof (*lps->ps));
  ddsi_entidx_enum_participant_init (&est, gv->entity_index);
  while ((pp = ddsi_entidx_enum_participant_next (&est)) != NULL)
  {
    if (lps->nps == nps_alloc)
    {
      /* New participants may get added while we do this (or
         existing ones removed), so we may have to restart if it
         turns out we didn't allocate enough memory [an
         alternative would be to realloc on the fly]. */
      ddsi_entidx_enum_participant_fini (&est);
      GVTRACE ("  need more memory - restarting\n");
      goto restart;
    }
    else
    {
      lps->ps[lps->nps].m_conn = pp->m_conn;
      lps->ps[lps->nps].guid_prefix = pp->e.guid.prefix;
      GVTRACE ("  pp "PGUIDFMT" handle %"PRIdSOCK"\n", PGUID (pp->e.guid), ddsi_conn_handle (pp->m_conn));
      lps->nps++;
    }
  }
  ddsi_entidx_enum_participant_fini (&est);

  /* There is a (very small) probability of a participant
     disappearing and new one appearing with the same socket while
     we are enumerating, which would cause us to misinterpret the
     participant guid prefix for a directed packet without an
     explicit destination. Membar because we must have completed
     the loop before testing the generation again. */
  ddsrt_atomic_fence_acq ();
  if (lps->gen != ddsrt_atomic_ld32 (&gv->participant_set_generation))
  {
    GVTRACE ("  set changed - restarting\n");
    goto restart;
  }
  ddsi_thread_state_asleep (thrst);

  /* The definition of the hash enumeration allows visiting one
     participant multiple times, so guard against that, too.  Note
     that there's no requirement that the set be ordered on
     socket: it is merely a convenient way of finding
     duplicates. */
  if (lps->nps)
  {
    qsort (lps->ps, lps->nps, sizeof (*lps->ps), local_participant_cmp);
    lps->nps = (unsigned) dedup_sorted_array (lps->ps, lps->nps, sizeof (*lps->ps), local_participant_cmp);
  }
  GVTRACE ("  nparticipants %"PRIu32"\n", lps->nps);
}

uint32_t ddsi_listen_thread (struct ddsi_tran_listener *listener)
{
  struct ddsi_domaingv *gv = listener->m_base.gv;
  struct ddsi_tran_conn * conn;

  while (ddsrt_atomic_ld32 (&gv->rtps_keepgoing))
  {
    /* Accept connection from listener */

    conn = ddsi_listener_accept (listener);
    if (conn)
    {
      ddsi_sock_waitset_add (gv->recv_threads[0].arg.u.many.ws, conn);
      ddsi_sock_waitset_trigger (gv->recv_threads[0].arg.u.many.ws);
    }
  }
  return 0;
}

static int recv_thread_waitset_add_conn (struct ddsi_sock_waitset * ws, struct ddsi_tran_conn * conn)
{
  if (conn == NULL)
    return 0;
  else
  {
    struct ddsi_domaingv *gv = conn->m_base.gv;
    for (uint32_t i = 0; i < gv->n_recv_threads; i++)
      if (gv->recv_threads[i].arg.mode == DDSI_RTM_SINGLE && gv->recv_threads[i].arg.u.single.conn == conn)
        return 0;
    return ddsi_sock_waitset_add (ws, conn);
  }
}

void ddsi_trigger_recv_threads (const struct ddsi_domaingv *gv)
{
  for (uint32_t i = 0; i < gv->n_recv_threads; i++)
  {
    if (gv->recv_threads[i].thrst == NULL)
      continue;
    switch (gv->recv_threads[i].arg.mode)
    {
      case DDSI_RTM_SINGLE: {
        char buf[DDSI_LOCSTRLEN];
        char dummy = 0;
        const ddsi_locator_t *dst = gv->recv_threads[i].arg.u.single.loc;
        ddsrt_iovec_t iov;
        iov.iov_base = &dummy;
        iov.iov_len = 1;
        GVTRACE ("ddsi_trigger_recv_threads: %"PRIu32" single %s\n", i, ddsi_locator_to_string (buf, sizeof (buf), dst));
        // all sockets listen on at least the interfaces used for transmitting (at least for now)
        ddsi_conn_write (gv->xmit_conns[0], dst, 1, &iov, 0);
        break;
      }
      case DDSI_RTM_MANY: {
        GVTRACE ("ddsi_trigger_recv_threads: %"PRIu32" many %p\n", i, (void *) gv->recv_threads[i].arg.u.many.ws);
        ddsi_sock_waitset_trigger (gv->recv_threads[i].arg.u.many.ws);
        break;
      }
    }
  }
}

/*
struct ddsi_thread_state * const thrst = ddsi_lookup_thread_state ();: 获取当前线程的状态结构体thrst。

struct ddsi_recv_thread_arg *recv_thread_arg = vrecv_thread_arg;: 将传入的参数vrecv_thread_arg强制类型转换为struct ddsi_recv_thread_arg类型，并赋值给recv_thread_arg。

struct ddsi_domaingv * const gv = recv_thread_arg->gv;: 从参数中获取全局域结构体指针gv。

struct ddsi_rbufpool *rbpool = recv_thread_arg->rbpool;: 从参数中获取接收缓冲池结构体指针rbpool。

struct ddsi_sock_waitset * waitset = recv_thread_arg->mode == DDSI_RTM_MANY ? recv_thread_arg->u.many.ws : NULL;: 根据传入的线程模式，将多播模式下的ddsrt_sock_waitset对象赋值给waitset。在单播模式下，waitset将为NULL。

ddsi_rbufpool_setowner (rbpool, ddsrt_thread_self ());: 设置接收缓冲池的所有者线程为当前线程。

接下来，根据工作模式执行不同的接收逻辑：

a. 在单播模式下，通过循环监听单个传输连接（conn），并在每次循环中调用do_packet函数处理接收到的数据包。

b. 在多播模式下，使用local_participant_set结构来管理多个传输连接，并在需要时重建waitset以反映参与者（participant）的更改。在循环中，等待waitset中的任何传输连接上的事件，然后调用do_packet函数处理接收到的数据包。

在处理完数据包后，继续执行下一次循环直到gv->rtps_keepgoing为false，表示接收线程需要退出。

GVTRACE ("done\n");: 输出日志，表示接收线程完成任务。

总结：ddsi_recv_thread函数负责在不同的工作模式下，接收和处理来自不同传输连接的数据包，并将其交给do_packet函数进行处理。它是接收线程的主要逻辑实现。在单播模式下，它通过循环监听单个传输连接；在多播模式下，它使用waitset对象来管理多个传输连接并等待事件。这样，接收线程能够高效地处理接收到的数据，并将其分发给相应的处理逻辑。

*/





/*

struct thread_state1 * const ts1 = lookup_thread_state ();：获取当前线程的状态。

struct recv_thread_arg *recv_thread_arg = vrecv_thread_arg;：将传递给线程的参数转换为 recv_thread_arg 结构。

struct ddsi_domaingv * const gv = recv_thread_arg->gv;：获取域的全局变量。

struct nn_rbufpool *rbpool = recv_thread_arg->rbpool;：获取消息缓冲池。

os_sockWaitset waitset = recv_thread_arg->mode == RTM_MANY ? recv_thread_arg->u.many.ws : NULL;：根据模式选择是否使用等待集（waitset）。

nn_rbufpool_setowner (rbpool, ddsrt_thread_self ());：设置消息缓冲池的所有权。

if (waitset == NULL)：如果没有等待集，说明是单一连接模式。

struct ddsi_tran_conn *conn = recv_thread_arg->u.single.conn;：获取单一连接。

while (ddsrt_atomic_ld32 (&gv->rtps_keepgoing))：循环，只要全局变量 rtps_keepgoing 为真。

LOG_THREAD_CPUTIME (&gv->logconfig, next_thread_cputime);：记录线程 CPU 时间。

(void) do_packet (ts1, gv, conn, NULL, rbpool);：调用 do_packet 处理数据包。

else：如果有等待集，说明是多连接模式。

struct local_participant_set lps;：本地参与者集合结构。

unsigned num_fixed = 0, num_fixed_uc = 0;：计数器，记录固定连接的数量。

os_sockWaitsetCtx ctx;：等待集上下文。

local_participant_set_init (&lps, &gv->participant_set_generation);：初始化本地参与者集合。

接下来进入主循环：

int rebuildws = 0;：标志是否需要重建等待集。

LOG_THREAD_CPUTIME (&gv->logconfig, next_thread_cputime);：记录线程 CPU 时间。

如果多播模式，检查是否需要重建等待集。

if ((ctx = os_sockWaitsetWait (waitset)) != NULL)：如果等待集上有事件发生。

循环处理等待集中的事件：

如果是固定连接或者是多播模式，guid_prefix = NULL；否则，获取参与者的 GUID 前缀。

if (!do_packet (ts1, gv, conn, guid_prefix, rbpool) && !conn->m_connless)：处理数据包，如果失败且不是无连接连接，则释放连接。

local_participant_set_fini (&lps);：释放本地参与者集合的资源。

GVTRACE ("done\n");：记录线程完成。

return 0;：返回 0。


*/
uint32_t ddsi_recv_thread (void *vrecv_thread_arg)
{
  struct ddsi_thread_state * const thrst = ddsi_lookup_thread_state ();
  struct ddsi_recv_thread_arg *recv_thread_arg = vrecv_thread_arg;
  struct ddsi_domaingv * const gv = recv_thread_arg->gv;
  struct ddsi_rbufpool *rbpool = recv_thread_arg->rbpool;
  struct ddsi_sock_waitset * waitset = recv_thread_arg->mode == DDSI_RTM_MANY ? recv_thread_arg->u.many.ws : NULL;
  ddsrt_mtime_t next_thread_cputime = { 0 };

  ddsi_rbufpool_setowner (rbpool, ddsrt_thread_self ());
  if (waitset == NULL)
  {
    struct ddsi_tran_conn *conn = recv_thread_arg->u.single.conn;
    while (ddsrt_atomic_ld32 (&gv->rtps_keepgoing))
    {
      LOG_THREAD_CPUTIME (&gv->logconfig, next_thread_cputime);
      (void) do_packet (thrst, gv, conn, NULL, rbpool);
    }
  }
  else
  {
    //使用local_participant_set结构来管理多个传输连接
    struct local_participant_set lps;
    unsigned num_fixed = 0, num_fixed_uc = 0;
    struct ddsi_sock_waitset_ctx * ctx;
    local_participant_set_init (&lps, &gv->participant_set_generation);

  /// Whether this is a connection-oriented transport like TCP (false), where a socket communicates
  /// with one other socket after connecting; or whether it can send to any address at any time like
  /// UDP (true).
  bool m_connless;
    if (gv->m_factory->m_connless)
    {
      //recv_thread_waitset_add_conn函数的作用是将一个传输连接（struct ddsi_tran_conn）添加到ddsrt_sock_waitset对象中。这样做的目的是使接收线程能够通过等待waitset上的事件来处理多个传输连接，而无需在循环中轮询每个传输连接。在多播模式下，接收线程可能需要监听多个传输连接，这些传输连接可能对应不同的参与者（participant）或者传输方式（unicast/multicast）。通过将这些传输连接添加到waitset对象中，接收线程可以通过等待waitset上的事件，来处理到达这些传输连接的数据包。这样，接收线程就可以更高效地处理数据包的接收和分发。
      //函数签名：int recv_thread_waitset_add_conn(struct ddsi_sock_waitset *ws, struct ddsi_tran_conn *conn);

      // 参数说明：

      // ws：要添加传输连接的ddsrt_sock_waitset对象。
      // conn：要添加到waitset的传输连接。
      // 返回值：

      // 返回值为正数表示成功添加传输连接到waitset。
      // 返回值为负数表示添加失败。
      // 请注意，recv_thread_waitset_add_conn函数只在多播模式下使用，因为在单播模式下只需要监听一个传输连接。

      int rc;
      if ((rc = recv_thread_waitset_add_conn (waitset, gv->disc_conn_uc)) < 0)
        DDS_FATAL("recv_thread: failed to add disc_conn_uc to waitset\n");
      num_fixed_uc += (unsigned)rc;
      if ((rc = recv_thread_waitset_add_conn (waitset, gv->data_conn_uc)) < 0)
        DDS_FATAL("recv_thread: failed to add data_conn_uc to waitset\n");
      num_fixed_uc += (unsigned)rc;
      num_fixed += num_fixed_uc;
      if ((rc = recv_thread_waitset_add_conn (waitset, gv->disc_conn_mc)) < 0)
        DDS_FATAL("recv_thread: failed to add disc_conn_mc to waitset\n");
      num_fixed += (unsigned)rc;
      if ((rc = recv_thread_waitset_add_conn (waitset, gv->data_conn_mc)) < 0)
        DDS_FATAL("recv_thread: failed to add data_conn_mc to waitset\n");
      num_fixed += (unsigned)rc;

      // OpenDDS doesn't respect the locator lists and insists on sending to the
      // socket it received packets from
      for (int i = 0; i < gv->n_interfaces; i++)
      {
        // Iceoryx gets added as a pseudo-interface but there's no socket to wait
        // for input on
        if (ddsi_conn_handle (gv->xmit_conns[i]) == DDSRT_INVALID_SOCKET)
          continue;
        if ((rc = recv_thread_waitset_add_conn (waitset, gv->xmit_conns[i])) < 0)
          DDS_FATAL("recv_thread: failed to add transmit_conn[%d] to waitset\n", i);
        num_fixed += (unsigned)rc;
      }
    }

    while (ddsrt_atomic_ld32 (&gv->rtps_keepgoing))
    {
      int rebuildws = 0;
      LOG_THREAD_CPUTIME (&gv->logconfig, next_thread_cputime);
      if (gv->config.many_sockets_mode != DDSI_MSM_MANY_UNICAST)
      {
        /* no other sockets to check */
      }
      /*
      gv->participant_set_generation：这是一个全局变量，可能表示参与者集合的当前代数或版本。在分布式系统中，可能会有多个参与者（participants），每个参与者都有一个唯一的标识。当有新的参与者加入或离开系统时，版本号可能会被递增，表示发生了变化。

      lps.gen：这是本地参与者集合（lps）的版本号。该版本号在初始化时设置，并且在每次重建等待集合时可能会更新。

      因此，条件 ddsrt_atomic_ld32 (&gv->participant_set_generation) != lps.gen 意味着如果全局参与者集合的版本号与本地参与者集合的版本号不相等，就设置 rebuildws 为1，表示需要重建等待集合。这通常表示有新的参与者加入或离开系统，需要更新等待集合以反映这些变化。
      
      */
      else if (ddsrt_atomic_ld32 (&gv->participant_set_generation) != lps.gen)
      {
        rebuildws = 1;
      }

    /*
    如果需要重新建立等待集合（rebuildws 为真），并且配置为许多套接字模式，那么执行以下操作：
    重建本地参与者集合。
    清除等待集合中的固定连接。
    将本地参与者集合中的连接添加到等待集合。
    */
      if (rebuildws && waitset && gv->config.many_sockets_mode == DDSI_MSM_MANY_UNICAST)
      {
        /* first rebuild local participant set - unless someone's toggling "deafness", this
         only happens when the participant set has changed, so might as well rebuild it */
        rebuild_local_participant_set (thrst, gv, &lps);
        ddsi_sock_waitset_purge (waitset, num_fixed);
        for (uint32_t i = 0; i < lps.nps; i++)
        {
          if (lps.ps[i].m_conn)
            ddsi_sock_waitset_add (waitset, lps.ps[i].m_conn);
        }
      }

      /*
      在主循环中，首先检查程序是否需要保持运行。
      然后，它检查等待集合中的事件。
      如果有事件发生，就遍历这些事件并处理每个事件。
      do_packet 函数用于处理接收到的数据包。
      如果数据包处理失败或连接关闭，ddsi_conn_free 会释放连接
      */
      if ((ctx = ddsi_sock_waitset_wait (waitset)) != NULL)
      {
        int idx;
        struct ddsi_tran_conn * conn;
        while ((idx = ddsi_sock_waitset_next_event (ctx, &conn)) >= 0)
        {
          const ddsi_guid_prefix_t *guid_prefix;
          if (((unsigned)idx < num_fixed) || gv->config.many_sockets_mode != DDSI_MSM_MANY_UNICAST)
            guid_prefix = NULL;
          else
            guid_prefix = &lps.ps[(unsigned)idx - num_fixed].guid_prefix;
          /* Process message and clean out connection if failed or closed */
          if (!do_packet (thrst, gv, conn, guid_prefix, rbpool) && !conn->m_connless)
            ddsi_conn_free (conn);
        }
      }
    }
    local_participant_set_fini (&lps);
  }

  GVTRACE ("done\n");
  return 0;
}
