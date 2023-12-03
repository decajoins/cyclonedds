// Copyright(c) 2020 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI__ACKNACK_H
#define DDSI__ACKNACK_H

#include <stddef.h>
#include <stdbool.h>

#include "dds/ddsrt/time.h"
#include "ddsi__xevent.h"
#include "ddsi__protocol.h"

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_xevent;
struct ddsi_pwr_rd_match;
struct ddsi_proxy_writer;

//表示添加 ACKNACK 信息的结果，包括以下几种情况：
enum ddsi_add_acknack_result {
  //不发送任何内容，因为距离上次 ACK 发送的时间太短。
  AANR_SUPPRESSED_ACK,  //!< sending nothing: too short a time since the last ACK
  //发送 ACK，且没有需要 NACK 的内容。
  AANR_ACK,             //!< sending an ACK and there's nothing to NACK
  //即使有需要 NACK 的内容，也发送 ACK。
  AANR_SUPPRESSED_NACK, //!< sending an ACK even though there are things to NACK
  //发送 NACK，可能同时发送 NACKFRAG。
  AANR_NACK,            //!< sending a NACK, possibly also a NACKFRAG
  //仅发送 NACKFRAG。
  AANR_NACKFRAG_ONLY    //!< sending only a NACKFRAG
};

DDSRT_STATIC_ASSERT ((DDSI_SEQUENCE_NUMBER_SET_MAX_BITS % 32) == 0 && (DDSI_FRAGMENT_NUMBER_SET_MAX_BITS % 32) == 0);
//用于存储发送 ACKNACK 的相关信息。包括以下字段：
struct ddsi_add_acknack_info {
  //表示最近一次 NACK 是否是由于 NackDelay 引起的。
  bool nack_sent_on_nackdelay;
  //如果 ACK_REASON_IN_FLAGS 被定义，则表示附加的 ACKNACK 标志。
#if ACK_REASON_IN_FLAGS
  uint8_t flags;
#endif
  struct {
    //表示 ACK 的序列号集的头部信息。
    struct ddsi_sequence_number_set_header set;
    //存储 ACK 序列号集的实际数据，以32位为单位。
    uint32_t bits[DDSI_FRAGMENT_NUMBER_SET_MAX_BITS / 32];
  } acknack;
  struct {
    //表示 NACK 的序列号。
    ddsi_seqno_t seq;
    //表示 NACKFRAG 的分片号集的头部信息。
    struct ddsi_fragment_number_set_header set;
    //存储 NACKFRAG 分片号集的实际数据，以32位为单位。
    uint32_t bits[DDSI_FRAGMENT_NUMBER_SET_MAX_BITS / 32];
  } nackfrag;
};


/** @component incoming_rtps */
void ddsi_sched_acknack_if_needed (struct ddsi_xevent *ev, struct ddsi_proxy_writer *pwr, struct ddsi_pwr_rd_match *rwn, ddsrt_mtime_t tnow, bool avoid_suppressed_nack);

struct ddsi_acknack_xevent_cb_arg {
  ddsi_guid_t pwr_guid;
  ddsi_guid_t rd_guid;
};

void ddsi_acknack_xevent_cb (struct ddsi_domaingv *gv, struct ddsi_xevent *ev, struct ddsi_xpack *xp, void *varg, ddsrt_mtime_t tnow);

#if defined (__cplusplus)
}
#endif

#endif /* DDSI__ACKNACK_H */
