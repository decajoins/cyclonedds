// Copyright(c) 2006 to 2020 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI_HBCONTROL_H
#define DDSI_HBCONTROL_H

#include "dds/features.h"
#include "dds/ddsrt/time.h"

#if defined (__cplusplus)
extern "C" {
#endif

/// @brief State information used in deciding when/what kind of a heartbeat to send (per writer)
///
/// Heartbeats inform readers of the range of sequence numbers available from the writer and serve the dual
/// purpose of (1) allowing the reader to detect message loss, and (2) allowing the reader to request a retransmit.
///
/// Because readers are not allowed to request a retransmit unless they received a heartbeat, we make an
/// effort to a embed heartbeat in an outgoing RTPS message (~ a packet) if a preceding RTPS message
/// also contained data from the writer. Its sole purpose is to allow it to request a retransmit.
struct ddsi_hbcontrol {
  ddsrt_mtime_t t_of_last_write; ///< Time of most recent write
  ddsrt_mtime_t t_of_last_hb;    ///< Time of last heartbeat sent
  ddsrt_mtime_t t_of_last_ackhb; ///< Time of last heartbeat sent that requires a response
  ddsrt_mtime_t tsched;          ///< Time at which next asynchronous heartbeat is scheduled
  uint32_t hbs_since_last_write; ///< Number of heartbeats sent since last write
  uint32_t last_packetid;        ///< Last RTPS message id containing a heartbeat from this writer
};

/// @brief Encoding for possible ways of adding heartbeats to messages
/*
这段代码定义了一个枚举类型 ddsi_hbcontrol_ack_required，该枚举用于表示心跳控制（Heartbeat Control）中的不同状态。具体来说，它表示心跳（Heartbeat）是否需要接收方的响应。

DDSI_HBC_ACK_REQ_NO: 表示心跳不需要接收方的响应。这通常对应于在心跳中设置了 FINAL 标志，表示这是最后一个心跳，不需要接收方进行响应。

DDSI_HBC_ACK_REQ_YES: 表示心跳需要接收方的响应，并且可以继续打包（packing）其他消息。这意味着发送方期望接收方响应，但不必立即发送下一个心跳。

DDSI_HBC_ACK_REQ_YES_AND_FLUSH: 表示心跳需要接收方的响应，并且必须立即发送下一个心跳。这可能是因为发送方需要在一定时间内得到接收方的响应，因此需要立即发送下一个心跳。

这些状态提供了一种对心跳发送和接收的控制机制，以确保在通信中的一致性和可靠性。
*/
enum ddsi_hbcontrol_ack_required {
  DDSI_HBC_ACK_REQ_NO,           ///< Heartbeat does not require a response (FINAL flag set)
  DDSI_HBC_ACK_REQ_YES,          ///< Heartbeat requires a response, may continue packing
  DDSI_HBC_ACK_REQ_YES_AND_FLUSH ///< Heartbeat requires a response, must send immediately
};

#if defined (__cplusplus)
}
#endif

#endif /* DDSI_HBCONTROL_H */
