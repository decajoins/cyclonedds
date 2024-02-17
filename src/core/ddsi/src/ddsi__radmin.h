// Copyright(c) 2006 to 2021 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI__RADMIN_H
#define DDSI__RADMIN_H

#include <stddef.h>

#include "dds/ddsrt/time.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/threads.h"
#include "dds/ddsrt/align.h"
#include "dds/ddsrt/static_assert.h"
#include "dds/ddsi/ddsi_locator.h"
#include "dds/ddsi/ddsi_protocol.h"
#include "dds/ddsi/ddsi_radmin.h"

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_rbufpool;
struct ddsi_rbuf;
struct ddsi_rmsg;
struct ddsi_rdata;
struct ddsi_rsample;
struct ddsi_rsample_chain;
struct ddsi_rsample_info;
struct ddsi_defrag;
struct ddsi_reorder;
struct ddsi_dqueue;
struct ddsi_guid;
struct ddsi_tran_conn;
struct ddsi_proxy_writer;
struct ddsrt_log_cfg;
struct ddsi_fragment_number_set_header;
struct ddsi_sequence_number_set_header;

/* Allocated inside a chunk of memory by a custom allocator and requires >= 8-byte alignment */
#define DDSI_ALIGNOF_RMSG (dds_alignof(struct ddsi_rmsg) > 8 ? dds_alignof(struct ddsi_rmsg) : 8)

typedef int (*ddsi_dqueue_handler_t) (const struct ddsi_rsample_info *sampleinfo, const struct ddsi_rdata *fragchain, const struct ddsi_guid *rdguid, void *qarg);

/**
 * 
ddsi_receiver_state： 包含接收器状态的结构体，其中包括源和目标GUID前缀、回复定位器、厂商ID、协议版本等信息。这是接收器的基本状态。

ddsi_rsample_info： 包含接收到的样本信息，如序列号、接收器状态、代理写入器、样本大小、时间戳等。

ddsi_rsample_chain_elem和ddsi_rsample_chain： 这两个结构体表示样本的链式结构。ddsi_rsample_chain_elem
包含一个样本的片段链，以及指向下一个元素的指针。ddsi_rsample_chain则表示整个样本链。

rsample_info → rsample_chain → rsample_chain_elem： 
对接收到的样本的信息可以链接成一个样本链，其中每个元素由ddsi_rsample_chain_elem结构表示。
*/
//创建一个 ddsi_rsample 结构表示接收到的数据。该函数用于将接收到的数据碎片重新组装成完整的数据样本（rsample）



struct ddsi_receiver_state {
  ddsi_guid_prefix_t src_guid_prefix;     /* 12 */
  ddsi_guid_prefix_t dst_guid_prefix;     /* 12 */
  struct ddsi_addrset *reply_locators;         /* 4/8 */
  uint32_t forme:1;                       /* 4 */
  uint32_t rtps_encoded:1;                /* - */
  ddsi_vendorid_t vendor;                   /* 2 */
  ddsi_protocol_version_t protocol_version; /* 2 => 44/48 */
  struct ddsi_tran_conn *conn;            /* Connection for request */
  ddsi_locator_t srcloc;
  struct ddsi_domaingv *gv;
};

struct ddsi_rsample_info {
  ddsi_seqno_t seq;
  struct ddsi_receiver_state *rst;
  struct ddsi_proxy_writer *pwr;
  uint32_t size;
  uint32_t fragsize;
  ddsrt_wctime_t timestamp;
  ddsrt_wctime_t reception_timestamp; /* OpenSplice extension -- but we get it essentially for free, so why not? */
  unsigned statusinfo: 2;       /* just the two defined bits from the status info */
  unsigned bswap: 1;            /* so we can extract well formatted writer info quicker */
  unsigned complex_qos: 1;      /* includes QoS other than keyhash, 2-bit statusinfo, PT writer info */
};

struct ddsi_rsample_chain_elem {
  /* FIXME: evidently smaller than a defrag_iv, but maybe better to
     merge it with defrag_iv in a union anyway. */
  struct ddsi_rdata *fragchain;
  struct ddsi_rsample_chain_elem *next;
  /* Gaps have sampleinfo = NULL, but nonetheless a fragchain with 1
     rdata with min=maxp1 (length 0) and valid rmsg pointer.  And (see
     DQUEUE) its lsb gets abused so we can queue "bubbles" in addition
     to data). */
  struct ddsi_rsample_info *sampleinfo;
};

struct ddsi_rsample_chain {
  struct ddsi_rsample_chain_elem *first;
  struct ddsi_rsample_chain_elem *last;
};

enum ddsi_reorder_mode {
  DDSI_REORDER_MODE_NORMAL,
  DDSI_REORDER_MODE_MONOTONICALLY_INCREASING,
  DDSI_REORDER_MODE_ALWAYS_DELIVER
};

enum ddsi_defrag_drop_mode {
  DDSI_DEFRAG_DROP_OLDEST,        /* (believed to be) best for unreliable */
  DDSI_DEFRAG_DROP_LATEST         /* (...) best for reliable  */
};

typedef int32_t ddsi_reorder_result_t;
/* typedef of reorder result serves as a warning that it is to be
   interpreted as follows: */
/* REORDER_DELIVER > 0 -- number of samples in sample chain */
#define DDSI_REORDER_ACCEPT        0 /* accepted/stored (for gap: also adjusted next_expected) */
#define DDSI_REORDER_TOO_OLD      -1 /* discarded because it was too old */
#define DDSI_REORDER_REJECT       -2 /* caller may reuse memory ("real" reject for data, "fake" for gap) */

typedef void (*ddsi_dqueue_callback_t) (void *arg);

enum ddsi_defrag_nackmap_result {
  DDSI_DEFRAG_NACKMAP_UNKNOWN_SAMPLE,
  DDSI_DEFRAG_NACKMAP_ALL_ADVERTISED_FRAGMENTS_KNOWN,
  DDSI_DEFRAG_NACKMAP_FRAGMENTS_MISSING
};

/** @component receive_buffers */
struct ddsi_rbufpool *ddsi_rbufpool_new (const struct ddsrt_log_cfg *logcfg, uint32_t rbuf_size, uint32_t max_rmsg_size);

/** @component receive_buffers */
void ddsi_rbufpool_setowner (struct ddsi_rbufpool *rbp, ddsrt_thread_t tid);

/** @component receive_buffers */
void ddsi_rbufpool_free (struct ddsi_rbufpool *rbp);

/** @component receive_buffers */
struct ddsi_rmsg *ddsi_rmsg_new (struct ddsi_rbufpool *rbufpool);

/** @component receive_buffers */
void ddsi_rmsg_setsize (struct ddsi_rmsg *rmsg, uint32_t size);

/** @component receive_buffers */
void ddsi_rmsg_commit (struct ddsi_rmsg *rmsg);

/** @component receive_buffers */
void ddsi_rmsg_free (struct ddsi_rmsg *rmsg);

/** @component receive_buffers */
void *ddsi_rmsg_alloc (struct ddsi_rmsg *rmsg, uint32_t size);

/** @component receive_buffers */
struct ddsi_rdata *ddsi_rdata_new (struct ddsi_rmsg *rmsg, uint32_t start, uint32_t endp1, uint32_t submsg_offset, uint32_t payload_offset, uint32_t keyhash_offset);

/** @component receive_buffers */
struct ddsi_rdata *ddsi_rdata_newgap (struct ddsi_rmsg *rmsg);

/** @component receive_buffers */
void ddsi_fragchain_adjust_refcount (struct ddsi_rdata *frag, int adjust);

/** @component receive_buffers */
void ddsi_fragchain_unref (struct ddsi_rdata *frag);


/** @component receive_buffers */
struct ddsi_defrag *ddsi_defrag_new (const struct ddsrt_log_cfg *logcfg, enum ddsi_defrag_drop_mode drop_mode, uint32_t max_samples);

/** @component receive_buffers */
void ddsi_defrag_free (struct ddsi_defrag *defrag);

/** @component receive_buffers */
struct ddsi_rsample *ddsi_defrag_rsample (struct ddsi_defrag *defrag, struct ddsi_rdata *rdata, const struct ddsi_rsample_info *sampleinfo);

/** @component receive_buffers */
void ddsi_defrag_notegap (struct ddsi_defrag *defrag, ddsi_seqno_t min, ddsi_seqno_t maxp1);

/** @component receive_buffers */
enum ddsi_defrag_nackmap_result ddsi_defrag_nackmap (struct ddsi_defrag *defrag, ddsi_seqno_t seq, uint32_t maxfragnum, struct ddsi_fragment_number_set_header *map, uint32_t *mapbits, uint32_t maxsz);

/** @component receive_buffers */
void ddsi_defrag_prune (struct ddsi_defrag *defrag, ddsi_guid_prefix_t *dst, ddsi_seqno_t min);

/** @component receive_buffers */
struct ddsi_reorder *ddsi_reorder_new (const struct ddsrt_log_cfg *logcfg, enum ddsi_reorder_mode mode, uint32_t max_samples, bool late_ack_mode);

/** @component receive_buffers */
void ddsi_reorder_free (struct ddsi_reorder *r);

/** @component receive_buffers */
struct ddsi_rsample *ddsi_reorder_rsample_dup_first (struct ddsi_rmsg *rmsg, struct ddsi_rsample *rsampleiv);

/** @component receive_buffers */
struct ddsi_rdata *ddsi_rsample_fragchain (struct ddsi_rsample *rsample);

/** @component receive_buffers */
ddsi_reorder_result_t ddsi_reorder_rsample (struct ddsi_rsample_chain *sc, struct ddsi_reorder *reorder, struct ddsi_rsample *rsampleiv, int *refcount_adjust, int delivery_queue_full_p);

/** @component receive_buffers */
ddsi_reorder_result_t ddsi_reorder_gap (struct ddsi_rsample_chain *sc, struct ddsi_reorder *reorder, struct ddsi_rdata *rdata, ddsi_seqno_t min, ddsi_seqno_t maxp1, int *refcount_adjust);

/** @component receive_buffers */
void ddsi_reorder_drop_upto (struct ddsi_reorder *reorder, ddsi_seqno_t maxp1); // drops [1,maxp1); next_seq' = maxp1

/** @component receive_buffers */
int ddsi_reorder_wantsample (const struct ddsi_reorder *reorder, ddsi_seqno_t seq);

/** @component receive_buffers */
unsigned ddsi_reorder_nackmap (const struct ddsi_reorder *reorder, ddsi_seqno_t base, ddsi_seqno_t maxseq, struct ddsi_sequence_number_set_header *map, uint32_t *mapbits, uint32_t maxsz, int notail);

/** @component receive_buffers */
ddsi_seqno_t ddsi_reorder_next_seq (const struct ddsi_reorder *reorder);

/** @component receive_buffers */
void ddsi_reorder_set_next_seq (struct ddsi_reorder *reorder, ddsi_seqno_t seq);


/** @component receive_buffers */
struct ddsi_dqueue *ddsi_dqueue_new (const char *name, const struct ddsi_domaingv *gv, uint32_t max_samples, ddsi_dqueue_handler_t handler, void *arg);

/** @component receive_buffers */
bool ddsi_dqueue_start (struct ddsi_dqueue *q);

/** @component receive_buffers */
void ddsi_dqueue_free (struct ddsi_dqueue *q);

/** @component receive_buffers */
bool ddsi_dqueue_enqueue_deferred_wakeup (struct ddsi_dqueue *q, struct ddsi_rsample_chain *sc, ddsi_reorder_result_t rres);

/** @component receive_buffers */
void ddsi_dqueue_enqueue_trigger (struct ddsi_dqueue *q);

/** @component receive_buffers */
void ddsi_dqueue_enqueue (struct ddsi_dqueue *q, struct ddsi_rsample_chain *sc, ddsi_reorder_result_t rres);

/** @component receive_buffers */
void ddsi_dqueue_enqueue1 (struct ddsi_dqueue *q, const ddsi_guid_t *rdguid, struct ddsi_rsample_chain *sc, ddsi_reorder_result_t rres);

/** @component receive_buffers */
void ddsi_dqueue_enqueue_callback (struct ddsi_dqueue *q, ddsi_dqueue_callback_t cb, void *arg);

/** @component receive_buffers */
int ddsi_dqueue_is_full (struct ddsi_dqueue *q);

/** @component receive_buffers */
void ddsi_dqueue_wait_until_empty_if_full (struct ddsi_dqueue *q);


/** @component receive_buffers */
void ddsi_defrag_stats (struct ddsi_defrag *defrag, uint64_t *discarded_bytes);

/** @component receive_buffers */
void ddsi_reorder_stats (struct ddsi_reorder *reorder, uint64_t *discarded_bytes);

#if defined (__cplusplus)
}
#endif

#endif /* DDSI__RADMIN_H */

/*
ddsi_defrag_iv：用于表示数据重组过程中的一个区间，包含最小值和最大值，以及指向该区间中第一个和最后一个数据片段的指针。

ddsi_rsample：用于表示一个样本，其中包含两种用途的联合体。在重组模式下，它包含了一个区间树（fragtree）和一些其他的信息，例如最后一个片段（lastfrag）、样本信息（sampleinfo）和序列号（seq）。
              在重新排序模式下，它包含了一些与重新排序相关的信息。

ddsi_defrag：用于管理数据重组过程的结构体，包含了样本树（sampletree）、最大样本指针（max_sample）、样本数量、最大样本数量、丢弃模式、丢弃的字节数、日志配置和跟踪标志等信息。


ddsi_rsample_chain_elem 和 ddsi_rsample_chain：用于表示重新排序过程中的样本链，其中链元素包含了指向片段链的指针、下一个链元素的指针和样本信息。
*/