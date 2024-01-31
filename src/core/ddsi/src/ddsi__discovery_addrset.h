// Copyright(c) 2023 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#ifndef DDSI__DISCOVERY_ADDRSET_H
#define DDSI__DISCOVERY_ADDRSET_H

#include "dds/ddsi/ddsi_domaingv.h" // FIXME: MAX_XMIT_CONNS

#if defined (__cplusplus)
extern "C" {
#endif

//ddsi_interface_set_t 结构体：该结构体定义了一个接口集合，其中 xs 数组用于表示每个可能的传输连接是否可用。
typedef struct ddsi_interface_set {
  bool xs[MAX_XMIT_CONNS];
} ddsi_interface_set_t;

/** @brief Initializes an interface set to all-false
 * @component discovery
 * 
 * @param[out] intfs interface set to initialize */
// /该函数用于初始化一个接口集合，将其所有成员都设置为 false，即所有传输连接都被视为不可用。
void ddsi_interface_set_init (ddsi_interface_set_t *intfs)
  ddsrt_nonnull_all;

/** @brief Whether multicast locators are to be included in discovery information for this domain
 * @component discovery
 *
 * @param[in] gv domain
 * @return true iff multicast locators are to be included */
//该函数用于确定在发现信息中是否应包含多播定位器。检查域（domain）的配置信息，判断是否应该在发现信息中包含多播定位器。返回 true 表示应该包含，否则返回 false。
bool ddsi_include_multicast_locator_in_discovery (const struct ddsi_domaingv *gv)
  ddsrt_nonnull_all;

/** @brief Constructs a new address set from uni- and multicast locators received in SPDP or SEDP
 * @component discovery
 *
 * The construction process uses heuristics for determining which interfaces appear to be applicable for and uses
 * this information to set (1) the transmit sockets and (2) choose the interfaces with which to associate multicast
 * addresses.
 *
 * Loopback addresses are accepted if it can be determined that they originate on the same machine:
 * - if all enabled interfaces are loopback interfaces, the peer must be on the same host (this ought to be cached)
 * - if all advertised addresses are loopback addresses
 * - if there is a non-unicast address that matches one of the (enabled) addresses of the host
 *
 * Unicast addresses are matched against interface addresses to determine whether the address is likely to be
 * reachable without any routing. If so, the address is assigned to the interface and the interface is marked as
 * "enabled" for the purposes of multicast handling. If not, it is associated with the first enabled non-loopback
 * interface on the assumption that unicast routing works fine (but the interface is not "enabled" for multicast
 * handling).
 *
 * Multicast addresses are added only for interfaces that are "enabled" based on unicast processing. If none are
 * and the source locator matches an interface, it will enable that interface.
 *
 * @param[in] gv domain state, needed for interfaces, transports, tracing
 * @param[in] uc list of advertised unicast locators
 * @param[in] mc list of advertised multicast locators
 * @param[in] srcloc source address for discovery packet, or "invalid"
 * @param[in,out] inherited_intfs set of applicable interfaces, may be NULL
 *
 * @return new addrset, possibly empty */
//该函数用于从 SPDP（Simple Participant Discovery Protocol） 或 SEDP（Simple Endpoint Discovery Protocol） 接收到的单播和多播定位器列表构建新的地址集。
//函数根据一些启发式方法确定哪些接口可能适用，并使用此信息设置传输套接字。它还会根据一些规则处理回环地址和单播地址，以构建新的地址集。
//函数的参数包括域状态信息、广告的单播和多播定位器列表、发现数据包的源地址，以及继承的接口集合。函数返回一个新的地址集
struct ddsi_addrset *ddsi_addrset_from_locatorlists (const struct ddsi_domaingv *gv, const ddsi_locators_t *uc, const ddsi_locators_t *mc, const ddsi_locator_t *srcloc, const ddsi_interface_set_t *inherited_intfs)
  ddsrt_attribute_warn_unused_result ddsrt_nonnull((1,2,3,4));

#if defined (__cplusplus)
}
#endif

#endif /* DDSI__DISCOVERY_ADDRSET_H */
