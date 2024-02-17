// Copyright(c) 2023 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "dds/version.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/log.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "ddsi__discovery_addrset.h"
#include "ddsi__participant.h"
#include "ddsi__tran.h"
#include "ddsi__addrset.h"

void ddsi_interface_set_init (ddsi_interface_set_t *intfs)
{
  for (size_t i = 0; i < sizeof (intfs->xs) / sizeof (intfs->xs[0]); i++)
    intfs->xs[i] = false;
}

bool ddsi_include_multicast_locator_in_discovery (const struct ddsi_domaingv *gv)
{
#ifdef DDS_HAS_SSM
  /* Note that if the default multicast address is an SSM address,
     we will simply advertise it. The recipients better understand
     it means the writers will publish to address and the readers
     favour SSM. */
  if (ddsi_is_ssm_mcaddr (gv, &gv->loc_default_mc))
    return (gv->config.allowMulticast & DDSI_AMC_SSM) != 0;
  else
    return (gv->config.allowMulticast & DDSI_AMC_ASM) != 0;
#else
  return (gv->config.allowMulticast & DDSI_AMC_ASM) != 0;
#endif
}

static void allowmulticast_aware_add_to_addrset (const struct ddsi_domaingv *gv, uint32_t allow_multicast, struct ddsi_addrset *as, const ddsi_xlocator_t *loc)
{
#ifdef DDS_HAS_SSM
  if (ddsi_is_ssm_mcaddr (gv, &loc->c))
  {
    if (!(allow_multicast & DDSI_AMC_SSM))
      return;
  }
  else if (ddsi_is_mcaddr (gv, &loc->c))
  {
    if (!(allow_multicast & DDSI_AMC_ASM))
      return;
  }
#else
  if (ddsi_is_mcaddr (gv, &loc->c) && !(allow_multicast & DDSI_AMC_ASM))
    return;
#endif
  ddsi_add_xlocator_to_addrset (gv, as, loc);
}

static void addrset_from_locatorlists_add_one (struct ddsi_domaingv const * const gv, const ddsi_locator_t *loc, struct ddsi_addrset *as, ddsi_interface_set_t *intfs, bool *direct)
{
  size_t interf_idx;
  switch (ddsi_is_nearby_address (gv, loc, (size_t) gv->n_interfaces, gv->interfaces, &interf_idx))
  {
    case DNAR_SELF:
    case DNAR_LOCAL:
      // if it matches an interface, use that one and record that this is a
      // directly connected interface: those will then all be possibilities
      // for transmitting multicasts (assuming capable, allowed, &c.)
      assert (interf_idx < MAX_XMIT_CONNS);
      ddsi_add_xlocator_to_addrset (gv, as, &(const ddsi_xlocator_t) {
        .conn = gv->xmit_conns[interf_idx],
        .c = *loc });
      intfs->xs[interf_idx] = true;
      *direct = true;
      break;
    case DNAR_DISTANT:
      // If DONT_ROUTE is set and there is no matching interface, then presumably
      // one would not be able to reach this address.
      if (!gv->config.dontRoute)
      {
        // Pick the first selected interface that isn't link-local or loopback
        // (maybe it matters, maybe not, but it doesn't make sense to assign
        // a transmit socket for a local interface to a distant host).  If none
        // exists, skip the address.
        for (int i = 0; i < gv->n_interfaces; i++)
        {
          // do not use link-local or loopback interfaces transmit conn for distant nodes
          if (gv->interfaces[i].link_local || gv->interfaces[i].loopback)
            continue;
          ddsi_add_xlocator_to_addrset (gv, as, &(const ddsi_xlocator_t) {
            .conn = gv->xmit_conns[i],
            .c = *loc });
          break;
        }
      }
      break;
    case DNAR_UNREACHABLE:
      break;
  }
}
//从广告的单播和多播定位器列表中构建一个地址集，确保选择适当的网络接口，以便在DDS系统中实现正确的通信。
struct ddsi_addrset *ddsi_addrset_from_locatorlists (const struct ddsi_domaingv *gv, const ddsi_locators_t *uc, const ddsi_locators_t *mc, const ddsi_locator_t *srcloc, const ddsi_interface_set_t *inherited_intfs)
{
  //初始化一个新的地址集。
  struct ddsi_addrset *as = ddsi_new_addrset ();
  //创建一个接口集合 intfs。
  ddsi_interface_set_t intfs;
  //初始化接口集合。创建一个接口集合，并初始化为全假（所有接口都未启用）
  ddsi_interface_set_init (&intfs);

  // if all interfaces are loopback, or all locators in uc are loopback, we're cool with loopback addresses
  //检查是否允许使用 loopback 地址，并根据配置和广告的定位器信息判断是否允许。如果允许，则设置 allow_loopback 为 true。
  //这是一个块级作用域，包含两个布尔变量 a 和 b 的初始化。首先，通过循环检查所有系统接口是否都是环回地址，将结果存储在变量 a 中。接着，
  //通过循环检查广播定位器列表中的地址是否为环回地址，将结果存储在变量 b 中。最后，allow_loopback 被设置为 a 和 b 的逻辑或运算结果。
  bool allow_loopback;
  {
    bool a = true;
    for (int i = 0; i < gv->n_interfaces && a; i++)
      if (!gv->interfaces[i].loopback)
        a = false;
    bool b = true;
    // FIXME: what about the cases where SEDP gives just a loopback address, but the proxypp is known to be on a remote node?
    for (struct ddsi_locators_one *l = uc->first; l != NULL && b; l = l->next)
      b = ddsi_is_loopbackaddr (gv, &l->loc);
    allow_loopback = (a || b);
  }

  // if any non-loopback address is identical to one of our own addresses (actual or advertised),
  // assume it is the same machine, in which case loopback addresses may be picked up
  //如果不允许使用环回地址，则检查是否有非环回地址与系统的接口地址相同，如果有，则允许使用环回地址。
  for (struct ddsi_locators_one *l = uc->first; l != NULL && !allow_loopback; l = l->next)
  {
    if (ddsi_is_loopbackaddr (gv, &l->loc))
      continue;
      //就认为当前主机与定位器所在的主机是相邻的，即在同一主机上
    allow_loopback = (ddsi_is_nearby_address (gv, &l->loc, (size_t) gv->n_interfaces, gv->interfaces, NULL) == DNAR_SELF);
  }
  //GVTRACE(" allow_loopback=%d\n", allow_loopback);

//用于标识是否是直连，初始化为假。
  bool direct = false;
  //处理单播地址列表
  for (struct ddsi_locators_one *l = uc->first; l != NULL; l = l->next)
  {
#if 0
    {
      char buf[DDSI_LOCSTRLEN];
      ddsi_locator_to_string_no_port (buf, sizeof (buf), &l->loc);
      GVTRACE("%s: ignore %d loopback %d\n", buf, l->loc.tran->m_ignore, ddsi_is_loopbackaddr (gv, &l->loc));
    }
#endif
    // skip unrecognized ones, as well as loopback ones if not on the same host
    //- 如果不允许使用环回地址且当前定位器是环回地址，则跳过，不处理该定位器。
    if (!allow_loopback && ddsi_is_loopbackaddr (gv, &l->loc))
      continue;

//复制当前定位器的地址到 loc 变量。
    ddsi_locator_t loc = l->loc;

    // if the advertised locator matches our own external locator, than presumably
    // it is the same machine and should be addressed using the actual interface
    // address
    //用于标识当前地址是否是外部地址且与系统的接口地址相同。
    


    bool extloc_of_self = false;
    //遍历系统的接口地址，检查当前地址是否与系统的外部接口地址相同。如果相同，则将当前地址转换为系统的内部接口地址
    for (int i = 0; i < gv->n_interfaces; i++)
    {
      if (loc.kind == gv->interfaces[i].loc.kind && memcmp (loc.address, gv->interfaces[i].extloc.address, sizeof (loc.address)) == 0)
      {
        memcpy (loc.address, gv->interfaces[i].loc.address, sizeof (loc.address));
        extloc_of_self = true;
        break;
      }
    }
  //如果当前地址是 IPv4 UDP 地址，且存在外部地址掩码，则进行地址转换。转换的目的是将定位器地址转换为与系统内部接口地址在同一子网上的地址。
    if (!extloc_of_self && loc.kind == DDSI_LOCATOR_KIND_UDPv4 && gv->extmask.kind != DDSI_LOCATOR_KIND_INVALID)
    {
      /* If the examined locator is in the same subnet as our own
         external IP address, this locator will be translated into one
         in the same subnet as our own local ip and selected. */
      assert (gv->n_interfaces == 1); // gv->extmask: the hack is only supported if limited to a single interface
      /*
        

            这部分代码是在遍历系统的接口地址（gv->interfaces）时，检查当前处理的单播地址是否与系统的外部接口地址相同。如果找到相同的外部接口地址，就将当前处理的地址转换为系统内部接口地址。
在实际网络中，有时候同一台机器可能有多个网络接口，每个接口都有一个唯一的地址。外部接口地址通常是公共可路由的地址，
而内部接口地址则可能是局域网地址。这个检查和转换的目的是确保在与其他机器通信时使用内部接口地址，而不是外部接口地址，以避免网络路由问题。
假设一台机器有两个网络接口，一个连接到局域网（内部接口），另一个连接到互联网（外部接口）。

内部接口地址（局域网）可能是：192.168.1.2
外部接口地址（互联网）可能是：203.0.113.5
如果这台机器想要与同一局域网内的其他机器通信，最好使用内部接口地址（192.168.1.2），因为这样的通信会更加直接和可靠，不需要经过路由器等设备。

而如果这台机器要与互联网上的其他机器通信，可能需要使用外部接口地址（203.0.113.5），因为这是唯一能够从互联网上访问到这台机器的地址。

在这个例子中，通过检查和转换地址，代码确保在处理单播地址时，使用内部接口地址与局域网内的机器通信，而使用外部接口地址与互联网上的机器通信。

假设我们有以下网络设置：

外部接口地址（互联网）：203.0.113.5

外部接口子网掩码：255.255.255.0

内部接口地址（局域网）：192.168.1.2

内部接口子网掩码：255.255.255.0

假设我们的目标是根据这些设置，将外部接口地址（203.0.113.5）转换为内部接口所在的子网，以确保在处理单播地址时使用局域网内的地址。

代码中的这段部分就是实现这一目标的。

首先，它检查当前地址是否不是自身的外部地址且是IPv4 UDP地址。如果是，而且外部地址掩码有效，那么它执行以下操作：

从当前地址中提取 IPv4 地址的网络部分，即排除掉主机部分。
获取自身内部接口的 IPv4 地址（ownip）和外部接口的 IPv4 地址（extip）以及外部接口的子网掩码（extmask）。
判断当前地址是否位于与自身外部接口相同的子网中。
如果是，将当前地址的网络部分替换为自身内部接口的 IPv4 地址的网络部分，实现了将外部地址转换为内部地址的操作。
这样，通过检查并转换地址，代码确保在处理单播地址时，使用内部接口地址与局域网内的机器通信。


外部接口地址（extip）: 203.0.113.5
外部接口子网掩码（extmask）: 255.255.255.0
内部接口地址（ownip）: 192.168.1.1
现在有一个待处理的IPv4地址为 203.0.113.25。我们会按照上述步骤进行判断和转换：

提取IPv4地址 203.0.113.25 的网络部分：

markdown
Copy code
203.0.113.25     (IPv4地址)
255.255.255.0    (子网掩码)
----------------
203.0.113.0      (网络部分)
判断是否与自身外部接口在相同的子网中：

由于网络部分 203.0.113.0 与外部接口地址的网络部分 203.0.113.5 相同，判断为真。
如果判断为真，将当前地址的网络部分替换为自身内部接口的IPv4地址的网络部分：

markdown
Copy code
192.168.1.1      (内部接口地址的网络部分)
203.0.113.25     (原始IPv4地址)
----------------
192.168.1.25     (替换后的IPv4地址)
在这个例子中，203.0.113.25 通过判断与自身外部接口在相同的子网中，然后将其网络部分替换为内部接口的IPv4地址的网络部分，最终转换为 192.168.1.25。这就是将外部地址转换为内部地址的操作。
      */
      struct in_addr tmp4 = *((struct in_addr *) (loc.address + 12));
      const struct in_addr ownip = *((struct in_addr *) (gv->interfaces[0].loc.address + 12));
      const struct in_addr extip = *((struct in_addr *) (gv->interfaces[0].extloc.address + 12));
      const struct in_addr extmask = *((struct in_addr *) (gv->extmask.address + 12));

      if ((tmp4.s_addr & extmask.s_addr) == (extip.s_addr & extmask.s_addr))
      {
        /* translate network part of the IP address from the external
           one to the internal one */
        tmp4.s_addr = (tmp4.s_addr & ~extmask.s_addr) | (ownip.s_addr & extmask.s_addr);
        memcpy (loc.address + 12, &tmp4, 4);
      }
    }
  //将当前地址添加到地址集合
    addrset_from_locatorlists_add_one (gv, &loc, as, &intfs, &direct);
  }
//如果地址集合为空且源地址不为空，则将源地址也添加到地址集合。
  if (ddsi_addrset_empty (as) && !ddsi_is_unspec_locator (srcloc))
  {
    //GVTRACE("add srcloc\n");
    // FIXME: conn_read should provide interface information in source address
    //GVTRACE (" add-srcloc");
    addrset_from_locatorlists_add_one (gv, srcloc, as, &intfs, &direct);
  }
//如果地址集合仍为空且存在继承的接口信息，则使用继承的接口信息。
  if (ddsi_addrset_empty (as) && inherited_intfs)
  {
    // implies no interfaces enabled in "intfs" yet -- just use whatever
    // we inherited for the purposes of selecting multicast addresses
    assert (!direct);
    for (int i = 0; i < gv->n_interfaces; i++)
      assert (!intfs.xs[i]);
    //GVTRACE (" using-inherited-intfs");
    intfs = *inherited_intfs;
  }
  else if (!direct && gv->config.multicast_ttl > 1)
  {
    //GVTRACE("assuming multicast routing works\n");
    // if not directly connected but multicast TTL allows routing,
    // assume any non-local interface will do
    //GVTRACE (" enabling-non-loopback/link-local");
    for (int i = 0; i < gv->n_interfaces; i++)
    {
      assert (!intfs.xs[i]);
      intfs.xs[i] = !(gv->interfaces[i].link_local || gv->interfaces[i].loopback);
    }
  }

#if 0
  GVTRACE("enabled interfaces for multicast:");
  for (int i = 0; i < gv->n_interfaces; i++)
  {
    if (intfs[i])
      GVTRACE(" %s(%d)", gv->interfaces[i].name, gv->interfaces[i].mc_capable);
  }
  GVTRACE("\n");
#endif

  for (struct ddsi_locators_one *l = mc->first; l != NULL; l = l->next)
  {
    for (int i = 0; i < gv->n_interfaces; i++)
    {
      if (intfs.xs[i] && gv->interfaces[i].mc_capable)
      {
        const ddsi_xlocator_t loc = {
          .conn = gv->xmit_conns[i],
          .c = l->loc
        };
        if (ddsi_factory_supports (loc.conn->m_factory, loc.c.kind))
          allowmulticast_aware_add_to_addrset (gv, gv->config.allowMulticast, as, &loc);
      }
    }
  }
  return as;
}



/*
假设我们有以下配置和广告的定位器信息：

域状态信息 gv 包含三个网络接口，分别是 Loopback 接口、Ethernet 接口1、Ethernet 接口2。
广告的单播定位器列表 uc 包含两个定位器：LocatorA 和 LocatorB。
广告的多播定位器列表 mc 包含一个定位器：MulticastLocator.
配置和广告的定位器信息如下：

c
Copy code
// 配置：三个网络接口
struct ddsi_interface interfaces[3] = {
    { .name = "Loopback", .loopback = true, .mc_capable = true },
    { .name = "Ethernet1", .loopback = false, .mc_capable = true },
    { .name = "Ethernet2", .loopback = false, .mc_capable = true }
};

// 域状态信息
struct ddsi_domaingv gv = {
    .n_interfaces = 3,
    .interfaces = interfaces,
    // 其他域状态信息的设置
};

// 广告的单播定位器列表
ddsi_locators_t uc = {
    .first = &LocatorA, // 第一个定位器
    .next = &LocatorB,  // 第二个定位器
    // 其他单播定位器的设置
};

// 广告的多播定位器列表
ddsi_locators_t mc = {
    .first = &MulticastLocator, // 唯一的多播定位器
    // 其他多播定位器的设置
};

// 源地址
ddsi_locator_t srcloc = {
    .kind = DDSI_LOCATOR_KIND_UDPv4,
    .address = "192.168.0.1", // 假设源地址是 IPv4 地址
    // 其他源地址信息的设置
};

// 继承的接口集合
ddsi_interface_set_t inherited_intfs = {
    .xs = { true, false, true } // 仅使用 Loopback 和 Ethernet2 接口
};
基于上述情境，调用 ddsi_addrset_from_locatorlists 函数会按照代码逻辑执行以下步骤：

初始化新的地址集 as 和接口集合 intfs。
检查是否允许使用 Loopback 地址，并设置 allow_loopback。
处理单播地址列表 uc，对于每个定位器，根据一些规则（如是否是 Loopback 地址、是否与自身地址相同等）进行处理，并通过 addrset_from_locatorlists_add_one 函数将符合条件的单播地址添加到地址集 as 中。
如果地址集为空，且源地址 srcloc 不是未指定的地址，则将源地址添加到地址集中。
如果地址集为空，且存在继承的接口集合 inherited_intfs，则使用该集合用于选择多播地址。
处理多播地址列表 mc，对于每个定位器，根据接口集合和接口的多播能力选择合适的接口，并将多播地址添加到地址集 as 中。
返回构建好的地址集 as。


interface->loc->addrest
*/

