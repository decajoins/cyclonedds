// Copyright(c) 2006 to 2022 ZettaScale Technology and others
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

#include "dds/ddsrt/cdtors.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsi/ddsi_entity.h"
#include "dds/ddsi/ddsi_participant.h"
#include "dds/ddsi/ddsi_proxy_endpoint.h"
#include "dds/ddsi/ddsi_thread.h"
#include "dds/ddsi/ddsi_plist.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_entity_index.h"
#include "dds/version.h"
#include "dds__init.h"
#include "dds__domain.h"
#include "dds__participant.h"
#include "dds__builtin.h"
#include "dds__qos.h"

DECL_ENTITY_LOCK_UNLOCK (dds_participant)

#define DDS_PARTICIPANT_STATUS_MASK    (0u)

static int cmp_ktopic_name (const void *a, const void *b)
{
  return strcmp (a, b);
}

const ddsrt_avl_treedef_t participant_ktopics_treedef = DDSRT_AVL_TREEDEF_INITIALIZER_INDKEY(offsetof (struct dds_ktopic, pp_ktopics_avlnode), offsetof (struct dds_ktopic, name), cmp_ktopic_name, 0);

static dds_return_t dds_participant_status_validate (uint32_t mask)
{
  return (mask & ~DDS_PARTICIPANT_STATUS_MASK) ? DDS_RETCODE_BAD_PARAMETER : DDS_RETCODE_OK;
}

static dds_return_t dds_participant_delete (dds_entity *e) ddsrt_nonnull_all;

static dds_return_t dds_participant_delete (dds_entity *e)
{
  dds_return_t ret;
  assert (dds_entity_kind (e) == DDS_KIND_PARTICIPANT);

  /* ktopics & topics are children and therefore must all have been deleted by the time we get here */
  assert (ddsrt_avl_is_empty (&((struct dds_participant *) e)->m_ktopics));

  ddsi_thread_state_awake (ddsi_lookup_thread_state (), &e->m_domain->gv);
  if ((ret = ddsi_delete_participant (&e->m_domain->gv, &e->m_guid)) < 0)
    DDS_CERROR (&e->m_domain->gv.logconfig, "dds_participant_delete: internal error %"PRId32"\n", ret);
  ddsi_thread_state_asleep (ddsi_lookup_thread_state ());
  return DDS_RETCODE_OK;
}

static dds_return_t dds_participant_qos_set (dds_entity *e, const dds_qos_t *qos, bool enabled)
{
  /* note: e->m_qos is still the old one to allow for failure here */
  if (enabled)
  {
    struct ddsi_participant *pp;
    ddsi_thread_state_awake (ddsi_lookup_thread_state (), &e->m_domain->gv);
    if ((pp = ddsi_entidx_lookup_participant_guid (e->m_domain->gv.entity_index, &e->m_guid)) != NULL)
    {
      ddsi_plist_t plist;
      ddsi_plist_init_empty (&plist);
      plist.qos.present = plist.qos.aliased = qos->present;
      plist.qos = *qos;
      ddsi_update_participant_plist (pp, &plist);
    }
    ddsi_thread_state_asleep (ddsi_lookup_thread_state ());
  }
  return DDS_RETCODE_OK;
}

const struct dds_entity_deriver dds_entity_deriver_participant = {
  .interrupt = dds_entity_deriver_dummy_interrupt,
  .close = dds_entity_deriver_dummy_close,
  .delete = dds_participant_delete,
  .set_qos = dds_participant_qos_set,
  .validate_status = dds_participant_status_validate,
  .create_statistics = dds_entity_deriver_dummy_create_statistics,
  .refresh_statistics = dds_entity_deriver_dummy_refresh_statistics
};

dds_entity_t dds_create_participant (const dds_domainid_t domain, const dds_qos_t *qos, const dds_listener_t *listener)
{
  // 声明变量和指针
  dds_domain *dom;
  dds_entity_t ret;
  ddsi_guid_t guid;
  dds_participant * pp;
  ddsi_plist_t plist;
  dds_qos_t *new_qos = NULL;
  const char *config = "";

  // 确保DDS实例已经初始化：这行代码调用 dds_init() 函数来确保DDS实例已经初始化。如果初始化失败，则跳转到错误处理标签 err_dds_init。
  /* Make sure DDS instance is initialized. */
  if ((ret = dds_init ()) < 0)
    goto err_dds_init;

  // 获取环境变量的值：该代码通过调用 ddsrt_getenv() 函数获取名为 CYCLONEDDS_URI 的环境变量的值，并将其存储在 config 变量中
  (void) ddsrt_getenv ("CYCLONEDDS_URI", &config);

  // 创建域：这行代码调用 dds_domain_create_internal() 函数来创建一个域。它使用传入的 domain、config 和其他参数来创建域对象，
  // 并将结果存储在 dom 变量中。如果创建失败，则跳转到错误处理标签 err_domain_create
  if ((ret = dds_domain_create_internal (&dom, domain, true, config)) < 0)  ////deep into
    goto err_domain_create;


  // 创建并合并质量服务设置：这些代码创建一个新的质量服务设置对象 new_qos，并根据传入的 qos 和默认本地设置进行合并。dds_create_qos() 创建新的质量服务设置对象，
  // ddsi_xqos_mergein_missing() 用于合并质量服务设置，dds_apply_entity_naming() 用于应用实体命名规则。
  new_qos = dds_create_qos (); //创建新的质量服务设置对象
  if (qos != NULL)
    ddsi_xqos_mergein_missing (new_qos, qos, DDS_PARTICIPANT_QOS_MASK);  //qos合并进入new_qos
  dds_apply_entity_naming(new_qos, NULL, &dom->gv);  //用于应用实体命名规则,根据命名模式和配置为DDS实体的QoS设置生成一个唯一的实体名称，并将其应用到相应的QoS对象中。
  
  //可以将 dom->gv.default_local_xqos_pp 中的选项合并到 new_qos 中，确保在 new_qos 中存在所有在 dom->gv.default_local_xqos_pp 中出现的选项，同时不影响 new_qos 中已存在的选项。
  ddsi_xqos_mergein_missing (new_qos, &dom->gv.default_local_xqos_pp, ~(uint64_t)0);   

  //验证质量服务设置：ddsi_xqos_valid用于验证设置的有效性，检查日志配置，然后，检查活性设置是否为 DDS_LIVELINESS_AUTOMATIC。如果验证失败，则跳转到错误处理标签 err_qos_validation。
  if ((ret = ddsi_xqos_valid (&dom->gv.logconfig, new_qos)) < 0)
    goto err_qos_validation;
  // generic validation code will check lease duration, we only need to check kind
  // is what we insist on
  if (new_qos->liveliness.kind != DDS_LIVELINESS_AUTOMATIC)//要求参与者以自动方式处理活动状态。这是系统对质量服务设置的特定要求之一，以确保一致的行为和交互，以确保参与者的活动状态以自动方式管理
  {
    ret = DDS_RETCODE_BAD_PARAMETER;
    goto err_qos_validation;
  }

  /*参与者实体配置：
  ddsi_plist_fini(&plist);：该步骤执行清理操作，释放先前配置的参与者实体的资源。它对应于DDS实体的清理操作，以确保在重新配置或销毁实体之前，先释放之前的配置。
  ddsi_plist_init_empty (&plist);：这一步骤初始化一个空的plist（参与者实体配置）对象。它创建一个新的参与者实体配置，并将其设置为初始状态，没有任何具体配置值。
  ddsi_xqos_mergein_missing (&plist.qos, new_qos, ~(uint64_t)0);：这一步骤将新的QoS配置合并到参与者实体的配置中。它使用ddsi_xqos_mergein_missing函数将new_qos（新的QoS配置）与当前参与者实体配置的QoS进行合并。合并操作会将new_qos中未配置的选项合并到参与者实体配置中，确保参与者实体具有完整的配置信息。
  通过这三个步骤，先清理旧的配置，然后初始化一个空的配置对象，并将新的QoS配置合并到参与者实体的配置中，完成了对参与者实体的重新配置过程
  */
  ddsi_plist_fini(&plist);
  ddsi_plist_init_empty (&plist);
  ddsi_xqos_mergein_missing (&plist.qos, new_qos, ~(uint64_t)0);

  //它通常表示当前线程将进入休眠或等待状态，等待某个事件的发生。在这个特定的代码片段中，它可能表示参与者的创建过程需要等待某个条件满足，例如其他资源的初始化或配置完成。
  //这个函数的目的是将线程状态从休眠状态切换到唤醒状态，并通过全局变量向其他部分发送通知，以确保线程可以执行相应的任务和事件。这在DDS实现中是非常重要的，因为它确保了数据交换和其他关键操作的及时处理和协调。
  ddsi_thread_state_awake (ddsi_lookup_thread_state (), &dom->gv);
  ret = ddsi_new_participant (&guid, &dom->gv, 0, &plist); //deep into
  ddsi_thread_state_asleep (ddsi_lookup_thread_state ());//它将当前线程的状态设置为睡眠状态。
  ddsi_plist_fini (&plist);
  if (ret < 0)
  {
    ret = DDS_RETCODE_ERROR;
    goto err_new_participant;
  }


  /*
    pp = dds_alloc(sizeof(*pp));：使用 dds_alloc 函数为 pp 分配内存，pp 是指向 dds_participant 结构体的指针。
    dds_entity_init：通过调用 dds_entity_init 函数对参与者实体进行初始化。它会将参与者实体的成员变量设置为相应的值，包括实体类型（DDS_KIND_PARTICIPANT）、是否可删除、是否可释放等。
    pp->m_entity.m_guid = guid;：将参与者实体的全局唯一标识符（GUID）设置为变量 guid 的值。
    pp->m_entity.m_iid = ddsi_get_entity_instanceid(&dom->gv, &guid);：通过调用 ddsi_get_entity_instanceid 函数获取参与者实体的实例标识符（IID），并将其设置为参与者实体的 m_iid 成员变量的值。
    pp->m_entity.m_domain = dom;：将参与者实体的域（Domain）设置为变量 dom 的值。
    pp->m_builtin_subscriber = 0;：将参与者实体的内置订阅者标识符设置为0。
    ddsrt_avl_init(&participant_ktopics_treedef, &pp->m_ktopics);：使用 ddsrt_avl_init 函数初始化参与者的主题（Topics）列表。
    ddsrt_mutex_lock(&dom->m_entity.m_mutex);：对域实体的互斥锁进行加锁，以确保在添加参与者到域的范围时是线程安全的。
    dds_entity_register_child(&dom->m_entity, &pp->m_entity);：将参与者实体注册为域实体的子实体。
    ddsrt_mutex_unlock(&dom->m_entity.m_mutex);：释放域实体的互斥锁。
    dds_entity_init_complete(&pp->m_entity);：表示参与者实体的初始化已经完成。
    dds_entity_unpin_and_drop_ref(&dom->m_entity);：取消对域实体的引用并释放相关资源
    dds_entity_unpin_and_drop_ref(&dds_global.m_entity);：取消对全局实体的引用并释放相关资源。
    return ret;：返回参与者创建过程中的结果（错误码或成功标识）。
    总的来说，这段代码完成了参与者实体的创建过程，包括分配内存、初始化实体、设置成员变量、注册为域的子实体等操作。同时，还涉及到资源的引用计数、锁的使用以及错误处理。
  */
  pp = dds_alloc (sizeof (*pp));
  if ((ret = dds_entity_init (&pp->m_entity, &dom->m_entity, DDS_KIND_PARTICIPANT, false, true, new_qos, listener, DDS_PARTICIPANT_STATUS_MASK)) < 0)
    goto err_entity_init;

  pp->m_entity.m_guid = guid;
  pp->m_entity.m_iid = ddsi_get_entity_instanceid (&dom->gv, &guid);
  pp->m_entity.m_domain = dom;
  pp->m_builtin_subscriber = 0;
  ddsrt_avl_init (&participant_ktopics_treedef, &pp->m_ktopics);

  /* Add participant to extent */
  ddsrt_mutex_lock (&dom->m_entity.m_mutex);
  dds_entity_register_child (&dom->m_entity, &pp->m_entity);
  ddsrt_mutex_unlock (&dom->m_entity.m_mutex);

  dds_entity_init_complete (&pp->m_entity);
  /* drop temporary extra ref to domain, dds_init */
  dds_entity_unpin_and_drop_ref (&dom->m_entity);
  dds_entity_unpin_and_drop_ref (&dds_global.m_entity);
  return ret;

err_entity_init:
  dds_free (pp);
err_new_participant:
err_qos_validation:
  dds_delete_qos (new_qos);
  dds_entity_unpin_and_drop_ref (&dom->m_entity);
err_domain_create:
  dds_entity_unpin_and_drop_ref (&dds_global.m_entity);
err_dds_init:
  return ret;
}

dds_return_t dds_lookup_participant (dds_domainid_t domain_id, dds_entity_t *participants, size_t size)
{
  dds_return_t ret;

  if ((participants != NULL && (size == 0 || size >= INT32_MAX)) || (participants == NULL && size != 0))
    return DDS_RETCODE_BAD_PARAMETER;

  if (participants)
    participants[0] = 0;

  if ((ret = dds_init ()) < 0)
    return ret;

  ret = 0;
  struct dds_domain *dom;
  ddsrt_mutex_lock (&dds_global.m_mutex);
  if ((dom = dds_domain_find_locked (domain_id)) != NULL)
  {
    ddsrt_avl_iter_t it;
    for (dds_entity *e = ddsrt_avl_iter_first (&dds_entity_children_td, &dom->m_entity.m_children, &it); e != NULL; e = ddsrt_avl_iter_next (&it))
    {
      if ((size_t) ret < size)
        participants[ret] = e->m_hdllink.hdl;
      ret++;
    }
  }
  ddsrt_mutex_unlock (&dds_global.m_mutex);
  dds_entity_unpin_and_drop_ref (&dds_global.m_entity);
  return ret;
}
