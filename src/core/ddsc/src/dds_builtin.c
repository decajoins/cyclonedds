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
#include "dds/ddsrt/string.h"
#include "dds/ddsi/ddsi_entity.h"
#include "dds/ddsi/ddsi_topic.h"
#include "dds/ddsi/ddsi_endpoint.h"
#include "dds/ddsi/ddsi_thread.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsi/ddsi_plist.h"
#include "dds__init.h"
#include "dds__domain.h"
#include "dds__participant.h"
#include "dds__types.h"
#include "dds__builtin.h"
#include "dds__entity.h"
#include "dds__subscriber.h"
#include "dds__qos.h"
#include "dds__topic.h"
#include "dds__write.h"
#include "dds__writer.h"
#include "dds__whc_builtintopic.h"
#include "dds__serdata_builtintopic.h"
#include "dds/ddsi/ddsi_qosmatch.h"
#include "dds/ddsi/ddsi_tkmap.h"

dds_qos_t *dds__create_builtin_qos (void)
{
  const char *partition = "__BUILT-IN PARTITION__";
  dds_qos_t *qos = dds_create_qos ();
  dds_qset_durability (qos, DDS_DURABILITY_TRANSIENT_LOCAL);
  dds_qset_presentation (qos, DDS_PRESENTATION_TOPIC, false, false);
  dds_qset_reliability (qos, DDS_RELIABILITY_RELIABLE, DDS_MSECS(100));
  dds_qset_partition (qos, 1, &partition);
  ddsi_xqos_mergein_missing (qos, &ddsi_default_qos_topic, DDS_TOPIC_QOS_MASK);
  dds_qset_data_representation (qos, 1, (dds_data_representation_id_t[]) { DDS_DATA_REPRESENTATION_XCDR1 });
  return qos;
}

static const struct {
  dds_entity_t pseudo_handle;
  const char *name;
  const char *typename;
} builtin_topic_list[] = {
  { DDS_BUILTIN_TOPIC_DCPSPARTICIPANT, DDS_BUILTIN_TOPIC_PARTICIPANT_NAME, "org::eclipse::cyclonedds::builtin::DCPSParticipant" },
  { DDS_BUILTIN_TOPIC_DCPSTOPIC, DDS_BUILTIN_TOPIC_TOPIC_NAME, "org::eclipse::cyclonedds::builtin::DCPSTopic" },
  { DDS_BUILTIN_TOPIC_DCPSPUBLICATION, DDS_BUILTIN_TOPIC_PUBLICATION_NAME, "org::eclipse::cyclonedds::builtin::DCPSPublication" },
  { DDS_BUILTIN_TOPIC_DCPSSUBSCRIPTION, DDS_BUILTIN_TOPIC_SUBSCRIPTION_NAME, "org::eclipse::cyclonedds::builtin::DCPSSubscription" }
};

dds_return_t dds__get_builtin_topic_name_typename (dds_entity_t pseudo_handle, const char **name, const char **typename)
{
  const char *n;
  const char *tn;
  // avoid a search (mostly because we can)
  DDSRT_STATIC_ASSERT (DDS_BUILTIN_TOPIC_DCPSTOPIC == DDS_BUILTIN_TOPIC_DCPSPARTICIPANT + 1 &&
                       DDS_BUILTIN_TOPIC_DCPSPUBLICATION == DDS_BUILTIN_TOPIC_DCPSTOPIC + 1 &&
                       DDS_BUILTIN_TOPIC_DCPSSUBSCRIPTION == DDS_BUILTIN_TOPIC_DCPSPUBLICATION + 1);
  switch (pseudo_handle)
  {
    case DDS_BUILTIN_TOPIC_DCPSPARTICIPANT:
    case DDS_BUILTIN_TOPIC_DCPSTOPIC:
    case DDS_BUILTIN_TOPIC_DCPSPUBLICATION:
    case DDS_BUILTIN_TOPIC_DCPSSUBSCRIPTION: {
      dds_entity_t idx = pseudo_handle - DDS_BUILTIN_TOPIC_DCPSPARTICIPANT;
      n = builtin_topic_list[idx].name;
      tn = builtin_topic_list[idx].typename;
      break;
    }
    default: {
      // no assert: this is also used by some API calls
      return DDS_RETCODE_BAD_PARAMETER;
    }
  }
  if (name)
    *name = n;
  if (typename)
    *typename = tn;
  return 0;
}

dds_entity_t dds__get_builtin_topic_pseudo_handle_from_typename (const char *typename)
{
  for (size_t i = 0; i < sizeof (builtin_topic_list) / sizeof (builtin_topic_list[0]); i++)
  {
    if (strcmp (typename, builtin_topic_list[i].typename) == 0)
      return builtin_topic_list[i].pseudo_handle;
  }
  return DDS_RETCODE_BAD_PARAMETER;
}

dds_entity_t dds__get_builtin_topic (dds_entity_t entity, dds_entity_t topic)
{
  dds_entity_t tp;
  dds_return_t rc;
  dds_entity *e;
  dds_participant *par;

  if ((rc = dds_entity_pin (entity, &e)) < 0)
    return rc;
  if ((par = dds_entity_participant (e)) == NULL)
  {
    dds_entity_unpin (e);
    return DDS_RETCODE_ILLEGAL_OPERATION;
  }

  const char *topic_name;
  struct ddsi_sertype *sertype;
  (void) dds__get_builtin_topic_name_typename (topic, &topic_name, NULL);
  switch (topic)
  {
    case DDS_BUILTIN_TOPIC_DCPSPARTICIPANT:
      sertype = e->m_domain->builtin_participant_type;
      break;
#ifdef DDS_HAS_TOPIC_DISCOVERY
    case DDS_BUILTIN_TOPIC_DCPSTOPIC:
      sertype = e->m_domain->builtin_topic_type;
      break;
#endif
    case DDS_BUILTIN_TOPIC_DCPSPUBLICATION:
      sertype = e->m_domain->builtin_writer_type;
      break;
    case DDS_BUILTIN_TOPIC_DCPSSUBSCRIPTION:
      sertype = e->m_domain->builtin_reader_type;
      break;
    default:
      assert (0);
      dds_entity_unpin (e);
      return DDS_RETCODE_BAD_PARAMETER;
  }

  dds_qos_t *qos = dds__create_builtin_qos ();
  if ((tp = dds_create_topic_impl (par->m_entity.m_hdllink.hdl, topic_name, true, &sertype, qos, NULL, true)) > 0)
  {
    /* keep ownership for built-in sertypes because there are re-used, lifetime for these
       sertypes is bound to domain */
    ddsi_sertype_ref (sertype);
  }
  dds_delete_qos (qos);
  dds_entity_unpin (e);
  return tp;
}

static bool qos_has_resource_limits (const dds_qos_t *qos)
{
  assert (qos->present & DDSI_QP_RESOURCE_LIMITS);
  return (qos->resource_limits.max_samples != DDS_LENGTH_UNLIMITED ||
          qos->resource_limits.max_instances != DDS_LENGTH_UNLIMITED ||
          qos->resource_limits.max_samples_per_instance != DDS_LENGTH_UNLIMITED);
}

bool dds__validate_builtin_reader_qos (const dds_domain *dom, dds_entity_t topic, const dds_qos_t *qos)
{
  if (qos == NULL)
    /* default QoS inherited from topic is ok by definition */
    return true;
  else
  {
    /* failing writes on built-in topics are unwelcome complications, so we simply
       forbid the creation of a reader matching a built-in topics writer that has
       resource limits */
    struct ddsi_local_orphan_writer *bwr;
    switch (topic)
    {
      case DDS_BUILTIN_TOPIC_DCPSPARTICIPANT:
        bwr = dom->builtintopic_writer_participant;
        break;
#ifdef DDS_HAS_TOPIC_DISCOVERY
      case DDS_BUILTIN_TOPIC_DCPSTOPIC:
        bwr = dom->builtintopic_writer_topics;
        break;
#endif
      case DDS_BUILTIN_TOPIC_DCPSPUBLICATION:
        bwr = dom->builtintopic_writer_publications;
        break;
      case DDS_BUILTIN_TOPIC_DCPSSUBSCRIPTION:
        bwr = dom->builtintopic_writer_subscriptions;
        break;
      default:
        assert (0);
        return false;
    }

    /* FIXME: DDSI-level readers, writers have topic, type name in their QoS, but
       DDSC-level ones don't and that gives an automatic mismatch when comparing
       the full QoS object ...  Here the two have the same topic by construction
       so ignoring them in the comparison makes things work.  The discrepancy
       should be addressed one day. */
    const uint64_t qmask = ~(DDSI_QP_TOPIC_NAME | DDSI_QP_TYPE_NAME | DDSI_QP_TYPE_INFORMATION);
    dds_qos_policy_id_t dummy;
#ifdef DDS_HAS_TYPE_DISCOVERY
    return ddsi_qos_match_mask_p (bwr->wr.e.gv, qos, bwr->wr.xqos, qmask, &dummy, NULL, NULL, NULL, NULL) && !qos_has_resource_limits (qos);
#else
    return ddsi_qos_match_mask_p (bwr->wr.e.gv, qos, bwr->wr.xqos, qmask, &dummy) && !qos_has_resource_limits (qos);
#endif
  }
}

static dds_entity_t dds__create_builtin_subscriber (dds_participant *participant)
{
  dds_qos_t *qos = dds__create_builtin_qos ();
  dds_entity_t sub = dds__create_subscriber_l (participant, false, qos, NULL);
  dds_delete_qos (qos);
  return sub;
}

dds_entity_t dds__get_builtin_subscriber (dds_entity_t e)
{
  dds_entity_t sub;
  dds_return_t ret;
  dds_entity_t pp;
  dds_participant *p;

  if ((pp = dds_get_participant (e)) <= 0)
    return pp;
  if ((ret = dds_participant_lock (pp, &p)) != DDS_RETCODE_OK)
    return ret;

  if (p->m_builtin_subscriber <= 0) {
    p->m_builtin_subscriber = dds__create_builtin_subscriber (p);
  }
  sub = p->m_builtin_subscriber;
  dds_participant_unlock(p);
  return sub;
}

static bool dds__builtin_is_builtintopic (const struct ddsi_sertype *tp, void *vdomain)
{
  (void) vdomain;
  return tp->ops == &ddsi_sertype_ops_builtintopic;
}

static bool dds__builtin_is_visible (const ddsi_guid_t *guid, ddsi_vendorid_t vendorid, void *vdomain)
{
  (void) vdomain;
  if (ddsi_is_builtin_endpoint (guid->entityid, vendorid) || ddsi_is_builtin_topic (guid->entityid, vendorid))
    return false;
  return true;
}

static struct ddsi_tkmap_instance *dds__builtin_get_tkmap_entry (const struct ddsi_guid *guid, void *vdomain)
{
  struct dds_domain *domain = vdomain;
  /* any random builtin topic will do (provided it has a GUID for a key), because what matters is the "class"
     of the topic, not the actual topic; also, this is called early in the initialisation of the entity with
     this GUID, which simply causes serdata_from_keyhash to create a key-only serdata because the key lookup
     fails. */
  struct ddsi_serdata *sd = dds_serdata_builtin_from_endpoint (domain->builtin_participant_type, guid, NULL, SDK_KEY);
  struct ddsi_tkmap_instance *tk = ddsi_tkmap_find (domain->gv.m_tkmap, sd, true);
  ddsi_serdata_unref (sd);
  return tk;
}

struct ddsi_serdata *dds__builtin_make_sample_endpoint (const struct ddsi_entity_common *e, ddsrt_wctime_t timestamp, bool alive)
{
  /* initialize to avoid gcc warning ultimately caused by C's horrible type system */
  struct dds_domain *dom = e->gv->builtin_topic_interface->arg;
  struct ddsi_sertype *type = NULL;
  switch (e->kind)
  {
    case DDSI_EK_PARTICIPANT:
    case DDSI_EK_PROXY_PARTICIPANT:
      type = dom->builtin_participant_type;
      break;
    case DDSI_EK_WRITER:
    case DDSI_EK_PROXY_WRITER:
      type = dom->builtin_writer_type;
      break;
    case DDSI_EK_READER:
    case DDSI_EK_PROXY_READER:
      type = dom->builtin_reader_type;
      break;
    default:
      abort ();
      break;
  }
  assert (type != NULL);
  struct ddsi_serdata *serdata = dds_serdata_builtin_from_endpoint (type, &e->guid, (struct ddsi_entity_common *) e, alive ? SDK_DATA : SDK_KEY);
  serdata->timestamp = timestamp;
  serdata->statusinfo = alive ? 0 : DDSI_STATUSINFO_DISPOSE | DDSI_STATUSINFO_UNREGISTER;
  return serdata;
}

#ifdef DDS_HAS_TOPIC_DISCOVERY

static struct ddsi_serdata *dds__builtin_make_sample_topic_impl (const struct ddsi_topic_definition *tpd, ddsrt_wctime_t timestamp, bool alive)
{
  struct dds_domain *dom = tpd->gv->builtin_topic_interface->arg;
  struct ddsi_sertype *type = dom->builtin_topic_type;
  struct ddsi_serdata *serdata = dds_serdata_builtin_from_topic_definition (type, (dds_builtintopic_topic_key_t *) &tpd->key, tpd, alive ? SDK_DATA : SDK_KEY);
  serdata->timestamp = timestamp;
  serdata->statusinfo = alive ? 0 : DDSI_STATUSINFO_DISPOSE | DDSI_STATUSINFO_UNREGISTER;
  return serdata;
}

struct ddsi_serdata *dds__builtin_make_sample_topic (const struct ddsi_entity_common *e, ddsrt_wctime_t timestamp, bool alive)
{
  struct ddsi_topic *tp = (struct ddsi_topic *) e;
  ddsrt_mutex_lock (&tp->e.qos_lock);
  struct ddsi_serdata *sd = dds__builtin_make_sample_topic_impl (tp->definition, timestamp, alive);
  ddsrt_mutex_unlock (&tp->e.qos_lock);
  return sd;
}

struct ddsi_serdata *dds__builtin_make_sample_proxy_topic (const struct ddsi_proxy_topic *proxytp, ddsrt_wctime_t timestamp, bool alive)
{
  return dds__builtin_make_sample_topic_impl (proxytp->definition, timestamp, alive);
}

#endif /* DDS_HAS_TOPIC_DISCOVERY  */

static void dds__builtin_write_endpoint (const struct ddsi_entity_common *e, ddsrt_wctime_t timestamp, bool alive, void *vdomain)
{
  struct dds_domain *dom = vdomain;
  //使用 dds__builtin_is_visible 函数判断给定实体是否对给定域可见。如果不可见，则不执行写入操作
  if (dds__builtin_is_visible (&e->guid, ddsi_get_entity_vendorid (e), dom))
  {
    /* initialize to avoid gcc warning ultimately caused by C's horrible type system */
    struct ddsi_local_orphan_writer *bwr = NULL;
    //使用 dds__builtin_make_sample_endpoint 函数根据实体信息、时间戳和活动状态构造序列化的数据
    struct ddsi_serdata *serdata = dds__builtin_make_sample_endpoint (e, timestamp, alive);
    assert (e->tk != NULL);
    switch (e->kind)
    {
      case DDSI_EK_PARTICIPANT:
      case DDSI_EK_PROXY_PARTICIPANT:
        bwr = dom->builtintopic_writer_participant;
        break;
      case DDSI_EK_WRITER:
      case DDSI_EK_PROXY_WRITER:
        bwr = dom->builtintopic_writer_publications;
        break;
      case DDSI_EK_READER:
      case DDSI_EK_PROXY_READER:
        bwr = dom->builtintopic_writer_subscriptions;
        break;
      default:
        abort ();
        break;
    }
    //调用 dds_writecdr_local_orphan_impl 函数执行本地的写入操作，将数据写入内置主题。
    dds_writecdr_local_orphan_impl (bwr, serdata);
  }
}

#ifdef DDS_HAS_TOPIC_DISCOVERY
static void dds__builtin_write_topic (const struct ddsi_topic_definition *tpd, ddsrt_wctime_t timestamp, bool alive, void *vdomain)
{
  struct dds_domain *dom = vdomain;
  struct ddsi_local_orphan_writer *bwr = dom->builtintopic_writer_topics;
  struct ddsi_serdata *serdata = dds__builtin_make_sample_topic_impl (tpd, timestamp, alive);
  dds_writecdr_local_orphan_impl (bwr, serdata);
}
#endif

static void unref_builtin_types (struct dds_domain *dom)
{
  ddsi_sertype_unref (dom->builtin_participant_type);
#ifdef DDS_HAS_TOPIC_DISCOVERY
  ddsi_sertype_unref (dom->builtin_topic_type);
#endif
  ddsi_sertype_unref (dom->builtin_reader_type);
  ddsi_sertype_unref (dom->builtin_writer_type);
}

/*
这段代码是用于初始化DDS（Data Distribution Service）的内建（builtin）主题（topics）和相关的一些结构的函数。DDS是一种通信协议，用于在分布式系统中进行数据交换。

让我们逐步解释这段代码：

1. dds_qos_t *qos = dds__create_builtin_qos (); - 创建用于内建主题的QoS（Quality of Service）配置。
2. 设置 dom 结构的 btif 成员，这是一个内建主题接口的结构，包括一些回调函数和其他成员。这些回调函数将被用于处理内建主题的不同方面，比如写入、是否是内建主题等等。
3. 设置 dom->gv.builtin_topic_interface 为 &dom->btif，将内建主题接口与域（domain）相关联。
4. 获取内建主题的类型名，并通过调用 dds_new_sertype_builtintopic 和 dds_new_sertype_builtintopic_topic 创建内建主题的类型。
5. 注册这些内建主题的类型到全局的 dom->gv 结构中。
6. 唤醒等待中的线程，以便使新的内建主题类型可用。
7. 通过调用 ddsi_new_local_orphan_writer 创建内建主题的写者（writer），这些写者用于发布内建主题的信息。这包括参与者（Participant）、主题（Topic）、发布者（Publisher）和订阅者（Subscriber）。
8. 将新创建的写者与相关的内建主题相关联，例如，DDS_BUILTIN_TOPIC_PARTICIPANT_NAME 对应参与者主题。
9. 通过调用 ddsi_thread_state_asleep 将线程置为休眠状态，以确保在内建主题写者创建后，不再有其他线程在访问。
10. 释放用于内建主题的QoS配置，调用 dds_delete_qos(qos)。
11. unref_builtin_types(dom) - 这个函数用于减少内建主题类型的引用计数，因为在之前的注册和初始化步骤中，已经为这些类型增加了引用计数。

总体而言，这段代码完成了DDS域的内建主题的初始化工作，包括创建内建主题类型、注册类型、创建内建主题的写者，并处理一些与内建主题相关的回调函数。这些内建主题通常用于DDS的元数据交换，例如，用于描述发布者、订阅者、主题等信息

*/
void dds__builtin_init (struct dds_domain *dom)
{
  dds_qos_t *qos = dds__create_builtin_qos ();

  dom->btif.arg = dom;
  dom->btif.builtintopic_get_tkmap_entry = dds__builtin_get_tkmap_entry;
  dom->btif.builtintopic_is_builtintopic = dds__builtin_is_builtintopic;
  dom->btif.builtintopic_is_visible = dds__builtin_is_visible;
  dom->btif.builtintopic_write_endpoint = dds__builtin_write_endpoint;
#ifdef DDS_HAS_TOPIC_DISCOVERY
  dom->btif.builtintopic_write_topic = dds__builtin_write_topic;
#endif
  dom->gv.builtin_topic_interface = &dom->btif;

  const char *typename;
  (void) dds__get_builtin_topic_name_typename (DDS_BUILTIN_TOPIC_DCPSPARTICIPANT, NULL, &typename);
  dom->builtin_participant_type = dds_new_sertype_builtintopic (DSBT_PARTICIPANT, typename);
#ifdef DDS_HAS_TOPIC_DISCOVERY
  (void) dds__get_builtin_topic_name_typename (DDS_BUILTIN_TOPIC_DCPSTOPIC, NULL, &typename);
  dom->builtin_topic_type = dds_new_sertype_builtintopic_topic (DSBT_TOPIC, typename);
#endif
  (void) dds__get_builtin_topic_name_typename (DDS_BUILTIN_TOPIC_DCPSSUBSCRIPTION, NULL, &typename);
  dom->builtin_reader_type = dds_new_sertype_builtintopic (DSBT_READER, typename);
  (void) dds__get_builtin_topic_name_typename (DDS_BUILTIN_TOPIC_DCPSPUBLICATION, NULL, &typename);
  dom->builtin_writer_type = dds_new_sertype_builtintopic (DSBT_WRITER, typename);

  ddsrt_mutex_lock (&dom->gv.sertypes_lock);
  ddsi_sertype_register_locked (&dom->gv, dom->builtin_participant_type);
#ifdef DDS_HAS_TOPIC_DISCOVERY
  ddsi_sertype_register_locked (&dom->gv, dom->builtin_topic_type);
#endif
  ddsi_sertype_register_locked (&dom->gv, dom->builtin_reader_type);
  ddsi_sertype_register_locked (&dom->gv, dom->builtin_writer_type);
  ddsrt_mutex_unlock (&dom->gv.sertypes_lock);

  ddsi_thread_state_awake (ddsi_lookup_thread_state (), &dom->gv);
  const struct ddsi_entity_index *gh = dom->gv.entity_index;
  dom->builtintopic_writer_participant = ddsi_new_local_orphan_writer (&dom->gv, ddsi_to_entityid (DDSI_ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER), DDS_BUILTIN_TOPIC_PARTICIPANT_NAME, dom->builtin_participant_type, qos, dds_builtintopic_whc_new (DSBT_PARTICIPANT, gh));
#ifdef DDS_HAS_TOPIC_DISCOVERY
  dom->builtintopic_writer_topics = ddsi_new_local_orphan_writer (&dom->gv, ddsi_to_entityid (DDSI_ENTITYID_SEDP_BUILTIN_TOPIC_WRITER), DDS_BUILTIN_TOPIC_TOPIC_NAME, dom->builtin_topic_type, qos, dds_builtintopic_whc_new (DSBT_TOPIC, gh));
#endif
  dom->builtintopic_writer_publications = ddsi_new_local_orphan_writer (&dom->gv, ddsi_to_entityid (DDSI_ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER), DDS_BUILTIN_TOPIC_PUBLICATION_NAME, dom->builtin_writer_type, qos, dds_builtintopic_whc_new (DSBT_WRITER, gh));
  dom->builtintopic_writer_subscriptions = ddsi_new_local_orphan_writer (&dom->gv, ddsi_to_entityid (DDSI_ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER), DDS_BUILTIN_TOPIC_SUBSCRIPTION_NAME, dom->builtin_reader_type, qos, dds_builtintopic_whc_new (DSBT_READER, gh));
  ddsi_thread_state_asleep (ddsi_lookup_thread_state ());

  dds_delete_qos (qos);

  /* ddsi_sertype_init initializes the refcount to 1 and dds_sertype_register_locked increments
     it.  All "real" references (such as readers and writers) are also accounted for in the
     reference count, so we have an excess reference here. */
  unref_builtin_types (dom);
}

void dds__builtin_fini (struct dds_domain *dom)
{
  /* No more sources for builtin topic samples */
  ddsi_thread_state_awake (ddsi_lookup_thread_state (), &dom->gv);
  ddsi_delete_local_orphan_writer (dom->builtintopic_writer_participant);
#ifdef DDS_HAS_TOPIC_DISCOVERY
  ddsi_delete_local_orphan_writer (dom->builtintopic_writer_topics);
#endif
  ddsi_delete_local_orphan_writer (dom->builtintopic_writer_publications);
  ddsi_delete_local_orphan_writer (dom->builtintopic_writer_subscriptions);
  ddsi_thread_state_asleep (ddsi_lookup_thread_state ());
  unref_builtin_types (dom);
}
