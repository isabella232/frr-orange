/*
 * IS-IS Rout(e)ing protocol - isis_te.c
 *
 * This is an implementation of RFC5305 & RFC 7810
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2014 - 2019 Orange Labs http://www.orange.com
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <math.h>

#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "hash.h"
#include "if.h"
#include "vrf.h"
#include "checksum.h"
#include "md5.h"
#include "sockunion.h"
#include "network.h"
#include "sbuf.h"
#include "link_state.h"
#include "lib/json.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_te.h"
#include "isisd/isis_zebra.h"

/*------------------------------------------------------------------------*
 * Followings are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/

/* Main initialization / update function of the MPLS TE Circuit context */
/* Call when interface TE Link parameters are modified */
void isis_link_params_update(struct isis_circuit *circuit,
			     struct interface *ifp)
{
	int i;
	struct prefix_ipv4 *addr;
	struct prefix_ipv6 *addr6;
	struct isis_ext_subtlvs *ext;

	/* Check if TE is enable or not */
	if (!circuit->area || !IS_MPLS_TE(circuit->area->mta))
		return;

	/* Sanity Check */
	if ((ifp == NULL) || (circuit->state != C_STATE_UP))
		return;

	zlog_debug("TE(%s): Update circuit parameters for interface %s",
		   circuit->area->area_tag, ifp->name);

	/* Check if MPLS TE Circuit context has not been already created */
	if (circuit->ext == NULL) {
		circuit->ext = isis_alloc_ext_subtlvs();
		zlog_debug("  |- Allocated new Ext-subTLVs for interface %s",
			   ifp->name);
	}

	ext = circuit->ext;

	/* Fulfill Extended subTLVs from interface link parameters */
	if (HAS_LINK_PARAMS(ifp)) {
		/* STD_TE metrics */
		if (IS_PARAM_SET(ifp->link_params, LP_ADM_GRP)) {
			ext->adm_group = ifp->link_params->admin_grp;
			SET_SUBTLV(ext, EXT_ADM_GRP);
		} else
			UNSET_SUBTLV(ext, EXT_ADM_GRP);

		/* If known, register local IPv4 addr from ip_addr list */
		if (circuit->ip_addrs != NULL
		    && listcount(circuit->ip_addrs) != 0) {
			addr = (struct prefix_ipv4 *)listgetdata(
				(struct listnode *)listhead(circuit->ip_addrs));
			IPV4_ADDR_COPY(&ext->local_addr, &addr->prefix);
			SET_SUBTLV(ext, EXT_LOCAL_ADDR);
		} else
			UNSET_SUBTLV(ext, EXT_LOCAL_ADDR);

		/* Same for Remote IPv4 address */
		if (circuit->circ_type == CIRCUIT_T_P2P) {
			struct isis_adjacency *adj = circuit->u.p2p.neighbor;

			if (adj && adj->adj_state == ISIS_ADJ_UP
			    && adj->ipv4_address_count) {
				IPV4_ADDR_COPY(&ext->neigh_addr,
					       &adj->ipv4_addresses[0]);
				SET_SUBTLV(ext, EXT_NEIGH_ADDR);
			}
		} else
			UNSET_SUBTLV(ext, EXT_NEIGH_ADDR);

		/* If known, register local IPv6 addr from ip_addr list */
		if (circuit->ipv6_non_link != NULL
		    && listcount(circuit->ipv6_non_link) != 0) {
			addr6 = (struct prefix_ipv6 *)listgetdata(
				(struct listnode *)listhead(
					circuit->ipv6_non_link));
			IPV6_ADDR_COPY(&ext->local_addr6, &addr6->prefix);
			SET_SUBTLV(ext, EXT_LOCAL_ADDR6);
		} else
			UNSET_SUBTLV(ext, EXT_LOCAL_ADDR6);

		/* Same for Remote IPv6 address */
		if (circuit->circ_type == CIRCUIT_T_P2P) {
			struct isis_adjacency *adj = circuit->u.p2p.neighbor;

			if (adj && adj->adj_state == ISIS_ADJ_UP
			    && adj->ipv6_address_count) {
				IPV6_ADDR_COPY(&ext->neigh_addr6,
					       &adj->ipv6_addresses[0]);
				SET_SUBTLV(ext, EXT_NEIGH_ADDR6);
			}
		} else
			UNSET_SUBTLV(ext, EXT_NEIGH_ADDR6);

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_BW)) {
			ext->max_bw = ifp->link_params->max_bw;
			SET_SUBTLV(ext, EXT_MAX_BW);
		} else
			UNSET_SUBTLV(ext, EXT_MAX_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_RSV_BW)) {
			ext->max_rsv_bw = ifp->link_params->max_rsv_bw;
			SET_SUBTLV(ext, EXT_MAX_RSV_BW);
		} else
			UNSET_SUBTLV(ext, EXT_MAX_RSV_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_UNRSV_BW)) {
			for (i = 0; i < MAX_CLASS_TYPE; i++)
				ext->unrsv_bw[i] =
					ifp->link_params->unrsv_bw[i];
			SET_SUBTLV(ext, EXT_UNRSV_BW);
		} else
			UNSET_SUBTLV(ext, EXT_UNRSV_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_TE_METRIC)) {
			ext->te_metric = ifp->link_params->te_metric;
			SET_SUBTLV(ext, EXT_TE_METRIC);
		} else
			UNSET_SUBTLV(ext, EXT_TE_METRIC);

		/* TE metric extensions */
		if (IS_PARAM_SET(ifp->link_params, LP_DELAY)) {
			ext->delay = ifp->link_params->av_delay;
			SET_SUBTLV(ext, EXT_DELAY);
		} else
			UNSET_SUBTLV(ext, EXT_DELAY);

		if (IS_PARAM_SET(ifp->link_params, LP_MM_DELAY)) {
			ext->min_delay = ifp->link_params->min_delay;
			ext->max_delay = ifp->link_params->max_delay;
			SET_SUBTLV(ext, EXT_MM_DELAY);
		} else
			UNSET_SUBTLV(ext, EXT_MM_DELAY);

		if (IS_PARAM_SET(ifp->link_params, LP_DELAY_VAR)) {
			ext->delay_var = ifp->link_params->delay_var;
			SET_SUBTLV(ext, EXT_DELAY_VAR);
		} else
			UNSET_SUBTLV(ext, EXT_DELAY_VAR);

		if (IS_PARAM_SET(ifp->link_params, LP_PKT_LOSS)) {
			ext->pkt_loss = ifp->link_params->pkt_loss;
			SET_SUBTLV(ext, EXT_PKT_LOSS);
		} else
			UNSET_SUBTLV(ext, EXT_PKT_LOSS);

		if (IS_PARAM_SET(ifp->link_params, LP_RES_BW)) {
			ext->res_bw = ifp->link_params->res_bw;
			SET_SUBTLV(ext, EXT_RES_BW);
		} else
			UNSET_SUBTLV(ext, EXT_RES_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_AVA_BW)) {
			ext->ava_bw = ifp->link_params->ava_bw;
			SET_SUBTLV(ext, EXT_AVA_BW);
		} else
			UNSET_SUBTLV(ext, EXT_AVA_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_USE_BW)) {
			ext->use_bw = ifp->link_params->use_bw;
			SET_SUBTLV(ext, EXT_USE_BW);
		} else
			UNSET_SUBTLV(ext, EXT_USE_BW);

		/* INTER_AS */
		if (IS_PARAM_SET(ifp->link_params, LP_RMT_AS)) {
			ext->remote_as = ifp->link_params->rmt_as;
			ext->remote_ip = ifp->link_params->rmt_ip;
			SET_SUBTLV(ext, EXT_RMT_AS);
			SET_SUBTLV(ext, EXT_RMT_IP);
		} else {
			/* reset inter-as TE params */
			UNSET_SUBTLV(ext, EXT_RMT_AS);
			UNSET_SUBTLV(ext, EXT_RMT_IP);
		}
		zlog_debug("  |- New MPLS-TE link parameters status 0x%x",
			   ext->status);
	} else {
		zlog_debug("  |- Reset Extended subTLVs status 0x%x",
			   ext->status);
		/* Reset TE subTLVs keeping SR one's */
		if (IS_SUBTLV(ext, EXT_ADJ_SID))
			ext->status = EXT_ADJ_SID;
		else if (IS_SUBTLV(ext, EXT_LAN_ADJ_SID))
			ext->status = EXT_LAN_ADJ_SID;
		else
			ext->status = 0;
	}

	return;
}

static int isis_link_update_adj_hook(struct isis_adjacency *adj)
{

	struct isis_circuit *circuit = adj->circuit;

	/* Update MPLS TE Remote IP address parameter if possible */
	if (!IS_MPLS_TE(circuit->area->mta) || !IS_EXT_TE(circuit->ext))
		return 0;

	/* IPv4 first */
	if (adj->ipv4_address_count > 0) {
		IPV4_ADDR_COPY(&circuit->ext->neigh_addr,
			       &adj->ipv4_addresses[0]);
		SET_SUBTLV(circuit->ext, EXT_NEIGH_ADDR);
	}

	/* and IPv6 */
	if (adj->ipv6_address_count > 0) {
		IPV6_ADDR_COPY(&circuit->ext->neigh_addr6,
			       &adj->ipv6_addresses[0]);
		SET_SUBTLV(circuit->ext, EXT_NEIGH_ADDR6);
	}

	return 0;
}

int isis_mpls_te_update(struct interface *ifp)
{
	struct isis_circuit *circuit;
	uint8_t rc = 1;

	/* Sanity Check */
	if (ifp == NULL)
		return rc;

	/* Get circuit context from interface */
	circuit = circuit_scan_by_ifp(ifp);
	if (circuit == NULL)
		return rc;

	/* Update TE TLVs ... */
	isis_link_params_update(circuit, ifp);

	/* ... and LSP */
	if (circuit->area && IS_MPLS_TE(circuit->area->mta))
		lsp_regenerate_schedule(circuit->area, circuit->is_type, 0);

	rc = 0;
	return rc;
}

/**
 * Parse LSP and build corresponding vertex. If vertex doesn't exist in the
 * Link State Database it is created otherwise updated.
 *
 * @param ted	Traffic Engineering Link State Database
 * @param lsp	IS-IS Link State PDU
 *
 * @return	Link State Vertex or NULL in case of error
 */
static struct ls_vertex *lsp_to_vertex(struct ls_ted *ted, struct isis_lsp *lsp)
{
	struct ls_vertex *vertex = NULL;
	struct ls_node *old, lnode = {};
	struct ls_node_id lnid = {};
	const struct in_addr inaddr_any = {.s_addr = INADDR_ANY};

	/* Sanity check */
	if (!ted || !lsp)
		return NULL;

	/* Compute Link State Node ID from IS-IS sysID ... */
	if (lsp->level == ISIS_LEVEL1)
		lnid.origin = ISIS_L1;
	else
		lnid.origin = ISIS_L2;
	memcpy(&lnid.id.iso.sys_id, &lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
	lnid.id.iso.level = lsp->level;
	/* ... and search the corresponding vertex */
	vertex = ls_find_vertex_by_id(ted, lnid);
	/* Create a new one if not found */
	if (!vertex) {
		old = ls_node_new(lnid, inaddr_any, in6addr_any);
		old->type = STANDARD;
		vertex = ls_vertex_add(ted, old);
	}

	/* Fulfill Link State Node information */
	if (lsp->tlvs->te_router_id) {
		lnode.router_id = *lsp->tlvs->te_router_id;
		SET_FLAG(lnode.flags, LS_NODE_ROUTER_ID);
	}
	if (lsp->tlvs->hostname) {
		memcpy(&lnode.name, lsp->tlvs->hostname, MAX_NAME_LENGTH);
		SET_FLAG(lnode.flags, LS_NODE_NAME);
	}
	if (lsp->tlvs->router_cap) {
		struct isis_router_cap *cap = lsp->tlvs->router_cap;

		SET_FLAG(lnode.flags, LS_NODE_SR);
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
			lnode.algo[i] = cap->algo[i];
		lnode.srgb.flag = cap->srgb.flags;
		lnode.srgb.lower_bound = cap->srgb.lower_bound;
		lnode.srgb.range_size = cap->srgb.range_size;
		if (cap->srlb.lower_bound != 0 && cap->srlb.range_size != 0) {
			lnode.srlb.lower_bound = cap->srlb.lower_bound;
			lnode.srlb.range_size = cap->srlb.range_size;
			SET_FLAG(lnode.flags, LS_NODE_SRLB);
		}
		if (cap->msd != 0) {
			lnode.msd = cap->msd;
			SET_FLAG(lnode.flags, LS_NODE_MSD);
		}
	}

	/* Update Link State Node information */
	old = vertex->node;
	if (!ls_node_same(old, &lnode)) {
		memcpy(old, &lnode, sizeof(struct ls_node));
		if (vertex->status != NEW)
			vertex->status = UPDATE;
	}

	/* Set self TED vertex if LSP corresponds to the own router */
	if (lsp->own_lsp)
		ted->self = vertex;

	return vertex;
}

/**
 * Parse Extended Reachability TLVs and create or update the corresponding
 * Link State Edge and Attributes. Vertex connections are also updated if
 * needed based on the remote IP address of the Edge and existing reverse Edge.
 *
 * @param ted	  Link State Traffic Engineering Database
 * @param vertex  Link State Vertex which advertise this Edge
 * @param ier	  Extended Reachability information
 *
 * @return	Link State Edge if success, NULL otherwise
 */
static struct ls_edge *lsp_to_edge(struct ls_ted *ted, struct ls_vertex *vertex,
				   struct isis_extended_reach *ier)
{
	struct ls_edge *edge;
	struct ls_attributes *old, attr = {};
	struct isis_ext_subtlvs *tlvs;
	uint64_t key;

	/* Sanity Check */
	if (!ted || !vertex || !ier)
		return NULL;

	/* Check if we have a valid sub TLVs */
	tlvs = ier->subtlvs;
	if (tlvs == NULL)
		return NULL;
	if (!CHECK_FLAG(tlvs->status, EXT_LOCAL_ADDR))
		return NULL;

	/* Initialize Link State Attributes */
	// NOTE: item.id == remote IS-IS ID node attached to this link
	memcpy(&attr.adv, &vertex->node->adv, sizeof(struct ls_node_id));
	attr.metric = ier->metric;

	/* Browse sub-TLV and fulfill Link State Attributes */
	if (CHECK_FLAG(tlvs->status, EXT_ADM_GRP)) {
		attr.standard.admin_group = tlvs->adm_group;
		SET_FLAG(attr.flags, LS_ATTR_ADM_GRP);
	}
	if (CHECK_FLAG(tlvs->status, EXT_LLRI)) {
		attr.standard.local_id = tlvs->local_llri;
		attr.standard.remote_id = tlvs->remote_llri;
		SET_FLAG(attr.flags, LS_ATTR_LOCAL_ID);
		SET_FLAG(attr.flags, LS_ATTR_NEIGH_ID);
	}
	if (CHECK_FLAG(tlvs->status, EXT_LOCAL_ADDR)) {
		attr.standard.local.s_addr = tlvs->local_addr.s_addr;
		SET_FLAG(attr.flags, LS_ATTR_LOCAL_ADDR);
	}
	if (CHECK_FLAG(tlvs->status, EXT_NEIGH_ADDR)) {
		attr.standard.remote.s_addr = tlvs->neigh_addr.s_addr;
		SET_FLAG(attr.flags, LS_ATTR_NEIGH_ADDR);
	}
	if (CHECK_FLAG(tlvs->status, EXT_LOCAL_ADDR6)) {
		memcpy(&attr.standard.local6, &tlvs->local_addr6,
		       IPV6_MAX_BYTELEN);
		SET_FLAG(attr.flags, LS_ATTR_LOCAL_ADDR6);
	}
	if (CHECK_FLAG(tlvs->status, EXT_NEIGH_ADDR6)) {
		memcpy(&attr.standard.remote6, &tlvs->neigh_addr6,
		       IPV6_MAX_BYTELEN);
		SET_FLAG(attr.flags, LS_ATTR_NEIGH_ADDR6);
	}
	if (CHECK_FLAG(tlvs->status, EXT_MAX_BW)) {
		attr.standard.max_bw = tlvs->max_bw;
		SET_FLAG(attr.flags, LS_ATTR_MAX_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_MAX_RSV_BW)) {
		attr.standard.max_rsv_bw = tlvs->max_rsv_bw;
		SET_FLAG(attr.flags, LS_ATTR_RSV_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_UNRSV_BW)) {
		memcpy(&attr.standard.unrsv_bw, tlvs->unrsv_bw,
		       ISIS_SUBTLV_UNRSV_BW_SIZE);
		SET_FLAG(attr.flags, LS_ATTR_UNRSV_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_TE_METRIC)) {
		attr.standard.te_metric = tlvs->te_metric;
		SET_FLAG(attr.flags, LS_ATTR_TE_METRIC);
	}
	if (CHECK_FLAG(tlvs->status, EXT_RMT_AS)) {
		attr.standard.remote_as = tlvs->remote_as;
		SET_FLAG(attr.flags, LS_ATTR_REMOTE_AS);
	}
	if (CHECK_FLAG(tlvs->status, EXT_RMT_IP)) {
		attr.standard.remote_addr = tlvs->remote_ip;
		SET_FLAG(attr.flags, LS_ATTR_REMOTE_ADDR);
	}
	if (CHECK_FLAG(tlvs->status, EXT_DELAY)) {
		attr.extended.delay = tlvs->delay;
		SET_FLAG(attr.flags, LS_ATTR_DELAY);
	}
	if (CHECK_FLAG(tlvs->status, EXT_MM_DELAY)) {
		attr.extended.min_delay = tlvs->min_delay;
		attr.extended.max_delay = tlvs->max_delay;
		SET_FLAG(attr.flags, LS_ATTR_MIN_MAX_DELAY);
	}
	if (CHECK_FLAG(tlvs->status, EXT_DELAY_VAR)) {
		attr.extended.jitter = tlvs->delay_var;
		SET_FLAG(attr.flags, LS_ATTR_JITTER);
	}
	if (CHECK_FLAG(tlvs->status, EXT_PKT_LOSS)) {
		attr.extended.pkt_loss = tlvs->pkt_loss;
		SET_FLAG(attr.flags, LS_ATTR_PACKET_LOSS);
	}
	if (CHECK_FLAG(tlvs->status, EXT_AVA_BW)) {
		attr.extended.ava_bw = tlvs->ava_bw;
		SET_FLAG(attr.flags, LS_ATTR_AVA_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_RES_BW)) {
		attr.extended.rsv_bw = tlvs->res_bw;
		SET_FLAG(attr.flags, LS_ATTR_RSV_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_USE_BW)) {
		attr.extended.used_bw = tlvs->use_bw;
		SET_FLAG(attr.flags, LS_ATTR_USE_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_ADJ_SID)) {
		struct isis_adj_sid *adj =
			(struct isis_adj_sid *)tlvs->adj_sid.head;
		for (int i = 0; i < 2 && adj; adj = adj->next, i++) {
			attr.adj_sid[i].flags = adj->flags;
			attr.adj_sid[i].weight = adj->weight;
			attr.adj_sid[i].sid = adj->sid;
		}
		SET_FLAG(attr.flags, LS_ATTR_ADJ_SID);
	}
	if (CHECK_FLAG(tlvs->status, EXT_LAN_ADJ_SID)) {
		struct isis_lan_adj_sid *ladj =
			(struct isis_lan_adj_sid *)tlvs->lan_sid.head;
		for (int i = 0; i < 2 && ladj; ladj = ladj->next, i++) {
			attr.adj_sid[i].flags = ladj->flags;
			attr.adj_sid[i].weight = ladj->weight;
			attr.adj_sid[i].sid = ladj->sid;
			// TODO: convert neighbour_id into IP addr
			// attr.adj_sid[i].neighbor = ladj->neighbor_id;
		}
		SET_FLAG(attr.flags, LS_ATTR_ADJ_SID);
	}

	/* Get corresponding Edge from Link State Data Base */
	key = ((uint64_t)ntohl(attr.standard.local.s_addr)) & 0xffffffff;
	edge = ls_find_edge_by_key(ted, key);
	/* Create new one if not exist */
	if (!edge) {
		old = ls_attributes_new(attr.adv, attr.standard.local,
					attr.standard.local6, 0);
		edge = ls_edge_add(ted, old);
	}
	old = edge->attributes;

	te_debug("  |- Process Extended Reachability %pI4",
		 &attr.standard.local);

	/* Update Attribute fields */
	if (!ls_attributes_same(old, &attr)) {
		memcpy(old, &attr, sizeof(struct ls_attributes));
		if (edge->status != NEW)
			edge->status = UPDATE;
	}

	/* Update remote Link if remote IP addr is known */
	if (CHECK_FLAG(old->flags, LS_ATTR_NEIGH_ADDR)) {
		struct ls_edge *dst;

		dst = ls_find_edge_by_destination(ted, old);
		/* Attach remote link if not set */
		if (dst && edge->source && dst->destination == NULL) {
			vertex = edge->source;
			if (vertex->incoming_edges)
				listnode_add_sort_nodup(vertex->incoming_edges,
							dst);
			dst->destination = vertex;
		}
		/* and destination vertex to this edge */
		if (dst && dst->source && edge->destination == NULL) {
			vertex = dst->source;
			if (vertex->incoming_edges)
				listnode_add_sort_nodup(vertex->incoming_edges,
							edge);
			edge->destination = vertex;
		}
	}

	return edge;
}


/**
 * Parse Extended IP Reachability or MT IPv6 Reachability TLVs and create or
 * update the corresponding Link State Subnet and Prefix.
 *
 * @param ted	  Link State Traffic Engineering Database
 * @param vertex  Link State Vertex which advertise this Edge
 * @param p	  Prefix associated to this subnet
 * @param metric  Metric of
 * @param subtlvs Subtlvs if any
 *
 * @return	  Link State Subnet if success, NULL otherwise
 */
static struct ls_subnet *reach_to_subnet(struct ls_ted *ted,
					 struct ls_vertex *vertex,
					 const struct prefix *pref,
					 const uint32_t metric,
					 struct isis_subtlvs *subtlvs)
{
	struct ls_subnet *subnet;
	struct ls_prefix *ls_pref;

	/* Sanity Check */
	if (!ted || !vertex || !pref)
		return NULL;

	subnet = ls_find_subnet(ted, *pref);
	/* Create a new Subnet if not found */
	if (!subnet) {
		ls_pref = ls_prefix_new(vertex->node->adv, *pref);
		subnet = ls_subnet_add(ted, ls_pref);
		if (!subnet)
			return NULL;
	}
	ls_pref = subnet->ls_pref;
	/* Update Metric */
	if (!CHECK_FLAG(ls_pref->flags, LS_PREF_METRIC)
	    || (ls_pref->metric != metric)) {
		ls_pref->metric = metric;
		SET_FLAG(ls_pref->flags, LS_PREF_METRIC);
		if (subnet->status != NEW)
			subnet->status = UPDATE;
	} else {
		if (subnet->status == ORPHAN)
			subnet->status = SYNC;
	}

	/* Update Prefix SID if any */
	if (subtlvs || subtlvs->prefix_sids.count == 0) {
		struct isis_prefix_sid *psid;
		struct ls_sid sr = {};

		psid = (struct isis_prefix_sid *)subtlvs->prefix_sids.head;
		sr.algo = psid->algorithm;
		sr.sid_flag = psid->flags;
		sr.sid = psid->value;

		if (!CHECK_FLAG(ls_pref->flags, LS_PREF_SR)
		    || !memcmp(&ls_pref->sr, &sr, sizeof(struct ls_sid))) {
			memcpy(&ls_pref->sr, &sr, sizeof(struct ls_sid));
			SET_FLAG(ls_pref->flags, LS_PREF_SR);
			if (subnet->status != NEW)
				subnet->status = UPDATE;
		} else {
			if (subnet->status == ORPHAN)
				subnet->status = SYNC;
		}
	}

	return subnet;
}

/**
 * Export Link State information to consumer daemon through ZAPI Link State
 * Opaque Message.
 *
 * @param type		Type of Link State Element i.e. Vertex, Edge or Subnet
 * @param link_state	Pointer to Link State Vertex, Edge or Subnet
 *
 * @return		0 if success, -1 otherwise
 */
static int isis_te_export(uint8_t type, void *link_state)
{
	struct ls_message msg = {};
	int rc = 0;

	switch (type) {
	case LS_MSG_TYPE_NODE:
		ls_vertex2msg(&msg, (struct ls_vertex *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	case LS_MSG_TYPE_ATTRIBUTES:
		ls_edge2msg(&msg, (struct ls_edge *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	case LS_MSG_TYPE_PREFIX:
		ls_subnet2msg(&msg, (struct ls_subnet *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

/**
 * Parse ISIS LSP to fulfill the Link State Database
 *
 * @param ted	Link State Database
 * @param lsp	ISIS Link State PDU
 */
static void isis_te_parse_lsp(struct mpls_te_area *mta, struct isis_lsp *lsp)
{
	struct ls_ted *ted;
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	struct listnode *node;
	struct isis_item_list *items;
	struct isis_item *item;

	/* Sanity Check */
	if (!IS_MPLS_TE(mta) || !mta->ted || !lsp)
		return;

	ted = mta->ted;

	/* First parse LSP to obtain the corresponding Vertex */
	vertex = lsp_to_vertex(ted, lsp);
	if (!vertex) {
		zlog_warn("Unable to build Vertex from LSP %s. Abort!",
			  sysid_print(lsp->hdr.lsp_id));
		return;
	}

	/* Check if Vertex has been modified */
	if (vertex->status != SYNC) {
		te_debug("  |- %s Vertex %pI4",
			 vertex->status == NEW ? "Add" : "Update",
			 &vertex->node->router_id);

		/* Vertex is out of sync: export it if requested */
		if (IS_EXPORT_TE(mta))
			isis_te_export(LS_MSG_TYPE_NODE, vertex);
		vertex->status = SYNC;
	}

	/* Mark outgoing Edges and Subnets as ORPHAN to detect deletion */
	for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, node, edge))
		edge->status = ORPHAN;

	for (ALL_LIST_ELEMENTS_RO(vertex->prefixes, node, subnet))
		subnet->status = ORPHAN;

	/* Process Extended Reachability to build corresponding Edges */
	items = &lsp->tlvs->extended_reach;
	for (item = items ? items->head : NULL; item; item = item->next) {
		edge = lsp_to_edge(ted, vertex,
				   (struct isis_extended_reach *)item);
		if (edge == NULL)
			continue;

		/* Export Link State Edge if needed */
		if (edge->status == NEW || edge->status == UPDATE) {
			te_debug("  |- %s TE info. for Edge %pI4",
				 edge->status == NEW ? "Add" : "Update",
				 &edge->attributes->standard.local);

			if (IS_EXPORT_TE(mta) && edge->status != SYNC)
				isis_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
			edge->status = SYNC;
		}
	}

	/* Process Extended IP Reachability to build corresponding Subnets */
	items = &lsp->tlvs->extended_ip_reach;
	for (item = items ? items->head : NULL; item; item = item->next) {
		struct isis_extended_ip_reach *r;

		r = (struct isis_extended_ip_reach *)item;
		subnet = reach_to_subnet(ted, vertex, (struct prefix *)&r->prefix,
					 r->metric, r->subtlvs);
		if (subnet == NULL)
			continue;

		/* Export Link State Subnet if needed */
		if (subnet->status == NEW || subnet->status == UPDATE) {
			te_debug("  |- %s TE info. for Subnet %pFX",
				 subnet->status == NEW ? "Add" : "Update",
				 &subnet->ls_pref->pref);

			if (IS_EXPORT_TE(mta) && subnet->status != SYNC)
				isis_te_export(LS_MSG_TYPE_PREFIX, subnet);
			subnet->status = SYNC;
		}
	}

	/* Process MT IPv6 Reachability to build corresponding Subnets */
	items = isis_lookup_mt_items(&lsp->tlvs->mt_ipv6_reach,
				     ISIS_MT_IPV6_UNICAST);
	for (item = items ? items->head : NULL; item; item = item->next) {
		struct isis_ipv6_reach *r;

		r = (struct isis_ipv6_reach *)item;
		subnet = reach_to_subnet(ted, vertex, (struct prefix *)&r->prefix,
					 r->metric, r->subtlvs);
		if (subnet == NULL)
			continue;

		/* Export Link State Subnet if needed */
		if (subnet->status == NEW || subnet->status == UPDATE) {
			te_debug("  |- %s TE info. for Subnet %pFX",
				 subnet->status == NEW ? "Add" : "Update",
				 &subnet->ls_pref->pref);

			if (IS_EXPORT_TE(mta) && subnet->status != SYNC)
				isis_te_export(LS_MSG_TYPE_PREFIX, subnet);
			subnet->status = SYNC;
		}
	}

	/* Clean remaining Orphan Edges or Subnets */
	if (IS_EXPORT_TE(mta))
		ls_vertex_clean(ted, vertex, zclient);
	else
		ls_vertex_clean(ted, vertex, NULL);
}

/**
 * Delete Link State Database Vertex, Edge & Prefix that correspond to this
 * ISIS Link State PDU
 *
 * @param ted	Link State Database
 * @param lsp	ISIS Link State PDU
 */
static void isis_te_delete_lsp(struct mpls_te_area *mta, struct isis_lsp *lsp)
{

	// First parse Router information ==> Vertex

	// Then loop Extended Reachability & MT Reachability ==> Edge

	// Finaly loop Extended IP Reachability == Prefix

	// Clean Orphan
}

/**
 * Process ISIS LSP according to the event to add, update or remove
 * corresponding vertex, edge and prefix in the Link State database
 *
 * @param lsp	ISIS Link State PDU
 * @param event	LSP event: ADD, UPD, DEL (INC and TICK are ignored)
 *
 */
void isis_te_lsp_event(struct isis_lsp *lsp, enum lsp_event event)
{
	struct isis_area *area;

	if (!lsp || !lsp->area)
		return;

	area = lsp->area;
	if (!IS_MPLS_TE(area->mta))
		return;

	switch(event) {
	case LSP_ADD:
	case LSP_UPD:
		if (lsp->tlvs)
			isis_te_parse_lsp(area->mta, lsp);
		break;
	case LSP_DEL:
		if (lsp->tlvs)
			isis_te_delete_lsp(area->mta, lsp);
		break;
	default:
		break;
	}

}

/**
 * Send the whole Link State Traffic Engineering Database to the consumer that
 * request it through a ZAPI Link State Synchronous Opaque Message.
 *
 * @param info	ZAPI Opaque message
 *
 * @return	0 if success, -1 otherwise
 */
int isis_te_sync_ted(struct zapi_opaque_reg_info dst)
{
	struct listnode *node, *inode;
	struct isis *isis;
	struct isis_area *area;
	struct mpls_te_area *mta;
	int rc = -1;

	/*  For each area, send TED if TE distribution is enabled */
	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			mta = area->mta;
			if (IS_MPLS_TE(mta) && IS_EXPORT_TE(mta)) {
				rc = ls_sync_ted(mta->ted, zclient, &dst);
				if (rc != 0)
					return rc;
			}
		}
	}

	return rc;
}

/**
 * Initialize the Link State database from the LSP already stored for this area
 *
 * @param area	ISIS area
 */
void isis_te_init_ted(struct isis_area *area)
{
	struct isis_lsp *lsp;

	/* Iterate over all lsp. */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++)
		frr_each (lspdb, &area->lspdb[level - 1], lsp)
			isis_te_parse_lsp(area->mta, lsp);

}

/* Followings are vty command functions */
#ifndef FABRICD

DEFUN(show_isis_mpls_te_router,
      show_isis_mpls_te_router_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] mpls-te router",
      SHOW_STR
      PROTO_HELP
      VRF_CMD_HELP_STR "All VRFs\n"
      MPLS_TE_STR "Router information\n")
{

	struct listnode *anode, *inode;
	struct isis_area *area;
	struct isis *isis = NULL;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}
	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (vrf_name) {
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
				for (ALL_LIST_ELEMENTS_RO(isis->area_list,
							  anode, area)) {
					if (!IS_MPLS_TE(area->mta))
						continue;

					vty_out(vty, "Area %s:\n",
						area->area_tag);
					if (ntohs(area->mta->router_id.s_addr)
					    != 0)
						vty_out(vty,
							"  MPLS-TE Router-Address: %pI4\n",
							&area->mta->router_id);
					else
						vty_out(vty, "  N/A\n");
				}
			}
			return 0;
		}
		isis = isis_lookup_by_vrfname(vrf_name);
		if (isis != NULL) {
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode,
						  area)) {

				if (!IS_MPLS_TE(area->mta))
					continue;

				vty_out(vty, "Area %s:\n", area->area_tag);
				if (ntohs(area->mta->router_id.s_addr) != 0)
					vty_out(vty,
						"  MPLS-TE Router-Address: %pI4\n",
						&area->mta->router_id);
				else
					vty_out(vty, "  N/A\n");
			}
		}
	}

	return CMD_SUCCESS;
}

static void show_ext_sub(struct vty *vty, char *name,
			 struct isis_ext_subtlvs *ext)
{
	struct sbuf buf;
	char ibuf[PREFIX2STR_BUFFER];

	sbuf_init(&buf, NULL, 0);

	if (!ext || ext->status == EXT_DISABLE)
		return;

	vty_out(vty, "-- MPLS-TE link parameters for %s --\n", name);

	sbuf_reset(&buf);

	if (IS_SUBTLV(ext, EXT_ADM_GRP))
		sbuf_push(&buf, 4, "Administrative Group: 0x%x\n",
			ext->adm_group);
	if (IS_SUBTLV(ext, EXT_LLRI)) {
		sbuf_push(&buf, 4, "Link Local  ID: %u\n",
			  ext->local_llri);
		sbuf_push(&buf, 4, "Link Remote ID: %u\n",
			  ext->remote_llri);
	}
	if (IS_SUBTLV(ext, EXT_LOCAL_ADDR))
		sbuf_push(&buf, 4, "Local Interface IP Address(es): %pI4\n",
			  &ext->local_addr);
	if (IS_SUBTLV(ext, EXT_NEIGH_ADDR))
		sbuf_push(&buf, 4, "Remote Interface IP Address(es): %pI4\n",
			  &ext->neigh_addr);
	if (IS_SUBTLV(ext, EXT_LOCAL_ADDR6))
		sbuf_push(&buf, 4, "Local Interface IPv6 Address(es): %s\n",
			  inet_ntop(AF_INET6, &ext->local_addr6, ibuf,
				    PREFIX2STR_BUFFER));
	if (IS_SUBTLV(ext, EXT_NEIGH_ADDR6))
		sbuf_push(&buf, 4, "Remote Interface IPv6 Address(es): %s\n",
			  inet_ntop(AF_INET6, &ext->local_addr6, ibuf,
				    PREFIX2STR_BUFFER));
	if (IS_SUBTLV(ext, EXT_MAX_BW))
		sbuf_push(&buf, 4, "Maximum Bandwidth: %g (Bytes/sec)\n",
			  ext->max_bw);
	if (IS_SUBTLV(ext, EXT_MAX_RSV_BW))
		sbuf_push(&buf, 4,
			  "Maximum Reservable Bandwidth: %g (Bytes/sec)\n",
			  ext->max_rsv_bw);
	if (IS_SUBTLV(ext, EXT_UNRSV_BW)) {
		sbuf_push(&buf, 4, "Unreserved Bandwidth:\n");
		for (int j = 0; j < MAX_CLASS_TYPE; j += 2) {
			sbuf_push(&buf, 4 + 2,
				  "[%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n",
				  j, ext->unrsv_bw[j],
				  j + 1, ext->unrsv_bw[j + 1]);
		}
	}
	if (IS_SUBTLV(ext, EXT_TE_METRIC))
		sbuf_push(&buf, 4, "Traffic Engineering Metric: %u\n",
			  ext->te_metric);
	if (IS_SUBTLV(ext, EXT_RMT_AS))
		sbuf_push(&buf, 4,
			  "Inter-AS TE Remote AS number: %u\n",
			  ext->remote_as);
	if (IS_SUBTLV(ext, EXT_RMT_IP))
		sbuf_push(&buf, 4,
			  "Inter-AS TE Remote ASBR IP address: %pI4\n",
			  &ext->remote_ip);
	if (IS_SUBTLV(ext, EXT_DELAY))
		sbuf_push(&buf, 4,
			  "%s Average Link Delay: %u (micro-sec)\n",
			  IS_ANORMAL(ext->delay) ? "Anomalous" : "Normal",
			  ext->delay);
	if (IS_SUBTLV(ext, EXT_MM_DELAY)) {
		sbuf_push(&buf, 4, "%s Min/Max Link Delay: %u / %u (micro-sec)\n",
			  IS_ANORMAL(ext->min_delay) ? "Anomalous" : "Normal",
			  ext->min_delay & TE_EXT_MASK,
			  ext->max_delay & TE_EXT_MASK);
	}
	if (IS_SUBTLV(ext, EXT_DELAY_VAR))
		sbuf_push(&buf, 4,
			  "Delay Variation: %u (micro-sec)\n",
			  ext->delay_var & TE_EXT_MASK);
	if (IS_SUBTLV(ext, EXT_PKT_LOSS))
		sbuf_push(&buf, 4, "%s Link Packet Loss: %g (%%)\n",
			  IS_ANORMAL(ext->pkt_loss) ? "Anomalous" : "Normal",
			  (float)((ext->pkt_loss & TE_EXT_MASK)
				  * LOSS_PRECISION));
	if (IS_SUBTLV(ext, EXT_RES_BW))
		sbuf_push(&buf, 4,
			  "Unidirectional Residual Bandwidth: %g (Bytes/sec)\n",
			  ext->res_bw);
	if (IS_SUBTLV(ext, EXT_AVA_BW))
		sbuf_push(&buf, 4,
			  "Unidirectional Available Bandwidth: %g (Bytes/sec)\n",
			  ext->ava_bw);
	if (IS_SUBTLV(ext, EXT_USE_BW))
		sbuf_push(&buf, 4,
			  "Unidirectional Utilized Bandwidth: %g (Bytes/sec)\n",
			  ext->use_bw);

	vty_multiline(vty, "", "%s", sbuf_buf(&buf));
	vty_out(vty, "---------------\n\n");

	sbuf_free(&buf);
	return;
}

DEFUN (show_isis_mpls_te_interface,
       show_isis_mpls_te_interface_cmd,
       "show " PROTO_NAME " mpls-te interface [INTERFACE]",
       SHOW_STR
       PROTO_HELP
       MPLS_TE_STR
       "Interface information\n"
       "Interface name\n")
{
	struct listnode *anode, *cnode, *inode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct interface *ifp;
	int idx_interface = 4;
	struct isis *isis = NULL;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (argc == idx_interface) {
		/* Show All Interfaces. */
		for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode,
						  area)) {

				if (!IS_MPLS_TE(area->mta))
					continue;

				vty_out(vty, "Area %s:\n", area->area_tag);

				for (ALL_LIST_ELEMENTS_RO(area->circuit_list,
							  cnode, circuit))
					show_ext_sub(vty,
						     circuit->interface->name,
						     circuit->ext);
			}
		}
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name(argv[idx_interface]->arg, VRF_DEFAULT);
		if (ifp == NULL)
			vty_out(vty, "No such interface name\n");
		else {
			circuit = circuit_scan_by_ifp(ifp);
			if (!circuit)
				vty_out(vty,
					"ISIS is not enabled on circuit %s\n",
					ifp->name);
			else
				show_ext_sub(vty, ifp->name, circuit->ext);
		}
	}

	return CMD_SUCCESS;
}

static int show_ted(struct vty *vty, struct cmd_token *argv[], int argc,
		    struct ls_ted *ted)
{
	int idx = 0;
	struct in_addr ip_addr;
	struct prefix pref;
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	uint64_t key;
	bool verbose = false;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	idx = 5;
	if (argv_find(argv, argc, "vertex", &idx)) {
		/* Show Vertex */
		if (argv_find(argv, argc, "self-originate", &idx))
			vertex = ted->self;
		else if (argv_find(argv, argc, "adv-router", &idx)) {
			if (!inet_aton(argv[idx + 1]->arg, &ip_addr)) {
				vty_out(vty,
					"Specified Router ID %s is invalid\n",
					argv[idx + 1]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Vertex from the Link State Database */
			key = ((uint64_t)ntohl(ip_addr.s_addr)) & 0xffffffff;
			vertex = ls_find_vertex_by_key(ted, key);
			if (!vertex) {
				vty_out(vty, "No vertex found for ID %pI4\n",
					&ip_addr);
				return CMD_WARNING;
			}
		} else
			vertex = NULL;

		if (vertex)
			ls_show_vertex(vertex, vty, json, verbose);
		else
			ls_show_vertices(ted, vty, json, verbose);

	} else if (argv_find(argv, argc, "edge", &idx)) {
		/* Show Edge */
		if (argv_find(argv, argc, "A.B.C.D", &idx)) {
			if (!inet_aton(argv[idx]->arg, &ip_addr)) {
				vty_out(vty,
					"Specified Edge ID %s is invalid\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Edge from the Link State Database */
			key = ((uint64_t)ntohl(ip_addr.s_addr)) & 0xffffffff;
			edge = ls_find_edge_by_key(ted, key);
			if (!edge) {
				vty_out(vty, "No edge found for ID %pI4\n",
					&ip_addr);
				return CMD_WARNING;
			}
		} else
			edge = NULL;

		if (edge)
			ls_show_edge(edge, vty, json, verbose);
		else
			ls_show_edges(ted, vty, json, verbose);

	} else if (argv_find(argv, argc, "subnet", &idx)) {
		/* Show Subnet */
		if (argv_find(argv, argc, "A.B.C.D/M", &idx)) {
			if (!str2prefix(argv[idx]->arg, &pref)) {
				vty_out(vty, "Invalid prefix format %s\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Subnet from the Link State Database */
			subnet = ls_find_subnet(ted, pref);
			if (!subnet) {
				vty_out(vty, "No subnet found for ID %pFX\n",
					&pref);
				return CMD_WARNING;
			}
		} else
			subnet = NULL;

		if (subnet)
			ls_show_subnet(subnet, vty, json, verbose);
		else
			ls_show_subnets(ted, vty, json, verbose);

	} else {
		/* Show the complete TED */
		ls_show_ted(ted, vty, json, verbose);
	}

	if (uj) {
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

static int show_isis_ted(struct vty *vty, struct cmd_token *argv[], int argc,
			 struct isis *isis)
{
	struct listnode *node;
	struct isis_area *area;
	int rc;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");
		rc = show_ted(vty, argv, argc, area->mta->ted);
		if (rc != CMD_SUCCESS)
			return rc;
	}
	return CMD_SUCCESS;
}

DEFUN (show_isis_mpls_te_db,
       show_isis_mpls_te_db_cmd,
       "show " PROTO_NAME " [vrf <NAME|all>] mpls-te database [<vertex [<self-originate|adv-router A.B.C.D>]|edge [A.B.C.D]|subnet [A.B.C.D/M]>] [detail|json]",
       SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
       "All VRFs\n"
       MPLS_TE_STR
       "MPLS-TE database\n"
       "MPLS-TE Vertex\n"
       "Self-originated MPLS-TE router\n"
       "Advertised MPLS-TE router\n"
       "MPLS-TE router ID (as an IP address)\n"
       "MPLS-TE Edge\n"
       "MPLS-TE Edge ID (as an IP address)\n"
       "MPLS-TE Subnet\n"
       "MPLS-TE Subnet ID (as an IP prefix)\n"
       "Detailed information\n"
       JSON_STR)
{
	int idx_vrf = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	struct listnode *node;
	struct isis *isis;
	int rc = CMD_WARNING;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (vrf_name) {
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
				rc = show_isis_ted(vty, argv, argc, isis);
				if (rc != CMD_SUCCESS)
					return rc;
			}
			return CMD_SUCCESS;
		}
		isis = isis_lookup_by_vrfname(vrf_name);
		if (isis)
			rc = show_isis_ted(vty, argv, argc, isis);
	}

	return rc;
}

#endif /* #ifndef FRABRICD */

/* Initialize MPLS_TE */
void isis_mpls_te_init(void)
{

	/* Register Circuit and Adjacency hook */
	hook_register(isis_if_new_hook, isis_mpls_te_update);
	hook_register(isis_adj_state_change_hook, isis_link_update_adj_hook);


#ifndef FABRICD
	/* Register new VTY commands */
	install_element(VIEW_NODE, &show_isis_mpls_te_router_cmd);
	install_element(VIEW_NODE, &show_isis_mpls_te_interface_cmd);
	install_element(VIEW_NODE, &show_isis_mpls_te_db_cmd);
#endif

	return;
}
