/*
 * This is an implementation of Segment Routing for IS-IS
 * as per draft draft-ietf-isis-segment-routing-extensions-22
 *
 * Module name: Segment Routing
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2019 Orange Labs http://www.orange.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <zebra.h>

#include "command.h"
#include "hash.h"
#include "if.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "monotime.h"
#include "network.h"
#include "prefix.h"
#include "sockunion.h" /* for inet_aton() */
#include "stream.h"
#include "table.h"
#include "thread.h"
#include "vty.h"
#include "zclient.h"
#include <lib/json.h>
#include "isis_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_zebra.h"

/*
 * Global variable to manage Segment Routing on this node.
 * Note that all parameter values are stored in network byte order.
 */
static void isis_sr_register_vty(void);
static inline void del_sid_nhlfe(struct sr_nhlfe nhlfe);
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event);

/*
 * Segment Routing Data Base functions
 */

/* Hash function for Segment Routing entry */
static unsigned int sr_hash(void *p)
{
	const struct in_addr *rid = p;

	return jhash_1word(rid->s_addr, 0);
}

/* Compare 2 Router ID hash entries based on SR Node */
static bool sr_cmp(const void *p1, const void *p2)
{
	const struct sr_node *srn = p1;
	const struct in_addr *rid = p2;

	return IPV4_ADDR_SAME(&srn->adv_router, rid);
}

/* Functions to remove an SR Link */
static void del_sr_link(void *val)
{
	struct sr_link *srl = (struct sr_link *)val;

	del_sid_nhlfe(srl->nhlfe[0]);
	del_sid_nhlfe(srl->nhlfe[1]);
	XFREE(MTYPE_ISIS_SR, val);
}

/* Functions to remove an SR Prefix */
static void del_sr_pref(void *val)
{
	struct sr_prefix *srp = (struct sr_prefix *)val;

	del_sid_nhlfe(srp->nhlfe);
	XFREE(MTYPE_ISIS_SR, val);
}

/* Allocate new Segment Routine Node */
static struct sr_node *sr_node_new(struct in_addr *rid)
{

	if (rid == NULL)
		return NULL;

	struct sr_node *new;

	/* Allocate Segment Routing node memory */
	new = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_node));

	/* Default Algorithm, SRGB and MSD */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		new->algo[i] = SR_ALGORITHM_UNSET;

	new->srgb.range_size = 0;
	new->srgb.lower_bound = 0;
	new->msd = 0;

	/* Create Link, Prefix and Range TLVs list */
	new->ext_link = list_new();
	new->ext_prefix = list_new();
	new->ext_link->del = del_sr_link;
	new->ext_prefix->del = del_sr_pref;

	IPV4_ADDR_COPY(&new->adv_router, rid);
	new->neighbor = NULL;
	new->instance = 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Created new SR node for %s",
			   inet_ntoa(new->adv_router));
	return new;
}

/* Delete Segment Routing node */
static void sr_node_del(struct sr_node *srn)
{
	/* Sanity Check */
	if (srn == NULL)
		return;

	/* Clean Extended Link */
	list_delete(&srn->ext_link);

	/* Clean Prefix List */
	list_delete(&srn->ext_prefix);

	XFREE(MTYPE_ISIS_SR, srn);
}

/* Get SR Node for a given nexthop */
static struct sr_node *get_sr_node_by_nexthop(struct isis_area *area,
					      struct in_addr nexthop)
{
	struct isis_interface *oi = NULL;
	struct isis_neighbor *nbr = NULL;
	struct listnode *node;
	struct route_node *rn;
	struct sr_node *srn;
	bool found;

	/* Sanity check */
	if (area->srdb == NULL || area->srdb->neighbors == NULL)
		return NULL;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("      |-  Search SR-Node for nexthop %s",
			   inet_ntoa(nexthop));

	/* First, search neighbor Router ID for this nexthop */
	found = false;
	for (ALL_LIST_ELEMENTS_RO(isis->oiflist, node, oi)) {
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;
			if ((nbr) && (IPV4_ADDR_SAME(&nexthop, &nbr->src))) {
				found = true;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found)
		return NULL;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("      |-  Found nexthop Router ID %s",
			   inet_ntoa(nbr->router_id));
	/* Then, search SR Node */
	srn = (struct sr_node *)hash_lookup(area->srdb->neighbors, &nbr->router_id);

	return srn;
}

/*
 * Segment Routing Initialization functions
 */

/* Segment Routing starter function */
static int isis_sr_start(struct isis_area *area)
{
	struct sr_node *srn;
	int rc = 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Start Segment Routing", __func__);

	if (area == NULL)
		return rc;

	/* Initialize self SR Node */
	if (area->srdb == NULL)
		area->srdb = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_sr_db));

	srn = hash_get(area->srdb->neighbors, (void *)&(area->isis->router_id),
		       (void *)sr_node_new);

	/* Complete & Store self SR Node */
	srn->srgb.range_size = area->srdb->srgb.range_size;
	srn->srgb.lower_bound = area->srdb->srgb.lower_bound;
	srn->algo[0] = area->srdb->algo[0];
	srn->msd = area->srdb->msd;
	area->srdb->self = srn;

	if (IS_DEBUG_ISIS(DEBUG_EVENTS))
		zlog_debug("SR (%s): Update SR-DB from LSDB", __func__);

	/* Start by looking to Router Info & Extended LSA in lsdb */
	lsp_regenerate_schedule(area, area->is_type, 0);

	rc = 1;
	return rc;
}

/* Stop Segment Routing */
static void isis_sr_stop(struct isis_area *area)
{

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Stop Segment Routing", __func__);

	/*
	 * Remove all SR Nodes from the Hash table. Prefix and Link SID will
	 * be remove though list_delete() call. See sr_node_del()
	 */
	hash_clean(area->srdb->neighbors, (void *)sr_node_del);
}

/*
 * Segment Routing initialize function
 *
 * @param - nothing
 *
 * @return 0 if OK, -1 otherwise
 */
int isis_sr_init(struct isis_area *area)
{
	int rc = -1;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_info("SR (%s): Initialize SR Data Base", __func__);

	memset(&area->srdb, 0, sizeof(struct isis_sr_db));
	area->srdb->enabled = false;
	/* Only AREA flooding is supported in this release */
	area->srdb->scope = area->is_type;

	/* Initialize SRGB, Algorithms and MSD TLVs */
	/* Only Algorithm SPF is supported */
	area->srdb->algo[0] = SR_ALGORITHM_SPF;
	for (int i = 1; i < SR_ALGORITHM_COUNT; i++)
		area->srdb->algo[i] = SR_ALGORITHM_UNSET;

	area->srdb->srgb.range_size = MPLS_DEFAULT_MAX_SRGB_SIZE;
	area->srdb->srgb.lower_bound = MPLS_DEFAULT_MIN_SRGB_LABEL;
	area->srdb->msd = 0;

	/* Initialize Hash table for neighbor SR nodes */
	area->srdb->neighbors = hash_create(sr_hash, sr_cmp, "ISIS_SR");
	if (area->srdb->neighbors == NULL)
		return rc;

	/* Initialize Route Table for prefix */
	area->srdb->prefix = route_table_init();
	if (area->srdb->prefix == NULL)
		return rc;

	/* Register Segment Routing VTY command */
	isis_sr_register_vty();

	/* Register LSP event hook */
	hook_register_prio(isis_lsp_event_hook, 100, srdb_lsp_event);

	rc = 0;
	return rc;
}

/*
 * Segment Routing termination function
 *
 * @param - nothing
 * @return - nothing
 */
void isis_sr_term(struct isis_area *area)
{

	/* Stop Segment Routing */
	isis_sr_stop(area);

	/* Clear SR Node Table */
	if (area->srdb->neighbors)
		hash_free(area->srdb->neighbors);

	/* Clear Prefix Table */
	if (area->srdb->prefix)
		route_table_finish(area->srdb->prefix);

	area->srdb->enabled = false;
	area->srdb->self = NULL;
}

/*
 * Segment Routing finish function
 *
 * @param - nothing
 * @return - nothing
 */
void isis_sr_finish(struct isis_area *area)
{
	/* Stop Segment Routing */
	isis_sr_stop(area);

	area->srdb->enabled = false;
}

/*
 * Following functions are used to manipulate the
 * Next Hop Label Forwarding entry (NHLFE)
 */

/* Compute label from index */
static mpls_label_t index2label(uint32_t index, struct sr_srgb srgb)
{
	mpls_label_t label;

	label = srgb.lower_bound + index;
	if (label > (srgb.lower_bound + srgb.range_size))
		return MPLS_INVALID_LABEL;
	else
		return label;
}

/* Get neighbor full structure from address */
static struct isis_nexthop *get_neighbor_by_addr(struct isis_area *area,
						 struct in_addr addr)
{
	struct isis_spftree *tree;
	struct isis_route_info *rinfo;
	struct route_node *rn;
	struct isis_nexthop *nh;
	struct listnode *node;
	uint8_t level;

	/* Sanity Check */
	if (area == NULL)
		return NULL;

	/* TODO: Take into account when area is Level 1 & 2 */
	level = area->is_type == IS_LEVEL_1 ? 0 : 1;
	tree = area->spftree[SPFTREE_IPV4][level];
	for (rn = route_top(tree->route_table); rn;
	     rn = srcdest_route_next(rn)) {
		if (rn->info == NULL)
			continue;
		rinfo = rn->info;

		for (ALL_LIST_ELEMENTS_RO(rinfo->nexthops, node, nh))
			if (IPV4_ADDR_SAME(&nh->ip, &addr)
			    || IPV4_ADDR_SAME(&nh->router_address, &addr))
				return nh;
	}
	return NULL;
}

/* Get ISIS Path from address */
static struct isis_path *get_nexthop_by_addr(struct isis *top,
					     struct prefix_ipv4 p)
{
	struct isis_route * or ;
	struct isis_path *path;
	struct listnode *node;
	struct route_node *rn;

	/* Sanity Check */
	if (top == NULL)
		return NULL;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("      |-  Search Nexthop for prefix %s/%u",
			   inet_ntoa(p.prefix), p.prefixlen);

	rn = route_node_lookup(top->new_table, (struct prefix *)&p);

	/*
	 * Check if we found an ISIS route. May be NULL if SPF has not
	 * yet populate routing table for this prefix.
	 */
	if (rn == NULL)
		return NULL;

	route_unlock_node(rn);
	or = rn->info;
	if (or == NULL)
		return NULL;

	/* Then search path from this route */
	for (ALL_LIST_ELEMENTS_RO(or->paths, node, path))
		if (path->nexthop.s_addr != INADDR_ANY || path->ifindex != 0)
			return path;

	return NULL;
}

/* Compute NHLFE entry for Extended Link */
static int compute_link_nhlfe(struct sr_link *srl)
{
	struct isis *top = isis_lookup_by_vrf_id(VRF_DEFAULT);
	struct isis_nexthop *nh;
	int rc = 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Compute NHLFE for link %s/%u",
			   inet_ntoa(srl->nhlfe[0].prefv4.prefix),
			   srl->nhlfe[0].prefv4.prefixlen);

	/* First determine the ISIS Neighbor */
	nh = get_neighbor_by_addr(top, srl->nhlfe[0].nexthop);

	/* Neighbor could be not found when ISIS Adjacency just fire up
	 * because SPF don't yet populate routing table. This NHLFE will
	 * be fixed later when SR SPF schedule will be called.
	 */
	if (nh == NULL)
		return rc;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Found nexthop NHLFE %s",
			   inet_ntoa(nh->router_address));

	/* Set ifindex for this neighbor */
	srl->nhlfe[0].ifindex = nh->ifindex;
	srl->nhlfe[1].ifindex = nh->ifindex;

	/* Update neighbor address for LAN_ADJ_SID */
	if (srl->type == LAN_ADJ_SID) {
		IPV4_ADDR_COPY(&srl->nhlfe[0].nexthop, &nh->src);
		IPV4_ADDR_COPY(&srl->nhlfe[1].nexthop, &nh->src);
	}

	/* Set Input & Output Label */
	if (CHECK_FLAG(srl->flags[0], EXT_SUBTLV_LINK_ADJ_SID_VFLG))
		srl->nhlfe[0].label_in = srl->sid[0];
	else
		srl->nhlfe[0].label_in =
			index2label(srl->sid[0], srl->srn->srgb);
	if (CHECK_FLAG(srl->flags[1], EXT_SUBTLV_LINK_ADJ_SID_VFLG))
		srl->nhlfe[1].label_in = srl->sid[1];
	else
		srl->nhlfe[1].label_in =
			index2label(srl->sid[1], srl->srn->srgb);

	srl->nhlfe[0].label_out = MPLS_LABEL_IMPLICIT_NULL;
	srl->nhlfe[1].label_out = MPLS_LABEL_IMPLICIT_NULL;

	rc = 1;
	return rc;
}

/*
 * Compute NHLFE entry for Extended Prefix
 *
 * @param srp - Segment Routing Prefix
 *
 * @return -1 if next hop is not found, 0 if nexthop has not changed
 *         and 1 if success
 */
static int compute_prefix_nhlfe(struct sr_prefix *srp)
{
	struct isis *top = isis_lookup_by_vrf_id(VRF_DEFAULT);
	struct isis_path *nh = NULL;
	struct sr_node *srnext;
	int rc = -1;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Compute NHLFE for prefix %s/%u",
			   inet_ntoa(srp->nhlfe.prefv4.prefix),
			   srp->nhlfe.prefv4.prefixlen);

	/* First determine the nexthop */
	nh = get_nexthop_by_addr(top, srp->nhlfe.prefv4);

	/* Nexthop could be not found when ISIS Adjacency just fire up
	 * because SPF don't yet populate routing table. This NHLFE will
	 * be fixed later when SR SPF schedule will be called.
	 */
	if (nh == NULL)
		return rc;

	/* Check if NextHop has changed when call after running a new SPF */
	if (IPV4_ADDR_SAME(&nh->nexthop, &srp->nhlfe.nexthop)
	    && (nh->ifindex == srp->nhlfe.ifindex))
		return 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Found new next hop for this NHLFE: %s",
			   inet_ntoa(nh->nexthop));

	/*
	 * Get SR-Node for this nexthop. Could be not yet available
	 * if Extended IS / IP and Router Information TLVs are not
	 * yet present in the LSP_DB
	 */
	srnext = get_sr_node_by_nexthop(top, nh->nexthop);
	if (srnext == NULL)
		return rc;

	/* And store this information for later update if SR Node is found */
	srnext->neighbor = area->srdb->self;
	if (IPV4_ADDR_SAME(&srnext->adv_router, &srp->adv_router))
		srp->nexthop = NULL;
	else
		srp->nexthop = srnext;

	/*
	 * SR Node could be known, but SRGB could be not initialized
	 */
	if ((srnext == NULL) || (srnext->srgb.lower_bound == 0)
	    || (srnext->srgb.range_size == 0))
		return rc;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Found SRGB %u/%u for next hop SR-Node %s",
			   srnext->srgb.range_size, srnext->srgb.lower_bound,
			   inet_ntoa(srnext->adv_router));

	/* Set ip addr & ifindex for this neighbor */
	IPV4_ADDR_COPY(&srp->nhlfe.nexthop, &nh->nexthop);
	srp->nhlfe.ifindex = nh->ifindex;

	/* Compute Input Label with self SRGB */
	srp->nhlfe.label_in = index2label(srp->sid, area->srdb->srgb);
	/*
	 * and Output Label with Next hop SR Node SRGB or Implicit Null label
	 * if next hop is the destination and request PHP
	 */
	if ((srp->nexthop == NULL)
	    && (!CHECK_FLAG(srp->flags, SUBTLV_PREFIX_SID_NPFLG)))
		srp->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
	else if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_VFLG))
		srp->nhlfe.label_out = srp->sid;
	else
		srp->nhlfe.label_out = index2label(srp->sid, srnext->srgb);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Computed new labels in: %u out: %u",
			   srp->nhlfe.label_in, srp->nhlfe.label_out);

	rc = 1;
	return rc;
}

/* Send MPLS Label entry to Zebra for installation or deletion */
static int isis_zebra_send_mpls_labels(int cmd, struct sr_nhlfe nhlfe)
{
	struct stream *s;

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_putc(s, ZEBRA_LSP_SR);
	/* ISIS Segment Routing currently support only IPv4 */
	stream_putl(s, nhlfe.prefv4.family);
	stream_put_in_addr(s, &nhlfe.prefv4.prefix);
	stream_putc(s, nhlfe.prefv4.prefixlen);
	stream_put_in_addr(s, &nhlfe.nexthop);
	stream_putl(s, nhlfe.ifindex);
	stream_putc(s, ISIS_SR_PRIORITY_DEFAULT);
	stream_putl(s, nhlfe.label_in);
	stream_putl(s, nhlfe.label_out);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  %s MPLS entry %u/%u for %s/%u via %u",
			   cmd == ZEBRA_MPLS_LABELS_ADD ? "Add" : "Delete",
			   nhlfe.label_in, nhlfe.label_out,
			   inet_ntoa(nhlfe.prefv4.prefix),
			   nhlfe.prefv4.prefixlen, nhlfe.ifindex);

	return zclient_send_message(zclient);
}

/* Request zebra to install/remove FEC in FIB */
static int isis_zebra_send_mpls_ftn(int cmd, struct sr_nhlfe nhlfe)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;

	/* Support only IPv4 */
	if (nhlfe.prefv4.family != AF_INET)
		return -1;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_ISIS;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, &nhlfe.prefv4, sizeof(struct prefix_ipv4));

	if (cmd == ZEBRA_ROUTE_ADD) {
		/* Metric value. */
		SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
		api.metric = ISIS_SR_DEFAULT_METRIC;
		/* Nexthop */
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		api_nh = &api.nexthops[0];
		IPV4_ADDR_COPY(&api_nh->gate.ipv4, &nhlfe.nexthop);
		api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		api_nh->ifindex = nhlfe.ifindex;
		/* MPLS labels */
		SET_FLAG(api.message, ZAPI_MESSAGE_LABEL);
		api_nh->labels[0] = nhlfe.label_out;
		api_nh->label_num = 1;
		api_nh->vrf_id = VRF_DEFAULT;
		api.nexthop_num = 1;
	}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  %s FEC %u for %s/%u via %u",
			   cmd == ZEBRA_ROUTE_ADD ? "Add" : "Delete",
			   nhlfe.label_out, inet_ntoa(nhlfe.prefv4.prefix),
			   nhlfe.prefv4.prefixlen, nhlfe.ifindex);

	return zclient_route_send(cmd, zclient, &api);
}

/* Add new NHLFE entry for SID */
static inline void add_sid_nhlfe(struct sr_nhlfe nhlfe)
{
	if ((nhlfe.label_in != 0) && (nhlfe.label_out != 0)) {
		isis_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_ADD, nhlfe);
		if (nhlfe.label_out != MPLS_LABEL_IMPLICIT_NULL)
			isis_zebra_send_mpls_ftn(ZEBRA_ROUTE_ADD, nhlfe);
	}
}

/* Remove NHLFE entry for SID */
static inline void del_sid_nhlfe(struct sr_nhlfe nhlfe)
{
	if ((nhlfe.label_in != 0) && (nhlfe.label_out != 0)) {
		isis_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_DELETE, nhlfe);
		if (nhlfe.label_out != MPLS_LABEL_IMPLICIT_NULL)
			isis_zebra_send_mpls_ftn(ZEBRA_ROUTE_DELETE, nhlfe);
	}
}

/* Update NHLFE entry for SID */
static inline void update_sid_nhlfe(struct sr_nhlfe n1, struct sr_nhlfe n2)
{

	del_sid_nhlfe(n1);
	add_sid_nhlfe(n2);
}

/*
 * Functions to parse and get Extended Link / Prefix
 * TLVs and SubTLVs
 */

/* Extended Link SubTLVs Getter */
static struct sr_link *get_ext_link_sid(struct tlv_header *tlvh)
{

	struct sr_link *srl;
	struct ext_tlv_link *link = (struct ext_tlv_link *)tlvh;
	struct ext_subtlv_adj_sid *adj_sid;
	struct ext_subtlv_lan_adj_sid *lan_sid;
	struct ext_subtlv_rmt_itf_addr *rmt_itf;

	struct tlv_header *sub_tlvh;
	uint16_t length = 0, sum = 0, i = 0;

	srl = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_link));

	/* Initialize TLV browsing */
	length = ntohs(tlvh->length) - EXT_TLV_LINK_SIZE;
	sub_tlvh = (struct tlv_header *)((char *)(tlvh) + TLV_HDR_SIZE
					 + EXT_TLV_LINK_SIZE);
	for (; sum < length; sub_tlvh = TLV_HDR_NEXT(sub_tlvh)) {
		switch (ntohs(sub_tlvh->type)) {
		case EXT_SUBTLV_ADJ_SID:
			adj_sid = (struct ext_subtlv_adj_sid *)sub_tlvh;
			srl->type = ADJ_SID;
			i = CHECK_FLAG(adj_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_BFLG)
				    ? 1
				    : 0;
			srl->flags[i] = adj_sid->flags;
			if (CHECK_FLAG(adj_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
				srl->sid[i] = GET_LABEL(ntohl(adj_sid->value));
			else
				srl->sid[i] = ntohl(adj_sid->value);
			IPV4_ADDR_COPY(&srl->nhlfe[i].nexthop, &link->link_id);
			break;
		case EXT_SUBTLV_LAN_ADJ_SID:
			lan_sid = (struct ext_subtlv_lan_adj_sid *)sub_tlvh;
			srl->type = LAN_ADJ_SID;
			i = CHECK_FLAG(lan_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_BFLG)
				    ? 1
				    : 0;
			srl->flags[i] = lan_sid->flags;
			if (CHECK_FLAG(lan_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
				srl->sid[i] = GET_LABEL(ntohl(lan_sid->value));
			else
				srl->sid[i] = ntohl(lan_sid->value);
			IPV4_ADDR_COPY(&srl->nhlfe[i].nexthop,
				       &lan_sid->neighbor_id);
			break;
		case EXT_SUBTLV_RMT_ITF_ADDR:
			rmt_itf = (struct ext_subtlv_rmt_itf_addr *)sub_tlvh;
			IPV4_ADDR_COPY(&srl->nhlfe[0].nexthop, &rmt_itf->value);
			IPV4_ADDR_COPY(&srl->nhlfe[1].nexthop, &rmt_itf->value);
			break;
		default:
			break;
		}
		sum += TLV_SIZE(sub_tlvh);
	}

	IPV4_ADDR_COPY(&srl->nhlfe[0].prefv4.prefix, &link->link_data);
	srl->nhlfe[0].prefv4.prefixlen = IPV4_MAX_PREFIXLEN;
	srl->nhlfe[0].prefv4.family = AF_INET;
	apply_mask_ipv4(&srl->nhlfe[0].prefv4);
	IPV4_ADDR_COPY(&srl->nhlfe[1].prefv4.prefix, &link->link_data);
	srl->nhlfe[1].prefv4.prefixlen = IPV4_MAX_PREFIXLEN;
	srl->nhlfe[1].prefv4.family = AF_INET;
	apply_mask_ipv4(&srl->nhlfe[1].prefv4);

	if (IS_DEBUG_ISIS(DEBUG_SR)) {
		zlog_debug("  |-  Found primary Adj/Lan Sid %u for %s/%u",
			   srl->sid[0], inet_ntoa(srl->nhlfe[0].prefv4.prefix),
			   srl->nhlfe[0].prefv4.prefixlen);
		zlog_debug("  |-  Found backup Adj/Lan Sid %u for %s/%u",
			   srl->sid[1], inet_ntoa(srl->nhlfe[1].prefv4.prefix),
			   srl->nhlfe[1].prefv4.prefixlen);
	}

	return srl;
}

/* Extended Prefix SubTLVs Getter */
static struct sr_prefix *get_ext_prefix_sid(struct tlv_header *tlvh)
{

	struct sr_prefix *srp;
	struct ext_tlv_prefix *pref = (struct ext_tlv_prefix *)tlvh;
	struct ext_subtlv_prefix_sid *psid;

	struct tlv_header *sub_tlvh;
	uint16_t length = 0, sum = 0;

	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));

	/* Initialize TLV browsing */
	length = ntohs(tlvh->length) - EXT_TLV_PREFIX_SIZE;
	sub_tlvh = (struct tlv_header *)((char *)(tlvh) + TLV_HDR_SIZE
					 + EXT_TLV_PREFIX_SIZE);
	for (; sum < length; sub_tlvh = TLV_HDR_NEXT(sub_tlvh)) {
		switch (ntohs(sub_tlvh->type)) {
		case EXT_SUBTLV_PREFIX_SID:
			psid = (struct ext_subtlv_prefix_sid *)sub_tlvh;
			if (psid->algorithm != SR_ALGORITHM_SPF) {
				flog_err(EC_ISIS_INVALID_ALGORITHM,
					 "SR (%s): Unsupported Algorithm",
					 __func__);
				XFREE(MTYPE_ISIS_SR, srp);
				return NULL;
			}
			srp->type = PREF_SID;
			srp->flags = psid->flags;
			if (CHECK_FLAG(psid->flags, EXT_SUBTLV_PREFIX_SID_VFLG))
				srp->sid = GET_LABEL(ntohl(psid->value));
			else
				srp->sid = ntohl(psid->value);
			IPV4_ADDR_COPY(&srp->nhlfe.prefv4.prefix,
				       &pref->address);
			srp->nhlfe.prefv4.prefixlen = pref->pref_length;
			srp->nhlfe.prefv4.family = AF_INET;
			apply_mask_ipv4(&srp->nhlfe.prefv4);
			break;
		default:
			break;
		}
		sum += TLV_SIZE(sub_tlvh);
	}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Found SID %u for prefix %s/%u", srp->sid,
			   inet_ntoa(srp->nhlfe.prefv4.prefix),
			   srp->nhlfe.prefv4.prefixlen);
	return srp;
}

/*
 * Functions to manipulate Segment Routing Link & Prefix structures
 */

/* Compare two Segment Link: return 0 if equal, 1 otherwise */
static inline int sr_link_cmp(struct sr_link *srl1, struct sr_link *srl2)
{
	if ((srl1->sid[0] == srl2->sid[0]) && (srl1->sid[1] == srl2->sid[1])
	    && (srl1->type == srl2->type) && (srl1->flags[0] == srl2->flags[0])
	    && (srl1->flags[1] == srl2->flags[1]))
		return 0;
	else
		return 1;
}

/* Compare two Segment Prefix: return 0 if equal, 1 otherwise */
static inline int sr_prefix_cmp(struct sr_prefix *srp1, struct sr_prefix *srp2)
{
	if ((srp1->sid == srp2->sid) && (srp1->flags == srp2->flags))
		return 0;
	else
		return 1;
}


/* Create new SR Circuit context */
struct sr_extended *sr_circuit_new(void)
{
	struct sr_extended *sre;

	zlog_debug("SR(%): Create new Segment Routing Circuit context",
		   __func__);

	sre = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_extended));

	return sre;
}
/* Copy SUB TLVs parameters into a buffer - No space verification are performed
 */
/* Caller must verify before that there is enough free space in the buffer */
uint8_t add_sr_subtlvs(uint8_t *buf, struct sr_circuit *srp)
{
	uint8_t size;
	uint8_t length = 0;
	uint8_t *tlvs = buf;

	zlog_debug("SR (%): Add SR Sub TLVs to buffer", __func__);

	if (srp == NULL) {
		zlog_debug(
			"SR (%s): Abort! No SR Circuit available has been specified",
			__func__);
		return 0;
	}

	/* Create buffer if not provided */
	if (buf == NULL) {
		zlog_debug("SR (%): Abort! No Buffer has been specified",
			   __func__);
		return 0;
	}

	/* Adjacency SID primary */
	if (SUBTLV_TYPE(mtc->admin_grp) != 0) {
		size = SUBTLV_SIZE(&(mtc->admin_grp.header));
		memcpy(tlvs, &(srp->adj), size);
		tlvs += size;
		length += size;
	}

	return length;
}

/* Update Segment Link of given Segment Routing Node */
static void update_ext_link_sid(struct sr_node *srn, struct sr_link *srl,
				uint8_t lsa_flags)
{
	struct listnode *node;
	struct sr_link *lk;
	bool found = false;

	/* Sanity check */
	if ((srn == NULL) || (srl == NULL))
		return;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Process Extended Link Adj/Lan-SID");

	/* Process only Local Adj/Lan_Adj SID coming from LSA SELF */
	if (!CHECK_FLAG(srl->flags[0], EXT_SUBTLV_LINK_ADJ_SID_LFLG)
	    || !CHECK_FLAG(srl->flags[1], EXT_SUBTLV_LINK_ADJ_SID_LFLG)
	    || !CHECK_FLAG(lsa_flags, ISIS_LSA_SELF))
		return;

	/* Search for existing Segment Link */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, lk))
		if (lk->instance == srl->instance) {
			found = true;
			break;
		}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  %s SR Link 8.0.0.%u for SR node %s",
			   found ? "Update" : "Add",
			   GET_OPAQUE_ID(srl->instance),
			   inet_ntoa(srn->adv_router));

	/* if not found, add new Segment Link and install NHLFE */
	if (!found) {
		/* Complete SR-Link and add it to SR-Node list */
		srl->srn = srn;
		IPV4_ADDR_COPY(&srl->neighbor, &srn->adv_router);
		listnode_add(srn->ext_link, srl);
		/* Try to set MPLS table */
		if (compute_link_nhlfe(srl)) {
			add_sid_nhlfe(srl->nhlfe[0]);
			add_sid_nhlfe(srl->nhlfe[1]);
		}
	} else {
		if (sr_link_cmp(lk, srl)) {
			if (compute_link_nhlfe(srl)) {
				update_sid_nhlfe(lk->nhlfe[0], srl->nhlfe[0]);
				update_sid_nhlfe(lk->nhlfe[1], srl->nhlfe[1]);
				/* Replace Segment List */
				listnode_delete(srn->ext_link, lk);
				XFREE(MTYPE_ISIS_SR, lk);
				srl->srn = srn;
				IPV4_ADDR_COPY(&srl->neighbor,
					       &srn->adv_router);
				listnode_add(srn->ext_link, srl);
			} else {
				/* New NHLFE was not found.
				 * Just free the SR Link
				 */
				XFREE(MTYPE_ISIS_SR, srl);
			}
		} else {
			/*
			 * This is just an LSA refresh.
			 * Stop processing and free SR Link
			 */
			XFREE(MTYPE_ISIS_SR, srl);
		}
	}
}

/* Update Segment Prefix of given Segment Routing Node */
static void update_ext_prefix_sid(struct sr_node *srn, struct sr_prefix *srp)
{

	struct listnode *node;
	struct sr_prefix *pref;
	bool found = false;

	/* Sanity check */
	if (srn == NULL || srp == NULL)
		return;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Process Extended Prefix SID %u", srp->sid);

	/* Process only Global Prefix SID */
	if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_LFLG))
		return;

	/* Search for existing Segment Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, pref))
		if (pref->instance == srp->instance) {
			found = true;
			break;
		}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  %s SR LSA ID 7.0.0.%u for SR node %s",
			   found ? "Update" : "Add",
			   GET_OPAQUE_ID(srp->instance),
			   inet_ntoa(srn->adv_router));

	/* if not found, add new Segment Prefix and install NHLFE */
	if (!found) {
		/* Complete SR-Prefix and add it to SR-Node list */
		srp->srn = srn;
		IPV4_ADDR_COPY(&srp->adv_router, &srn->adv_router);
		listnode_add(srn->ext_prefix, srp);
		/* Try to set MPLS table */
		if (compute_prefix_nhlfe(srp) == 1)
			add_sid_nhlfe(srp->nhlfe);
	} else {
		if (sr_prefix_cmp(pref, srp)) {
			if (compute_prefix_nhlfe(srp) == 1) {
				update_sid_nhlfe(pref->nhlfe, srp->nhlfe);
				/* Replace Segment Prefix */
				listnode_delete(srn->ext_prefix, pref);
				XFREE(MTYPE_ISIS_SR, pref);
				srp->srn = srn;
				IPV4_ADDR_COPY(&srp->adv_router,
					       &srn->adv_router);
				listnode_add(srn->ext_prefix, srp);
			} else {
				/* New NHLFE was not found.
				 * Just free the SR Prefix
				 */
				XFREE(MTYPE_ISIS_SR, srp);
			}
		} else {
			/* This is just an LSA refresh.
			 * Stop processing and free SR Prefix
			 */
			XFREE(MTYPE_ISIS_SR, srp);
		}
	}
}

/*
 * When change the FRR Self SRGB, update the NHLFE Input Label
 * for all Extended Prefix with SID index through hash_iterate()
 */
static void update_in_nhlfe(struct hash_backet *backet, void *args)
{
	struct listnode *node;
	struct sr_node *srn = (struct sr_node *)backet->data;
	struct sr_prefix *srp;
	struct sr_nhlfe new;

	/* Process Every Extended Prefix for this SR-Node */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {
		/* Process Self SRN only if NO-PHP is requested */
		if ((srn == area->srdb->self)
		    && !CHECK_FLAG(srp->flags, SUBTLV_PREFIX_SID_NPFLG))
			continue;

		/* Process only SID Index */
		if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_VFLG))
			continue;

		/* OK. Compute new NHLFE */
		memcpy(&new, &srp->nhlfe, sizeof(struct sr_nhlfe));
		new.label_in = index2label(srp->sid, area->srdb->srgb);
		/* Update MPLS LFIB */
		update_sid_nhlfe(srp->nhlfe, new);
		/* Finally update Input Label */
		srp->nhlfe.label_in = new.label_in;
	}
}

/*
 * When SRGB has changed, update NHLFE Output Label for all Extended Prefix
 * with SID index which use the given SR-Node as nexthop though hash_iterate()
 */
static void update_out_nhlfe(struct hash_backet *backet, void *args)
{
	struct listnode *node;
	struct sr_node *srn = (struct sr_node *)backet->data;
	struct sr_node *srnext = (struct sr_node *)args;
	struct sr_prefix *srp;
	struct sr_nhlfe new;

	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {
		/* Process only SID Index for next hop without PHP */
		if ((srp->nexthop == NULL)
		    && (!CHECK_FLAG(srp->flags, SUBTLV_PREFIX_SID_NPFLG)))
			continue;
		memcpy(&new, &srp->nhlfe, sizeof(struct sr_nhlfe));
		new.label_out = index2label(srp->sid, srnext->srgb);
		update_sid_nhlfe(srp->nhlfe, new);
		srp->nhlfe.label_out = new.label_out;
	}
}

/*
 * Following functions are call by hook isis_lsp_event_hook() when an LSP
 * is received. 3 Event are managed
 *  - ADD: a new LSP is received and insert in the lspdb
 *  - DEL: a LSP is removed from the lspdb
 *  - UPD: a LSP is updated
 *  All Segment Routing (Router Information, Adj & Lan-Adj SID and Prefix SID
 *  are handle at one time as all information is embed in the same LSP
 */

/* Update Segment Routing from LSP */
static void srdb_lsp_update(struct isis_lsp *lsp)
{
	struct sr_node *srn;
	struct tlv_header *tlvh;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct ri_sr_tlv_sid_label_range *ri_srgb;
	struct ri_sr_tlv_sr_algorithm *algo;
	struct sr_srgb srgb;
	uint16_t length = 0, sum = 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug(
			"SR (%s): Process Router "
			"Information LSA 4.0.0.%u from %s",
			__func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			inet_ntoa(lsah->adv_router));

	/* Sanity check */
	if (IS_LSA_SELF(lsa))
		return;

	if (area->srdb->neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = hash_get(area->srdb->neighbors, (void *)&(lsah->adv_router),
		       (void *)sr_node_new);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't create SR node in hash table",
			 __func__);
		return;
	}

	if ((srn->instance != 0) && (srn->instance != ntohl(lsah->id.s_addr))) {
		flog_err(EC_ISIS_SR_INVALID_LSA_ID,
			 "SR (%s): Abort! Wrong "
			 "LSA ID 4.0.0.%u for SR node %s/%u",
			 __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			 inet_ntoa(lsah->adv_router), srn->instance);
		return;
	}

	/* Collect Router Information Sub TLVs */
	/* Initialize TLV browsing */
	length = ntohs(lsah->length) - ISIS_LSA_HEADER_SIZE;
	srgb.range_size = 0;
	srgb.lower_bound = 0;

	for (tlvh = TLV_HDR_TOP(lsah); (sum < length) && (tlvh != NULL);
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case RI_SR_TLV_SR_ALGORITHM:
			algo = (struct ri_sr_tlv_sr_algorithm *)tlvh;
			int i;

			for (i = 0; i < ntohs(algo->header.length); i++)
				srn->algo[i] = algo->value[0];
			for (; i < ALGORITHM_COUNT; i++)
				srn->algo[i] = SR_ALGORITHM_UNSET;
			sum += TLV_SIZE(tlvh);
			break;
		case RI_SR_TLV_SID_LABEL_RANGE:
			ri_srgb = (struct ri_sr_tlv_sid_label_range *)tlvh;
			srgb.range_size = GET_RANGE_SIZE(ntohl(ri_srgb->size));
			srgb.lower_bound =
				GET_LABEL(ntohl(ri_srgb->lower.value));
			sum += TLV_SIZE(tlvh);
			break;
		case RI_SR_TLV_NODE_MSD:
			srn->msd = ((struct ri_sr_tlv_node_msd *)(tlvh))->value;
			sum += TLV_SIZE(tlvh);
			break;
		default:
			sum += TLV_SIZE(tlvh);
			break;
		}
	}

	/* Check that we collect mandatory parameters */
	if (srn->algo[0] == SR_ALGORITHM_UNSET || srgb.range_size == 0
	    || srgb.lower_bound == 0) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Missing mandatory parameters. Abort!",
			 __func__);
		hash_release(area->srdb->neighbors, &(srn->adv_router));
		XFREE(MTYPE_ISIS_SR, srn);
		return;
	}

	/* Check if it is a new SR Node or not */
	if (srn->instance == 0) {
		/* update LSA ID */
		srn->instance = ntohl(lsah->id.s_addr);
		/* Copy SRGB */
		srn->srgb.range_size = srgb.range_size;
		srn->srgb.lower_bound = srgb.lower_bound;
	}

	/* Check if SRGB has changed */
	if ((srn->srgb.range_size != srgb.range_size)
	    || (srn->srgb.lower_bound != srgb.lower_bound)) {
		srn->srgb.range_size = srgb.range_size;
		srn->srgb.lower_bound = srgb.lower_bound;
		/* Update NHLFE if it is a neighbor SR node */
		if (srn->neighbor == area->srdb->self)
			hash_iterate(area->srdb->neighbors,
				     (void (*)(struct hash_backet *,
					       void *))update_out_nhlfe,
				     (void *)srn);
	}
}

/*
 * Delete SR Node entry in hash table information corresponding to an expired
 * Router Information LSA
 */
void isis_sr_ri_lsa_delete(struct isis_lsa *lsa)
{
	struct sr_node *srn;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Remove SR node %s from lsa_id 4.0.0.%u",
			   __func__, inet_ntoa(lsah->adv_router),
			   GET_OPAQUE_ID(ntohl(lsah->id.s_addr)));

	/* Sanity check */
	if (area->srdb->neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR Data Base", __func__);
		return;
	}

	/* Release Router ID entry in SRDB hash table */
	srn = hash_release(area->srdb->neighbors, &(lsah->adv_router));

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! no entry in SRDB for SR Node %s",
			 __func__, inet_ntoa(lsah->adv_router));
		return;
	}

	if ((srn->instance != 0) && (srn->instance != ntohl(lsah->id.s_addr))) {
		flog_err(EC_ISIS_SR_INVALID_LSA_ID,
			 "SR (%s): Abort! Wrong LSA ID 4.0.0.%u for SR node %s",
			 __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			 inet_ntoa(lsah->adv_router));
		return;
	}

	/* Remove SR node */
	sr_node_del(srn);
}

/* Update Segment Routing from Extended Link LSA */
void isis_sr_ext_link_lsa_update(struct isis_lsa *lsa)
{
	struct sr_node *srn;
	struct tlv_header *tlvh;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct sr_link *srl;

	uint16_t length, sum;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug(
			"SR (%s): Process Extended Link LSA 8.0.0.%u from %s",
			__func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			inet_ntoa(lsah->adv_router));

	/* Sanity check */
	if (area->srdb->neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(area->srdb->neighbors,
					 (void *)&(lsah->adv_router),
					 (void *)sr_node_new);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't create SR node in hash table",
			 __func__);
		return;
	}

	/* Initialize TLV browsing */
	length = ntohs(lsah->length) - ISIS_LSA_HEADER_SIZE;
	sum = 0;
	for (tlvh = TLV_HDR_TOP(lsah); (sum < length) && (tlvh != NULL);
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		if (ntohs(tlvh->type) == EXT_TLV_LINK) {
			/* Got Extended Link information */
			srl = get_ext_link_sid(tlvh);
			/* Update SID if not null */
			if (srl != NULL) {
				srl->instance = ntohl(lsah->id.s_addr);
				update_ext_link_sid(srn, srl, lsa->flags);
			}
		}
		sum += TLV_SIZE(tlvh);
	}
}

/* Delete Segment Routing from Extended Link LSA */
void isis_sr_ext_link_lsa_delete(struct isis_lsa *lsa)
{
	struct listnode *node;
	struct sr_link *srl;
	struct sr_node *srn;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	uint32_t instance = ntohl(lsah->id.s_addr);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Remove Extended Link LSA 8.0.0.%u from %s",
			   __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			   inet_ntoa(lsah->adv_router));

	/* Sanity check */
	if (area->srdb->neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(area->srdb->neighbors,
					    (void *)&(lsah->adv_router));

	/*
	 * SR-Node may be NULL if it has been remove previously when
	 * processing Router Information LSA deletion
	 */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Stop! no entry in SRDB for SR Node %s",
			 __func__, inet_ntoa(lsah->adv_router));
		return;
	}

	/* Search for corresponding Segment Link */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, srl))
		if (srl->instance == instance)
			break;

	/* Remove Segment Link if found */
	if ((srl != NULL) && (srl->instance == instance)) {
		del_sid_nhlfe(srl->nhlfe[0]);
		del_sid_nhlfe(srl->nhlfe[1]);
		listnode_delete(srn->ext_link, srl);
		XFREE(MTYPE_ISIS_SR, srl);
	} else {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Didn't found corresponding SR Link 8.0.0.%u "
			 "for SR Node %s",
			 __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			 inet_ntoa(lsah->adv_router));
	}
}

/* Update Segment Routing from Extended Prefix LSA */
void isis_sr_ext_prefix_lsa_update(struct isis_lsa *lsa)
{
	struct sr_node *srn;
	struct tlv_header *tlvh;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct sr_prefix *srp;

	uint16_t length, sum;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug(
			"SR (%s): Process Extended Prefix LSA "
			"7.0.0.%u from %s",
			__func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			inet_ntoa(lsah->adv_router));

	/* Sanity check */
	if (area->srdb->neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(area->srdb->neighbors,
					 (void *)&(lsah->adv_router),
					 (void *)sr_node_new);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't create SR node in hash table",
			 __func__);
		return;
	}

	/* Initialize TLV browsing */
	length = ntohs(lsah->length) - ISIS_LSA_HEADER_SIZE;
	sum = 0;
	for (tlvh = TLV_HDR_TOP(lsah); sum < length;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		if (ntohs(tlvh->type) == EXT_TLV_LINK) {
			/* Got Extended Link information */
			srp = get_ext_prefix_sid(tlvh);
			/* Update SID if not null */
			if (srp != NULL) {
				srp->instance = ntohl(lsah->id.s_addr);
				update_ext_prefix_sid(srn, srp);
			}
		}
		sum += TLV_SIZE(tlvh);
	}
}

/* Delete Segment Routing from Extended Prefix LSA */
void isis_sr_ext_prefix_lsa_delete(struct isis_lsa *lsa)
{
	struct listnode *node;
	struct sr_prefix *srp;
	struct sr_node *srn;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	uint32_t instance = ntohl(lsah->id.s_addr);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug(
			"SR (%s): Remove Extended Prefix LSA 7.0.0.%u from %s",
			__func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			inet_ntoa(lsah->adv_router));

	/* Sanity check */
	if (area->srdb->neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(area->srdb->neighbors,
					    (void *)&(lsah->adv_router));

	/*
	 * SR-Node may be NULL if it has been remove previously when
	 * processing Router Information LSA deletion
	 */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s):  Stop! no entry in SRDB for SR Node %s",
			 __func__, inet_ntoa(lsah->adv_router));
		return;
	}

	/* Search for corresponding Segment Link */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp))
		if (srp->instance == instance)
			break;

	/* Remove Segment Link if found */
	if ((srp != NULL) && (srp->instance == instance)) {
		del_sid_nhlfe(srp->nhlfe);
		listnode_delete(srn->ext_link, srp);
		XFREE(MTYPE_ISIS_SR, srp);
	} else {
		flog_err(
			EC_ISIS_SR_INVALID_DB,
			"SR (%s): Didn't found corresponding SR Prefix 7.0.0.%u for SR Node %s",
			__func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			inet_ntoa(lsah->adv_router));
	}
}

static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event)
{
	int rc;

	switch(event) {
	case LSP_ADD:
		rc = srdb_lsp_add(lsp);
		break;
	case LSP_DEL:
		rc = srdb_lsp_del(lsp);
		break;
	case LSP_UPD:
		rc = srdb_lsp_update(lsp);
		break;
	default:
		rc = 1;
		break;
	}

	return rc;
}

/* Get Label for Extended Link SID */
/* TODO: To be replace by Zebra Label Manager */
uint32_t get_ext_link_label_value(void)
{
	static uint32_t label = ADJ_SID_MIN - 1;

	if (label < ADJ_SID_MAX)
		label += 1;

	return label;
}

/*
 * Update Prefix SID. Call by isis_ext_pref_ism_change to
 * complete initial CLI command at startutp.
 *
 * @param ifp - Loopback interface
 * @param pref - Prefix address of this interface
 *
 * @return - void
 */
void isis_sr_update_prefix(struct interface *ifp, struct prefix *p)
{
	struct listnode *node;
	struct sr_prefix *srp;

	/* Sanity Check */
	if ((ifp == NULL) || (p == NULL))
		return;

	/*
	 * Search if there is a Segment Prefix that correspond to this
	 * interface or prefix, and update it if found
	 */
	for (ALL_LIST_ELEMENTS_RO(area->srdb->self->ext_prefix, node, srp)) {
		if ((srp->nhlfe.ifindex == ifp->ifindex)
		    || ((IPV4_ADDR_SAME(&srp->nhlfe.prefv4.prefix,
					&p->u.prefix4))
			&& (srp->nhlfe.prefv4.prefixlen == p->prefixlen))) {

			/* Update Interface & Prefix info */
			srp->nhlfe.ifindex = ifp->ifindex;
			IPV4_ADDR_COPY(&srp->nhlfe.prefv4.prefix,
				       &p->u.prefix4);
			srp->nhlfe.prefv4.prefixlen = p->prefixlen;
			srp->nhlfe.prefv4.family = p->family;
			IPV4_ADDR_COPY(&srp->nhlfe.nexthop, &p->u.prefix4);

			/* OK. Let's Schedule Extended Prefix LSA */
			srp->instance = isis_ext_schedule_prefix_index(
				ifp, srp->sid, &srp->nhlfe.prefv4, srp->flags);

			/* Install NHLFE if NO-PHP is requested */
			if (CHECK_FLAG(srp->flags,
				       SUBTLV_PREFIX_SID_NPFLG)) {
				srp->nhlfe.label_in = index2label(
					srp->sid, area->srdb->self->srgb);
				srp->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
				add_sid_nhlfe(srp->nhlfe);
			}
		}
	}
}

/*
 * Following functions are used to update MPLS LFIB after a SPF run
 */

static void isis_sr_nhlfe_update(struct hash_backet *backet, void *args)
{

	struct sr_node *srn = (struct sr_node *)backet->data;
	struct listnode *node;
	struct sr_prefix *srp;
	struct sr_nhlfe old;
	int rc;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Update Prefix for SR Node %s",
			   inet_ntoa(srn->adv_router));

	/* Skip Self SR Node */
	if (srn == area->srdb->self)
		return;

	/* Update Extended Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {

		/* Backup current NHLFE */
		memcpy(&old, &srp->nhlfe, sizeof(struct sr_nhlfe));

		/* Compute the new NHLFE */
		rc = compute_prefix_nhlfe(srp);

		/* Check computation result */
		switch (rc) {
		/* next hop is not know, remove old NHLFE to avoid loop */
		case -1:
			del_sid_nhlfe(srp->nhlfe);
			break;
		/* next hop has not changed, skip it */
		case 0:
			break;
		/* there is a new next hop, update NHLFE */
		case 1:
			update_sid_nhlfe(old, srp->nhlfe);
			break;
		default:
			break;
		}
	}
}

static int isis_sr_update_schedule(struct thread *t)
{

	struct isis_area *area;
	struct timeval start_time, stop_time;

	isis = THREAD_ARG(t);
	isis->t_sr_update = NULL;

	if (!area->srdb->update)
		return 0;

	monotime(&start_time);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Start SPF update", __func__);

	hash_iterate(area->srdb->neighbors, (void (*)(struct hash_backet *,
						 void *))isis_sr_nhlfe_update,
		     NULL);

	monotime(&stop_time);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): SPF Processing Time(usecs): %lld\n",
			   __func__,
			   (stop_time.tv_sec - start_time.tv_sec) * 1000000LL
				   + (stop_time.tv_usec - start_time.tv_usec));

	area->srdb->update = false;
	return 1;
}

#define ISIS_SR_UPDATE_INTERVAL	1

void isis_sr_update_timer_add(struct isis_area *area)
{

	if (isis == NULL)
		return;

	/* Check if an update is not alreday engage */
	if (area->srdb->update)
		return;

	area->srdb->update = true;

	thread_add_timer(master, isis_sr_update_schedule, isis,
			 ISIS_SR_UPDATE_INTERVAL, &isis->t_sr_update);
}

/*
 * --------------------------------------
 * Followings are vty command functions.
 * --------------------------------------
 */

#ifdef MOVE_TO_NORTHBOUND
/*
 * Segment Routing Router configuration
 *
 * Must be centralize as it concerns both Extended Link/Prefix LSA
 * and Router Information LSA. Choose to call it from Extended Prefix
 * write_config() call back.
 *
 * @param vty VTY output
 *
 * @return none
 */
void isis_sr_config_write_router(struct vty *vty)
{
	struct listnode *node;
	struct sr_prefix *srp;

	if (area->srdb->enabled) {
		vty_out(vty, " segment-routing on\n");

		if ((area->srdb->srgb.lower_bound != MPLS_DEFAULT_MIN_SRGB_LABEL)
		    || (area->srdb->srgb.range_size != MPLS_DEFAULT_MAX_SRGB_SIZE)) {
			vty_out(vty, " segment-routing global-block %u %u\n",
				area->srdb->srgb.lower_bound,
				area->srdb->srgb.lower_bound + area->srdb->srgb.range_size
					- 1);
		}
		if (area->srdb->msd != 0)
			vty_out(vty, " segment-routing node-msd %u\n",
				area->srdb->msd);

		if (area->srdb->self != NULL) {
			for (ALL_LIST_ELEMENTS_RO(area->srdb->self->ext_prefix, node,
						  srp)) {
				vty_out(vty,
					" segment-routing prefix %s/%u "
					"index %u%s\n",
					inet_ntoa(srp->nhlfe.prefv4.prefix),
					srp->nhlfe.prefv4.prefixlen, srp->sid,
					CHECK_FLAG(srp->flags,
						   SUBTLV_PREFIX_SID_NPFLG)
						? " no-php-flag"
						: "");
			}
		}
	}
}

DEFUN(isis_sr_enable,
       isis_sr_enable_cmd,
       "segment-routing on",
       SR_STR
       "Enable Segment Routing\n")
{

	VTY_DECLVAR_INSTANCE_CONTEXT(isis, isis);

	if (area->srdb->enabled)
		return CMD_SUCCESS;

	if (isis->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"Segment Routing is only supported in default "
			"VRF\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (IS_DEBUG_ISIS_EVENT)
		zlog_debug("SR: Segment Routing: OFF -> ON");

	/* Start Segment Routing */
	area->srdb->enabled = true;
	isis_sr_start(isis);

	/* Set Router Information SR parameters */
	if (IS_DEBUG_ISIS_EVENT)
		zlog_debug("SR: Activate SR for Router Information LSA");

	isis_router_info_update_sr(true, area->srdb->srgb, area->srdb->msd);

	/* Update Ext LSA */
	if (IS_DEBUG_ISIS_EVENT)
		zlog_debug("SR: Activate SR for Extended Link/Prefix LSA");

	isis_ext_update_sr(true);

	return CMD_SUCCESS;
}

DEFUN (no_isis_sr_enable,
       no_isis_sr_enable_cmd,
       "no segment-routing [on]",
       NO_STR
       SR_STR
       "Disable Segment Routing\n")
{

	if (!area->srdb->enabled)
		return CMD_SUCCESS;

	if (IS_DEBUG_ISIS_EVENT)
		zlog_debug("SR: Segment Routing: ON -> OFF");

	/* Start by Disabling Extended Link & Prefix LSA */
	isis_ext_update_sr(false);

	/* then, disable Router Information SR parameters */
	isis_router_info_update_sr(false, area->srdb->srgb, area->srdb->msd);

	/* Finally, stop Segment Routing */
	isis_sr_stop();
	area->srdb->enabled = false;

	return CMD_SUCCESS;
}

static int isis_sr_enabled(struct vty *vty)
{
	if (area->srdb->enabled)
		return 1;

	if (vty)
		vty_out(vty, "%% ISIS SR is not turned on\n");

	return 0;
}

DEFUN (sr_sid_label_range,
       sr_sid_label_range_cmd,
       "segment-routing global-block (0-1048575) (0-1048575)",
       SR_STR
       "Segment Routing Global Block label range\n"
       "Lower-bound range in decimal (0-1048575)\n"
       "Upper-bound range in decimal (0-1048575)\n")
{
	uint32_t upper;
	uint32_t lower;
	uint32_t size;
	int idx_low = 2;
	int idx_up = 3;

	if (!isis_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* Get lower and upper bound */
	lower = strtoul(argv[idx_low]->arg, NULL, 10);
	upper = strtoul(argv[idx_up]->arg, NULL, 10);
	size = upper - lower + 1;

	if (size > MPLS_DEFAULT_MAX_SRGB_SIZE || size <= 0) {
		vty_out(vty,
			"Range size cannot be less than 0 or more than %u\n",
			MPLS_DEFAULT_MAX_SRGB_SIZE);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (upper > MPLS_DEFAULT_MAX_SRGB_LABEL) {
		vty_out(vty, "Upper-bound cannot exceed %u\n",
			MPLS_DEFAULT_MAX_SRGB_LABEL);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (upper < MPLS_DEFAULT_MIN_SRGB_LABEL) {
		vty_out(vty, "Upper-bound cannot be lower than %u\n",
			MPLS_DEFAULT_MIN_SRGB_LABEL);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check if values have changed */
	if ((area->srdb->srgb.range_size == size)
	    && (area->srdb->srgb.lower_bound == lower))
		return CMD_SUCCESS;

	/* Set SID/Label range SRGB */
	area->srdb->srgb.range_size = size;
	area->srdb->srgb.lower_bound = lower;
	if (area->srdb->self != NULL) {
		area->srdb->self->srgb.range_size = size;
		area->srdb->self->srgb.lower_bound = lower;
	}

	/* Set Router Information SR parameters */
	isis_router_info_update_sr(true, area->srdb->srgb, area->srdb->msd);

	/* Update NHLFE entries */
	hash_iterate(area->srdb->neighbors,
		     (void (*)(struct hash_backet *, void *))update_in_nhlfe,
		     NULL);

	return CMD_SUCCESS;
}

DEFUN (no_sr_sid_label_range,
	no_sr_sid_label_range_cmd,
	"no segment-routing global-block [(0-1048575) (0-1048575)]",
	NO_STR
	SR_STR
	"Segment Routing Global Block label range\n"
	"Lower-bound range in decimal (0-1048575)\n"
	"Upper-bound range in decimal (0-1048575)\n")
{

	if (!isis_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* Revert to default SRGB value */
	area->srdb->srgb.range_size = MPLS_DEFAULT_MIN_SRGB_SIZE;
	area->srdb->srgb.lower_bound = MPLS_DEFAULT_MIN_SRGB_LABEL;
	if (area->srdb->self != NULL) {
		area->srdb->self->srgb.range_size = area->srdb->srgb.range_size;
		area->srdb->self->srgb.lower_bound = area->srdb->srgb.lower_bound;
	}

	/* Set Router Information SR parameters */
	isis_router_info_update_sr(true, area->srdb->srgb, area->srdb->msd);

	/* Update NHLFE entries */
	hash_iterate(area->srdb->neighbors,
		     (void (*)(struct hash_backet *, void *))update_in_nhlfe,
		     NULL);

	return CMD_SUCCESS;
}

DEFUN (sr_node_msd,
       sr_node_msd_cmd,
       "segment-routing node-msd (1-16)",
       SR_STR
       "Maximum Stack Depth for this router\n"
       "Maximum number of label that could be stack (1-16)\n")
{
	uint32_t msd;
	int idx = 1;

	if (!isis_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* Get MSD */
	argv_find(argv, argc, "(1-16)", &idx);
	msd = strtoul(argv[idx]->arg, NULL, 10);
	if (msd < 1 || msd > MPLS_MAX_LABELS) {
		vty_out(vty, "MSD must be comprise between 1 and %u\n",
			MPLS_MAX_LABELS);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check if value has changed */
	if (area->srdb->msd == msd)
		return CMD_SUCCESS;

	/* Set this router MSD */
	area->srdb->msd = msd;
	if (area->srdb->self != NULL)
		area->srdb->self->msd = msd;

	/* Set Router Information SR parameters */
	isis_router_info_update_sr(true, area->srdb->srgb, area->srdb->msd);

	return CMD_SUCCESS;
}

DEFUN (no_sr_node_msd,
	no_sr_node_msd_cmd,
	"no segment-routing node-msd [(1-16)]",
	NO_STR
	SR_STR
	"Maximum Stack Depth for this router\n"
	"Maximum number of label that could be stack (1-16)\n")
{

	if (!isis_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* unset this router MSD */
	area->srdb->msd = 0;
	if (area->srdb->self != NULL)
		area->srdb->self->msd = 0;

	/* Set Router Information SR parameters */
	isis_router_info_update_sr(true, area->srdb->srgb, 0);

	return CMD_SUCCESS;
}

DEFUN (sr_prefix_sid,
       sr_prefix_sid_cmd,
       "segment-routing prefix A.B.C.D/M index (0-65535) [no-php-flag]",
       SR_STR
       "Prefix SID\n"
       "IPv4 Prefix as A.B.C.D/M\n"
       "SID index for this prefix in decimal (0-65535)\n"
       "Index value inside SRGB (lower_bound < index < upper_bound)\n"
       "Don't request Penultimate Hop Popping (PHP)\n")
{
	int idx = 0;
	struct prefix p;
	uint32_t index;
	struct listnode *node;
	struct sr_prefix *srp, *new;
	struct interface *ifp;

	if (!isis_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* Get network prefix */
	argv_find(argv, argc, "A.B.C.D/M", &idx);
	if (!str2prefix(argv[idx]->arg, &p)) {
		vty_out(vty, "Invalid prefix format %s\n", argv[idx]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get & verify index value */
	argv_find(argv, argc, "(0-65535)", &idx);
	index = strtoul(argv[idx]->arg, NULL, 10);
	if (index > area->srdb->srgb.range_size - 1) {
		vty_out(vty, "Index %u must be lower than range size %u\n",
			index, area->srdb->srgb.range_size);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* check that the index is not already used */
	for (ALL_LIST_ELEMENTS_RO(area->srdb->self->ext_prefix, node, srp)) {
		if (srp->sid == index) {
			vty_out(vty, "Index %u is already used\n", index);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Create new Extended Prefix to SRDB if not found */
	new = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));
	IPV4_ADDR_COPY(&new->nhlfe.prefv4.prefix, &p.u.prefix4);
	IPV4_ADDR_COPY(&new->nhlfe.nexthop, &p.u.prefix4);
	new->nhlfe.prefv4.prefixlen = p.prefixlen;
	new->nhlfe.prefv4.family = p.family;
	new->sid = index;
	/* Set NO PHP flag if present and compute NHLFE */
	if (argv_find(argv, argc, "no-php-flag", &idx)) {
		SET_FLAG(new->flags, SUBTLV_PREFIX_SID_NPFLG);
		new->nhlfe.label_in = index2label(new->sid, area->srdb->self->srgb);
		new->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
	}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Add new index %u to Prefix %s/%u",
			   __func__, index, inet_ntoa(new->nhlfe.prefv4.prefix),
			   new->nhlfe.prefv4.prefixlen);

	/* Get Interface and check if it is a Loopback */
	ifp = if_lookup_prefix(&p, VRF_DEFAULT);
	if (ifp == NULL) {
		/*
		 * Interface could be not yet available i.e. when this
		 * command is in the configuration file, ISIS is not yet
		 * ready. In this case, store the prefix SID for latter
		 * update of this Extended Prefix
		 */
		listnode_add(area->srdb->self->ext_prefix, new);
		zlog_info(
			"Interface for prefix %s/%u not found. Deferred LSA "
			"flooding",
			inet_ntoa(p.u.prefix4), p.prefixlen);
		return CMD_SUCCESS;
	}

	if (!if_is_loopback(ifp)) {
		vty_out(vty, "interface %s is not a Loopback\n", ifp->name);
		XFREE(MTYPE_ISIS_SR, new);
		return CMD_WARNING_CONFIG_FAILED;
	}
	new->nhlfe.ifindex = ifp->ifindex;

	/* Search if this prefix already exist */
	for (ALL_LIST_ELEMENTS_RO(area->srdb->self->ext_prefix, node, srp)) {
		if ((IPV4_ADDR_SAME(&srp->nhlfe.prefv4.prefix, &p.u.prefix4)
		     && srp->nhlfe.prefv4.prefixlen == p.prefixlen))
			break;
		else
			srp = NULL;
	}

	/* Update or Add this new SR Prefix */
	if (srp) {
		update_sid_nhlfe(srp->nhlfe, new->nhlfe);
		listnode_delete(area->srdb->self->ext_prefix, srp);
		listnode_add(area->srdb->self->ext_prefix, new);
	} else {
		listnode_add(area->srdb->self->ext_prefix, new);
		add_sid_nhlfe(new->nhlfe);
	}

	/* Finally, update Extended Prefix LSA */
	new->instance = isis_ext_schedule_prefix_index(
		ifp, new->sid, &new->nhlfe.prefv4, new->flags);
	if (new->instance == 0) {
		vty_out(vty, "Unable to set index %u for prefix %s/%u\n", index,
			inet_ntoa(p.u.prefix4), p.prefixlen);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (no_sr_prefix_sid,
       no_sr_prefix_sid_cmd,
       "no segment-routing prefix A.B.C.D/M [index (0-65535) no-php-flag]",
       NO_STR
       SR_STR
       "Prefix SID\n"
       "IPv4 Prefix as A.B.C.D/M\n"
       "SID index for this prefix in decimal (0-65535)\n"
       "Index value inside SRGB (lower_bound < index < upper_bound)\n"
       "Don't request Penultimate Hop Popping (PHP)\n")
{
	int idx = 0;
	struct prefix p;
	struct listnode *node;
	struct sr_prefix *srp;
	struct interface *ifp;
	bool found = false;
	int rc;

	if (!isis_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* Get network prefix */
	argv_find(argv, argc, "A.B.C.D/M", &idx);
	rc = str2prefix(argv[idx]->arg, &p);
	if (!rc) {
		vty_out(vty, "Invalid prefix format %s\n", argv[idx]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* check that the prefix is already set */
	for (ALL_LIST_ELEMENTS_RO(area->srdb->self->ext_prefix, node, srp))
		if (IPV4_ADDR_SAME(&srp->nhlfe.prefv4.prefix, &p.u.prefix4)
		    && (srp->nhlfe.prefv4.prefixlen == p.prefixlen)) {
			found = true;
			break;
		}

	if (!found) {
		vty_out(vty, "Prefix %s is not found. Abort!\n",
			argv[idx]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get Interface */
	ifp = if_lookup_by_index(srp->nhlfe.ifindex, VRF_DEFAULT);
	if (ifp == NULL) {
		vty_out(vty, "interface for prefix %s not found.\n",
			argv[idx]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Extended Prefix LSA */
	if (!isis_ext_schedule_prefix_index(ifp, 0, NULL, 0)) {
		vty_out(vty, "No corresponding loopback interface. Abort!\n");
		return CMD_WARNING;
	}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Remove Prefix %s/%u with index %u",
			   __func__, inet_ntoa(srp->nhlfe.prefv4.prefix),
			   srp->nhlfe.prefv4.prefixlen, srp->sid);

	/* Delete NHLFE is NO-PHP is set */
	if (CHECK_FLAG(srp->flags, SUBTLV_PREFIX_SID_NPFLG))
		del_sid_nhlfe(srp->nhlfe);

	/* OK, all is clean, remove SRP from SRDB */
	listnode_delete(area->srdb->self->ext_prefix, srp);
	XFREE(MTYPE_ISIS_SR, srp);

	return CMD_SUCCESS;
}
#endif

static void show_sr_node(struct vty *vty, struct json_object *json,
			 struct sr_node *srn)
{

	struct listnode *node;
	struct sr_link *srl;
	struct sr_prefix *srp;
	struct interface *itf;
	char pref[19];
	char sid[22];
	char label[8];
	json_object *json_node = NULL, *json_algo, *json_obj;
	json_object *json_prefix = NULL, *json_link = NULL;

	/* Sanity Check */
	if (srn == NULL)
		return;

	if (json) {
		json_node = json_object_new_object();
		json_object_string_add(json_node, "routerID",
				       inet_ntoa(srn->adv_router));
		json_object_int_add(json_node, "srgbSize",
				    srn->srgb.range_size);
		json_object_int_add(json_node, "srgbLabel",
				    srn->srgb.lower_bound);
		json_algo = json_object_new_array();
		json_object_object_add(json_node, "algorithms", json_algo);
		for (int i = 0; i < ALGORITHM_COUNT; i++) {
			if (srn->algo[i] == SR_ALGORITHM_UNSET)
				continue;
			json_obj = json_object_new_object();
			char tmp[2];

			snprintf(tmp, 2, "%u", i);
			json_object_string_add(json_obj, tmp,
					       srn->algo[i] == SR_ALGORITHM_SPF
						       ? "SPF"
						       : "S-SPF");
			json_object_array_add(json_algo, json_obj);
		}
		if (srn->msd != 0)
			json_object_int_add(json_node, "nodeMsd", srn->msd);
	} else {
		vty_out(vty, "SR-Node: %s", inet_ntoa(srn->adv_router));
		vty_out(vty, "\tSRGB (Size/Label): %u/%u", srn->srgb.range_size,
			srn->srgb.lower_bound);
		vty_out(vty, "\tAlgorithm(s): %s",
			srn->algo[0] == SR_ALGORITHM_SPF ? "SPF" : "S-SPF");
		for (int i = 1; i < SR_ALGORITHM_COUNT; i++) {
			if (srn->algo[i] == SR_ALGORITHM_UNSET)
				continue;
			vty_out(vty, "/%s",
				srn->algo[i] == SR_ALGORITHM_SPF ? "SPF"
								 : "S-SPF");
		}
		if (srn->msd != 0)
			vty_out(vty, "\tMSD: %u", srn->msd);
	}

	if (!json) {
		vty_out(vty,
			"\n\n    Prefix or Link  Label In  Label Out       "
			"Node or Adj. SID  Interface          Nexthop\n");
		vty_out(vty,
			"------------------  --------  ---------  "
			"---------------------  ---------  ---------------\n");
	}
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {
		snprintf(pref, 19, "%s/%u", inet_ntoa(srp->nhlfe.prefv4.prefix),
			 srp->nhlfe.prefv4.prefixlen);
		snprintf(sid, 22, "SR Pfx (idx %u)", srp->sid);
		if (srp->nhlfe.label_out == MPLS_LABEL_IMPLICIT_NULL)
			sprintf(label, "pop");
		else
			sprintf(label, "%u", srp->nhlfe.label_out);
		itf = if_lookup_by_index(srp->nhlfe.ifindex, VRF_DEFAULT);
		if (json) {
			if (!json_prefix) {
				json_prefix = json_object_new_array();
				json_object_object_add(json_node,
						       "extendedPrefix",
						       json_prefix);
			}
			json_obj = json_object_new_object();
			json_object_string_add(json_obj, "prefix", pref);
			json_object_int_add(json_obj, "sid", srp->sid);
			json_object_int_add(json_obj, "inputLabel",
					    srp->nhlfe.label_in);
			json_object_string_add(json_obj, "outputLabel", label);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_add(json_obj, "nexthop",
					       inet_ntoa(srp->nhlfe.nexthop));
			json_object_array_add(json_prefix, json_obj);
		} else {
			vty_out(vty, "%18s  %8u  %9s  %21s  %9s  %15s\n", pref,
				srp->nhlfe.label_in, label, sid,
				itf ? itf->name : "-",
				inet_ntoa(srp->nhlfe.nexthop));
		}
	}

	for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, srl)) {
		snprintf(pref, 19, "%s/%u",
			 inet_ntoa(srl->nhlfe[0].prefv4.prefix),
			 srl->nhlfe[0].prefv4.prefixlen);
		snprintf(sid, 22, "SR Adj. (lbl %u)", srl->sid[0]);
		if (srl->nhlfe[0].label_out == MPLS_LABEL_IMPLICIT_NULL)
			sprintf(label, "pop");
		else
			sprintf(label, "%u", srl->nhlfe[0].label_out);
		itf = if_lookup_by_index(srl->nhlfe[0].ifindex, VRF_DEFAULT);
		if (json) {
			if (!json_link) {
				json_link = json_object_new_array();
				json_object_object_add(
					json_node, "extendedLink", json_link);
			}
			/* Primary Link */
			json_obj = json_object_new_object();
			json_object_string_add(json_obj, "prefix", pref);
			json_object_int_add(json_obj, "sid", srl->sid[0]);
			json_object_int_add(json_obj, "inputLabel",
					    srl->nhlfe[0].label_in);
			json_object_string_add(json_obj, "outputLabel", label);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_add(
				json_obj, "nexthop",
				inet_ntoa(srl->nhlfe[0].nexthop));
			json_object_array_add(json_link, json_obj);
			/* Backup Link */
			json_obj = json_object_new_object();
			snprintf(sid, 22, "SR Adj. (lbl %u)", srl->sid[1]);
			if (srl->nhlfe[1].label_out == MPLS_LABEL_IMPLICIT_NULL)
				sprintf(label, "pop");
			else
				sprintf(label, "%u", srl->nhlfe[0].label_out);
			json_object_string_add(json_obj, "prefix", pref);
			json_object_int_add(json_obj, "sid", srl->sid[1]);
			json_object_int_add(json_obj, "inputLabel",
					    srl->nhlfe[1].label_in);
			json_object_string_add(json_obj, "outputLabel", label);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_add(
				json_obj, "nexthop",
				inet_ntoa(srl->nhlfe[1].nexthop));
			json_object_array_add(json_link, json_obj);
		} else {
			vty_out(vty, "%18s  %8u  %9s  %21s  %9s  %15s\n", pref,
				srl->nhlfe[0].label_in, label, sid,
				itf ? itf->name : "-",
				inet_ntoa(srl->nhlfe[0].nexthop));
			snprintf(sid, 22, "SR Adj. (lbl %u)", srl->sid[1]);
			if (srl->nhlfe[1].label_out == MPLS_LABEL_IMPLICIT_NULL)
				sprintf(label, "pop");
			else
				sprintf(label, "%u", srl->nhlfe[1].label_out);
			vty_out(vty, "%18s  %8u  %9s  %21s  %9s  %15s\n", pref,
				srl->nhlfe[1].label_in, label, sid,
				itf ? itf->name : "-",
				inet_ntoa(srl->nhlfe[1].nexthop));
		}
	}
	if (json)
		json_object_array_add(json, json_node);
	else
		vty_out(vty, "\n");
}

static void show_vty_srdb(struct hash_backet *backet, void *args)
{
	struct vty *vty = (struct vty *)args;
	struct sr_node *srn = (struct sr_node *)backet->data;

	show_sr_node(vty, NULL, srn);
}

static void show_json_srdb(struct hash_backet *backet, void *args)
{
	struct json_object *json = (struct json_object *)args;
	struct sr_node *srn = (struct sr_node *)backet->data;

	show_sr_node(NULL, json, srn);
}

DEFUN (show_ip_opsf_srdb,
       show_ip_isis_srdb_cmd,
       "show ip isis database segment-routing [adv-router A.B.C.D|self-originate] [json]",
       SHOW_STR
       IP_STR
       ISIS_STR
       "Database summary\n"
       "Show Segment Routing Data Base\n"
       "Advertising SR node\n"
       "Advertising SR node ID (as an IP address)\n"
       "Self-originated SR node\n"
       JSON_STR)
{
	int idx = 0;
	struct in_addr rid;
	struct sr_node *srn;
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *json_node_array = NULL;

	if (!area->srdb->enabled) {
		vty_out(vty, "Segment Routing is disabled on this router\n");
		return CMD_WARNING;
	}

	if (uj) {
		json = json_object_new_object();
		json_node_array = json_object_new_array();
		json_object_string_add(json, "srdbID",
				       inet_ntoa(area->srdb->self->adv_router));
		json_object_object_add(json, "srNodes", json_node_array);
	} else {
		vty_out(vty,
			"\n\t\tISIS Segment Routing database for ID %s\n\n",
			inet_ntoa(area->srdb->self->adv_router));
	}

	if (argv_find(argv, argc, "self-originate", &idx)) {
		srn = area->srdb->self;
		show_sr_node(vty, json_node_array, srn);
		if (uj) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
			json_object_free(json);
		}
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &rid)) {
			vty_out(vty, "Specified Router ID %s is invalid\n",
				argv[idx]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		/* Get the SR Node from the SRDB */
		srn = (struct sr_node *)hash_lookup(area->srdb->neighbors,
						    (void *)&rid);
		show_sr_node(vty, json_node_array, srn);
		if (uj) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
			json_object_free(json);
		}
		return CMD_SUCCESS;
	}

	/* No parameters have been provided, Iterate through all the SRDB */
	if (uj) {
		hash_iterate(area->srdb->neighbors, (void (*)(struct hash_backet *,
							 void *))show_json_srdb,
			     (void *)json_node_array);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		hash_iterate(area->srdb->neighbors, (void (*)(struct hash_backet *,
							 void *))show_vty_srdb,
			     (void *)vty);
	}
	return CMD_SUCCESS;
}

/* Install new CLI commands */
void isis_sr_register_vty(void)
{
	install_element(VIEW_NODE, &show_ip_isis_srdb_cmd);

}
