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
#include "sockunion.h"
#include "stream.h"
#include "table.h"
#include "thread.h"
#include "vty.h"
#include "zclient.h"
#include <lib/json.h>
#include "lib/lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_errors.h"

#if 0
static inline void del_sid_nhlfe(struct sr_nhlfe nhlfe);
#endif

/*
 * Segment Routing Data Base functions
 */

/* Hash function for Segment Routing entry */
static unsigned int sr_node_hash(const void *p)
{
	const struct sr_node *srn = p;

	return jhash(srn->sysid, ISIS_SYS_ID_LEN, 0x55aa5a5a);
}

/* Compare 2 Router ID hash entries based on SR Node */
static bool sr_node_cmp(const void *p1, const void *p2)
{
	const struct sr_node *srn1 = p1, *srn2 = p2;

	return (memcmp(srn1->sysid, srn2->sysid, ISIS_SYS_ID_LEN) == 0);
}

#if 0
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
#endif

/* Allocate new Segment Routine Node */
static void *sr_node_new(void *arg)
{
	struct sr_node *srn = arg;
	struct sr_node *new;

	/* Allocate Segment Routing node memory */
	new = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_node));

	/* Default Algorithm, SRGB and MSD */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		new->algo[i] = SR_ALGORITHM_UNSET;

	new->srgb.lower_bound = 0;
	new->srgb.range_size = 0;
	new->msd = 0;

#if 0
	/* Create Link, Prefix and Range TLVs list */
	new->ext_link = list_new();
	new->ext_prefix = list_new();
	new->ext_link->del = del_sr_link;
	new->ext_prefix->del = del_sr_pref;
#endif

	memcpy(new->sysid, srn->sysid, ISIS_SYS_ID_LEN);
	new->neighbor = NULL;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Created new SR node for %s",
			   sysid_print(new->sysid));

	return new;
}

/* Delete Segment Routing node */
static void sr_node_del(struct sr_node *srn)
{
	/* Sanity Check */
	if (srn == NULL)
		return;

#if 0
	/* Clean Extended Link */
	list_delete(&srn->ext_link);

	/* Clean Prefix List */
	list_delete(&srn->ext_prefix);
#endif

	XFREE(MTYPE_ISIS_SR, srn);
}

#if 0
/* Get SR Node for a given nexthop */
static struct sr_node *get_sr_node_by_nexthop(struct isis *isis,
					      struct in_addr nexthop)
{
	struct isis_interface *oi = NULL;
	struct isis_neighbor *nbr = NULL;
	struct listnode *node;
	struct route_node *rn;
	struct sr_node *srn;
	bool found;

	/* Sanity check */
	if (OspfSR.neighbors == NULL)
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
	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors, &nbr->router_id);

	return srn;
}
#endif

/* Segment Routing starter function */
void isis_sr_start(struct isis_area *area)
{
	struct sr_node *srn;
	struct isis_circuit *circuit;
	struct listnode *node;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Starting Segment Routing", __func__);

	/* Initialize self SR Node */
	srn = hash_get(area->srdb.neighbors, (void *)&(area->isis->sysid),
		       sr_node_new);

	/* Complete & Store self SR Node */
	srn->srgb.lower_bound = area->srdb.lower_bound;
	srn->srgb.range_size = area->srdb.upper_bound
			       - area->srdb.lower_bound + 1;
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		srn->algo[i] = area->srdb.algo[i];
	srn->msd = area->srdb.msd;
	area->srdb.self = srn;

	if (IS_DEBUG_ISIS(DEBUG_EVENTS))
		zlog_debug("SR (%s): Update SR-DB from LSDB", __func__);

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
		isis_sr_circuit_set_sid_adjs(circuit);

	lsp_regenerate_schedule(area, area->is_type, 0);
}

/* Stop Segment Routing */
void isis_sr_stop(struct isis_area *area)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Stopping Segment Routing", __func__);

	/* Stop SR */
	area->srdb.enabled = false;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
		isis_sr_circuit_unset_sid_adjs(circuit);

	lsp_regenerate_schedule(area, area->is_type, 0);

	/*
	 * Remove all SR Nodes from the Hash table. Prefix and Link SID will
	 * be remove though list_delete() call. See sr_node_del()
	 */
	hash_clean(area->srdb.neighbors, (void (*)(void *))sr_node_del);
}

/*
 * Segment Routing initialize function
 *
 * @param - nothing
 * @return - nothing
 */
void isis_sr_init(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;

	memset(srdb, 0, sizeof(*srdb));
	srdb->enabled = false;

	/* Initialize SRGB, Algorithms and MSD TLVs */
	/* Only Algorithm SPF is supported */
	srdb->algo[0] = SR_ALGORITHM_SPF;
	for (int i = 1; i < SR_ALGORITHM_COUNT; i++)
		srdb->algo[i] = SR_ALGORITHM_UNSET;

	/* Initialize Hash table for neighbor SR nodes */
	srdb->neighbors =
		hash_create(sr_node_hash, sr_node_cmp, "ISIS SR Neighbors");

	/* Initialize Route Table for Prefix-SID mappings */
	srdb->prefix4_sids = route_table_init();
	srdb->prefix6_sids = route_table_init();

	/* Default values */
	srdb->msd = 0;
#ifndef FABRICD
	srdb->lower_bound = yang_get_default_uint32(
		"/frr-isisd:isis/instance/segment-routing/srgb/lower-bound");
	srdb->upper_bound = yang_get_default_uint32(
		"/frr-isisd:isis/instance/segment-routing/srgb/upper-bound");
#else
	/* TODO */
	//srdb->srgb.range_size = MPLS_DEFAULT_MAX_SRGB_SIZE;
	//srdb->srgb.lower_bound = MPLS_DEFAULT_MIN_SRGB_LABEL;
#endif /* ifndef FABRICD */

	/* Register Various event hook */
	hook_register_prio(isis_lsp_event_hook, 100, srdb_lsp_event);
	hook_register(isis_if_new_hook, isis_sr_if_new_hook);
	hook_register(isis_circuit_type_update_hook,
		      isis_sr_circuit_type_update_hook);
}

/*
 * Segment Routing termination function
 *
 * @param - nothing
 * @return - nothing
 */
void isis_sr_term(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;

	/* Unregister various event hook */
	hook_unregister(isis_lsp_event_hook, srdb_lsp_event);
	hook_unregister(isis_if_new_hook, isis_sr_if_new_hook);
	hook_unregister(isis_circuit_type_update_hook,
		      isis_sr_circuit_type_update_hook);

	/* Stop Segment Routing */
	isis_sr_stop(area);

	/* Clear SR Node Table */
	hash_free(srdb->neighbors);

	/* Clear Prefix Table */
	route_table_finish(srdb->prefix4_sids);
	route_table_finish(srdb->prefix6_sids);

	srdb->enabled = false;
	srdb->self = NULL;
}

void isis_sr_srgb_update(struct isis_area *area)
{
	/* Set SID/Label range SRGB */
	if (area->srdb.self != NULL) {
		area->srdb.self->srgb.lower_bound = area->srdb.lower_bound;
		area->srdb.self->srgb.range_size =
			area->srdb.upper_bound - area->srdb.lower_bound +1;
	}

#if 0
	/* Update NHLFE entries */
	hash_iterate(area->srdb.neighbors,
		     (void (*)(struct hash_backet *, void *))update_in_nhlfe,
		     NULL);
#endif

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_msd_update(struct isis_area *area)
{
	/* Set this router MSD */
	if (area->srdb.self != NULL)
		area->srdb.self->msd = area->srdb.msd;

	lsp_regenerate_schedule(area, area->is_type, 0);
}

/* Functions to Manage Adjacency & Lan-Adjacency SID */
static void isis_sr_circuit_set_sid_adjs(struct isis_circuit *circuit)
{
	struct isis_adj_sid *adj_sid;
	struct isis_lan_adj_sid *ladj_sid;

	if (circuit->ext == NULL)
		circuit->ext =
			XCALLOC(MTYPE_ISIS_CIRCUIT, sizeof(*circuit->ext));

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		if (IS_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID))
			break;
		ladj_sid = &circuit->ext->ladj_sid[0];
		ladj_sid->flags = 0;
		ladj_sid->weight = 0;
		/* TODO: Check if it is not the neighbor System ID and
		 * not the local System ID that is need
		 *  memcpy(ladj_sid->neighbor_id, circuit->u.bc.XXXX,
		 *      sizeof(ladj_sid->neighbor_id));
		 */
		memcpy(ladj_sid->neighbor_id, circuit->area->isis->sysid,
		       sizeof(ladj_sid->neighbor_id));
		ladj_sid->sid = sr_get_local_label();
		SET_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID);
		break;
	case CIRCUIT_T_P2P:
		if (IS_SUBTLV(circuit->ext, EXT_ADJ_SID))
			break;
		adj_sid = &circuit->ext->adj_sid[0];
		adj_sid->flags = 0;
		adj_sid->weight = 0;
		adj_sid->sid = sr_get_local_label();
		SET_SUBTLV(circuit->ext, EXT_ADJ_SID);
		break;
	default:
		break;
	}
}

static void isis_sr_circuit_unset_sid_adjs(struct isis_circuit *circuit)
{
	if (circuit->ext == NULL)
		return;

	memset(&circuit->ext->adj_sid, 0, sizeof(circuit->ext->adj_sid));
	UNSET_SUBTLV(circuit->ext, EXT_ADJ_SID);
	memset(&circuit->ext->ladj_sid, 0, sizeof(circuit->ext->ladj_sid));
	UNSET_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID);
}

static struct route_table *
isis_sr_prefix_sid_find_table(const struct isis_area *area,
			      const struct prefix *prefix)
{
	switch (prefix->family) {
	case AF_INET:
		return area->srdb.prefix4_sids;
	case AF_INET6:
		return area->srdb.prefix6_sids;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown prefix family",
			 __func__);
		exit(1);
	}
}

struct sr_prefix *isis_sr_prefix_sid_add(struct isis_area *area,
					 const struct prefix *prefix)
{
	struct sr_prefix *srp;
	struct route_table *table;
	struct route_node *rn;
	struct interface *ifp;

	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(*srp));
	srp->prefix = *prefix;
	srp->nhlfe.prefix = *prefix;
	switch (prefix->family) {
	case AF_INET:
		srp->nhlfe.nexthop.ipv4 = prefix->u.prefix4;
		break;
	case AF_INET6:
		srp->nhlfe.nexthop.ipv6 = prefix->u.prefix6;
		break;
	}
	srp->area = area;

	/* Set flags. */
	ifp = if_lookup_prefix(prefix, VRF_DEFAULT);
	if (ifp && if_is_loopback(ifp))
		SET_FLAG(srp->flags, ISIS_PREFIX_SID_NODE);

	/* Add prefix-sid mapping to routing table. */
	table = isis_sr_prefix_sid_find_table(area, prefix);
	rn = route_node_get(table, prefix);
	assert(rn->info == NULL);
	rn->info = srp;

#if 0
	/* TODO: self might be NULL. Also, do we really need this? */
	listnode_add(area->srdb.self->ext_prefix, srp);
#endif

	return srp;
}

void isis_sr_prefix_sid_del(struct sr_prefix *srp)
{
	struct isis_area *area;
	struct route_table *table;
	struct route_node *rn;

	area = srp->area;
	table = isis_sr_prefix_sid_find_table(area, &srp->prefix);
	rn = route_node_lookup(table, &srp->prefix);
	rn->info = NULL;
	route_unlock_node(rn);

#if 0
	/* Delete NHLFE is NO-PHP is set */
	if (CHECK_FLAG(srp->flags, EXT_SUBTLV_LINK_ADJ_SID_PFLG))
		del_sid_nhlfe(srp->nhlfe);

	/* OK, all is clean, remove SRP from SRDB */
	listnode_delete(area->srdb.self->ext_prefix, srp);
#endif
	XFREE(MTYPE_ISIS_SR, srp);
}

struct sr_prefix *isis_sr_prefix_sid_find(const struct isis_area *area,
					  const struct prefix *prefix)
{
	struct route_table *table;
	struct route_node *rn;

	if (!area->srdb.enabled)
		return NULL;

	table = isis_sr_prefix_sid_find_table(area, prefix);
	rn = route_node_lookup(table, prefix);
	if (rn && rn->info)
		return rn->info;

	return NULL;
}

/* Function call by the different Hook */
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event)
{
	int rc = 0;

	switch(event) {
	case LSP_ADD:
		// rc = srdb_lsp_add(lsp);
		break;
	case LSP_DEL:
		// rc = srdb_lsp_del(lsp);
		break;
	case LSP_UPD:
		// rc = srdb_lsp_update(lsp);
		break;
	default:
		rc = 1;
		break;
	}

	return rc;
}

static int isis_sr_if_new_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return 0;

	area = circuit->area;
	if (!area->srdb.enabled)
		return 0;

	/* Create (LAN-)Adj-SID Sub-TLVs. */
	isis_sr_circuit_set_sid_adjs(circuit);

	/*
	 * Update the Node-SID flag of the configured Prefix-SID mappings if
	 * necessary. This needs to be done here since isisd reads the startup
	 * configuration before receiving interface information from zebra.
	 */
	FOR_ALL_INTERFACES_ADDRESSES(ifp, connected, node) {
		struct sr_prefix *srp;

		srp = isis_sr_prefix_sid_find(area, connected->address);
		if (!srp)
			continue;

		if (if_is_loopback(ifp)
		    && !CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_NODE)) {
			SET_FLAG(srp->flags, ISIS_PREFIX_SID_NODE);
			lsp_regenerate_schedule(area, area->is_type, 0);
		}
	}

	return 0;
}

static int isis_sr_circuit_type_update_hook(struct isis_circuit *circuit)
{
	struct isis_area *area;

	area = circuit->area;
	if (!area->srdb.enabled)
		return 0;

	/* Update (LAN-)Adj-SID Sub-TLVs. */
	isis_sr_circuit_unset_sid_adjs(circuit);
	isis_sr_circuit_set_sid_adjs(circuit);

	return 0;
}

#if 0
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
static struct isis_neighbor *get_neighbor_by_addr(struct isis *top,
						  struct in_addr addr)
{
	struct isis_neighbor *nbr;
	struct isis_interface *oi;
	struct listnode *node;
	struct route_node *rn;

	/* Sanity Check */
	if (top == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(top->oiflist, node, oi))
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;
			if (nbr)
				if (IPV4_ADDR_SAME(&nbr->address.u.prefix4,
						   &addr)
				    || IPV4_ADDR_SAME(&nbr->router_id, &addr)) {
					route_unlock_node(rn);
					return nbr;
				}
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
	struct isis_neighbor *nh;
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
			   inet_ntoa(nh->router_id));

	/* Set ifindex for this neighbor */
	srl->nhlfe[0].ifindex = nh->oi->ifp->ifindex;
	srl->nhlfe[1].ifindex = nh->oi->ifp->ifindex;

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
	srnext->neighbor = OspfSR.self;
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
	srp->nhlfe.label_in = index2label(srp->sid, OspfSR.srgb);
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
		if ((srn == OspfSR.self)
		    && !CHECK_FLAG(srp->flags, SUBTLV_PREFIX_SID_NPFLG))
			continue;

		/* Process only SID Index */
		if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_VFLG))
			continue;

		/* OK. Compute new NHLFE */
		memcpy(&new, &srp->nhlfe, sizeof(struct sr_nhlfe));
		new.label_in = index2label(srp->sid, OspfSR.srgb);
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
 * Following functions are call when new Segment Routing LSA are received
 *  - Router Information: isis_sr_ri_lsa_update() & isis_sr_ri_lsa_delete()
 *  - Extended Link: isis_sr_ext_link_update() & isis_sr_ext_link_delete()
 *  - Extended Prefix: isis_ext_prefix_update() & isis_sr_ext_prefix_delete()
 */

/* Update Segment Routing from Router Information LSA */
void isis_sr_ri_lsa_update(struct isis_lsa *lsa)
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

	if (OspfSR.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = hash_get(OspfSR.neighbors, (void *)&(lsah->adv_router),
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
		hash_release(OspfSR.neighbors, &(srn->adv_router));
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
		if (srn->neighbor == OspfSR.self)
			hash_iterate(OspfSR.neighbors,
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
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR Data Base", __func__);
		return;
	}

	/* Release Router ID entry in SRDB hash table */
	srn = hash_release(OspfSR.neighbors, &(lsah->adv_router));

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
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(OspfSR.neighbors,
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
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors,
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
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(OspfSR.neighbors,
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
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors,
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
#endif

/* Get Label for (LAN-)Adj-SID */
/* TODO: To be replace by Zebra Label Manager */
uint32_t sr_get_local_label(void)
{
	static uint32_t label = ADJ_SID_MIN - 1;

	if (label < ADJ_SID_MAX)
		label += 1;

	return label;
}

#if 0
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
	for (ALL_LIST_ELEMENTS_RO(OspfSR.self->ext_prefix, node, srp)) {
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
					srp->sid, OspfSR.self->srgb);
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
	if (srn == OspfSR.self)
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

	struct isis *isis;
	struct timeval start_time, stop_time;

	isis = THREAD_ARG(t);
	isis->t_sr_update = NULL;

	if (!OspfSR.update)
		return 0;

	monotime(&start_time);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Start SPF update", __func__);

	hash_iterate(OspfSR.neighbors, (void (*)(struct hash_backet *,
						 void *))isis_sr_nhlfe_update,
		     NULL);

	monotime(&stop_time);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): SPF Processing Time(usecs): %lld\n",
			   __func__,
			   (stop_time.tv_sec - start_time.tv_sec) * 1000000LL
				   + (stop_time.tv_usec - start_time.tv_usec));

	OspfSR.update = false;
	return 1;
}

#define ISIS_SR_UPDATE_INTERVAL	1

void isis_sr_update_timer_add(struct isis *isis)
{

	if (isis == NULL)
		return;

	/* Check if an update is not alreday engage */
	if (OspfSR.update)
		return;

	OspfSR.update = true;

	thread_add_timer(master, isis_sr_update_schedule, isis,
			 ISIS_SR_UPDATE_INTERVAL, &isis->t_sr_update);
}
#endif
