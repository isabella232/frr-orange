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
#include "lib/json.h"
#include "lib/lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_route.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_errors.h"

static inline void del_sid_nhlfe(struct sr_nhlfe nhlfe);
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event);
static void isis_sr_circuit_set_sid_adjs(struct isis_circuit *circuit);
static void isis_sr_circuit_unset_sid_adjs(struct isis_circuit *circuit);
static int isis_sr_circuit_type_update_hook(struct isis_circuit *circuit);
static int isis_sr_if_new_hook(struct interface *ifp);
static void update_in_nhlfe(struct hash_backet *backet, void *args);

/*
 * Segment Routing Data Base functions
 */

/* Hash function for Segment Routing entry */
static unsigned int sr_node_hash(void *p)
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

/* Functions to remove an SR Link */
static void del_sr_adj(void *val)
{
	struct sr_adjacency *sra = (struct sr_adjacency *)val;

	del_sid_nhlfe(sra->nhlfe);
	XFREE(MTYPE_ISIS_SR, sra);
}

/* Functions to remove an SR Prefix */
static void del_sr_pref(void *val)
{
	struct sr_prefix *srp = (struct sr_prefix *)val;

	del_sid_nhlfe(srp->nhlfe);
	XFREE(MTYPE_ISIS_SR, srp);
}

/* Get Label for (LAN-)Adj-SID */
/* TODO: To be replace by Zebra Label Manager */
static uint32_t sr_get_local_label(void)
{
	static uint32_t label = ADJ_SID_MIN - 1;

	if (label < ADJ_SID_MAX)
		label += 1;

	return label;
}

/* Allocate new Segment Routine Node */
static struct sr_node *sr_node_new(uint8_t *sysid)
{

	struct sr_node *new;

	if (sysid == NULL)
		return NULL;

	/* Allocate Segment Routing node memory */
	new = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_node));

	/* Default Algorithm, SRGB and MSD */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		new->cap.algo[i] = SR_ALGORITHM_UNSET;

	new->cap.srgb.lower_bound = 0;
	new->cap.srgb.range_size = 0;
	new->cap.msd = 0;

	/* Create Link, Prefix and Range TLVs list */
	new->pref_sids = list_new();
	new->pref_sids->del = del_sr_pref;
	new->adj_sids = list_new();
	new->adj_sids->del = del_sr_adj;

	memcpy(new->sysid, sysid, ISIS_SYS_ID_LEN);
	memset(new->lspid, 0, ISIS_SYS_ID_LEN + 2);
	new->neighbor = NULL;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Created new SR node for %s",
			   print_sys_hostname(new->sysid));

	return new;
}

/* Delete Segment Routing node */
static void sr_node_del(struct sr_node *srn)
{
	/* Sanity Check */
	if (srn == NULL)
		return;

	/* Clean Extended Link */
	list_delete(&srn->adj_sids);

	/* Clean Prefix List */
	list_delete(&srn->pref_sids);

	XFREE(MTYPE_ISIS_SR, srn);
}

/* Segment Routing starter function */
void isis_sr_start(struct isis_area *area)
{
	struct sr_node *srn;
	struct isis_circuit *circuit;
	struct listnode *node;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Starting Segment Routing", __func__);

	/* Initialize self SR Node */
	srn = (struct sr_node *)hash_get(area->srdb.neighbors,
					 (void *)&(area->isis->sysid),
					 (void *)sr_node_new);

	/* Complete & Store self SR Node */
	srn->cap.srgb.lower_bound = area->srdb.lower_bound;
	srn->cap.srgb.range_size =
		area->srdb.upper_bound - area->srdb.lower_bound + 1;
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		srn->cap.algo[i] = area->srdb.algo[i];
	srn->cap.msd = area->srdb.msd;
	area->srdb.self = srn;

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

/* Segment Routing configuration functions call by isis_northbound.c */
void isis_sr_srgb_update(struct isis_area *area)
{
	/* Set SID/Label range SRGB */
	if (area->srdb.self != NULL) {
		area->srdb.self->cap.srgb.lower_bound = area->srdb.lower_bound;
		area->srdb.self->cap.srgb.range_size =
			area->srdb.upper_bound - area->srdb.lower_bound +1;
	}

	/* Update NHLFE entries */
	hash_iterate(area->srdb.neighbors,
		     (void (*)(struct hash_backet *, void *))update_in_nhlfe,
		     (void *)&area->srdb);

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_msd_update(struct isis_area *area)
{
	/* Set this router MSD */
	if (area->srdb.self != NULL)
		area->srdb.self->cap.msd = area->srdb.msd;

	lsp_regenerate_schedule(area, area->is_type, 0);
}

/* Functions to Manage Adjacency & Lan-Adjacency SID */
static void isis_sr_circuit_set_sid_adjs(struct isis_circuit *circuit)
{
	struct isis_adj_sid *adj;
	struct isis_lan_adj_sid *lan;
	struct listnode *node;
	struct list *adjdb;
	struct isis_adjacency *ad;

	if (circuit->ext == NULL)
		circuit->ext =
			XCALLOC(MTYPE_ISIS_CIRCUIT, sizeof(*circuit->ext));

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		if (IS_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID))
			break;

		/* Set LAN Adj SID for each neighbors */
		adjdb = circuit->u.bc.adjdb[circuit->is_type - 1];
		for (ALL_LIST_ELEMENTS_RO(adjdb, node, ad)) {
			/* Install Primary SID ... */
			lan = XCALLOC(MTYPE_ISIS_SR, sizeof(lan));
			lan->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
			lan->weight = 0;
			memcpy(lan->neighbor_id, ad->sysid, ISIS_SYS_ID_LEN);
			lan->sid = sr_get_local_label();
			isis_tlvs_add_adj_sid(circuit->ext, adj);
			/* ... then Backup SID */
			lan = XCALLOC(MTYPE_ISIS_SR, sizeof(lan));
			lan->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_BFLG;
			lan->weight = 0;
			memcpy(lan->neighbor_id, ad->sysid, ISIS_SYS_ID_LEN);
			lan->sid = sr_get_local_label();
			isis_tlvs_add_adj_sid(circuit->ext, adj);
		}
		SET_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID);
		break;
	case CIRCUIT_T_P2P:
		if (IS_SUBTLV(circuit->ext, EXT_ADJ_SID))
			break;

		/* Install Primary SID ... */
		adj = XCALLOC(MTYPE_ISIS_SR, sizeof(adj));
		adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
			      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
		adj->weight = 0;
		adj->sid = sr_get_local_label();
		isis_tlvs_add_adj_sid(circuit->ext, adj);
		/* ... then Backup SID */
		adj = XCALLOC(MTYPE_ISIS_SR, sizeof(adj));
		adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
			      | EXT_SUBTLV_LINK_ADJ_SID_LFLG
			      | EXT_SUBTLV_LINK_ADJ_SID_BFLG;
		adj->weight = 0;
		adj->sid = sr_get_local_label();
		isis_tlvs_add_adj_sid(circuit->ext, adj);
		SET_SUBTLV(circuit->ext, EXT_ADJ_SID);
		break;
	default:
		break;
	}
}

static void isis_sr_circuit_unset_sid_adjs(struct isis_circuit *circuit)
{
	struct isis_item *item, *next_item;

	if (circuit->ext == NULL)
		return;

	for (item = circuit->ext->adj_sid.head; item; item = next_item) {
		next_item = item->next;
		XFREE(MTYPE_ISIS_SR, item);
	}
	UNSET_SUBTLV(circuit->ext, EXT_ADJ_SID);
	for (item = circuit->ext->lan_sid.head; item; item = next_item) {
		next_item = item->next;
		XFREE(MTYPE_ISIS_SR, item);
	}
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

	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));

	switch (prefix->family) {
	case AF_INET:
		srp->nhlfe.prefv4.prefix = prefix->u.prefix4;
		srp->nhlfe.prefv4.family = prefix->family;
		srp->nhlfe.prefv4.prefixlen = prefix->prefixlen;
		// srp->nhlfe.nexthop = prefix->u.prefix4; ???
		break;
	case AF_INET6:
		/* TODO: Add IPv6 support */
		break;
	}

	/* Set flags. */
	ifp = if_lookup_prefix(prefix, VRF_DEFAULT);
	if (ifp && if_is_loopback(ifp))
		SET_FLAG(srp->flags, ISIS_PREFIX_SID_NODE);

	/* Add prefix-sid mapping to routing table. */
	table = isis_sr_prefix_sid_find_table(area, prefix);
	rn = route_node_get(table, prefix);
	assert(rn->info == NULL);
	rn->info = srp;

	/* TODO: self might be NULL. Also, do we really need this? */
	listnode_add(area->srdb.self->pref_sids, srp);

	return srp;
}

void isis_sr_prefix_sid_del(struct sr_prefix *srp)
{
	struct isis_area *area;
	// struct route_table *table;
	struct route_node *rn;

	// table = isis_sr_prefix_sid_find_table(area, &srp->nhlfe.prefv4);
	rn = route_node_lookup(area->srdb.prefix4_sids, &srp->nhlfe.prefv4);
	rn->info = NULL;
	route_unlock_node(rn);

	/* Delete NHLFE if NO-PHP is set */
	if (CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_NO_PHP))
		del_sid_nhlfe(srp->nhlfe);

	/* OK, all is clean, remove SRP from SRDB */
	listnode_delete(area->srdb.self->pref_sids, srp);

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
		}
	}
	/* TODO: Check if it is not done in the calling function */
	lsp_regenerate_schedule(area, area->is_type, 0);
	return 0;
}

static int isis_sr_circuit_type_update_hook(struct isis_circuit *circuit)
{
	struct isis_area *area;

	area = circuit->area;
	if (!IS_SR(area))
		return 0;

	/* Update (LAN-)Adj-SID Sub-TLVs. */
	isis_sr_circuit_unset_sid_adjs(circuit);
	isis_sr_circuit_set_sid_adjs(circuit);

	return 0;
}

/*
 * Following functions are used to manipulate the
 * Next Hop Label Forwarding entry (NHLFE)
 */

/* Compute label from index */
static mpls_label_t index2label(uint32_t index, struct isis_srgb srgb)
{
	mpls_label_t label;

	label = srgb.lower_bound + index;
	if (label > (srgb.lower_bound + srgb.range_size))
		return MPLS_INVALID_LABEL;
	else
		return label;
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
#endif

/* Get ISIS Nexthop from IPv4 address */
static struct isis_nexthop *get_nexthop_by_prefix(struct isis_area *area,
						struct prefix_ipv4 p)
{
	struct route_node *rn = NULL;
	struct route_table *table;
	struct isis_nexthop *nh;
	struct isis_route_info *rinfo;
	struct listnode *node;

	/* Sanity Check */
	if (area == NULL)
		return NULL;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("      |-  Search Nexthop for prefix %s/%u",
			   inet_ntoa(p.prefix), p.prefixlen);

	switch (area->is_type) {
	case IS_LEVEL_1:
		table = area->spftree[SPFTREE_IPV4][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_2:
		table = area->spftree[SPFTREE_IPV4][1]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_1_AND_2:
		table = area->spftree[SPFTREE_IPV4][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		if (rn == NULL) {
			table = area->spftree[SPFTREE_IPV4][1]->route_table;
			rn = route_node_lookup(table, (struct prefix *)&p);
		}
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown ISIS Level",
			 __func__);
		break;
	}

	/*
	 * Check if we found an ISIS route. May be NULL if SPF has not
	 * yet populate routing table for this prefix.
	 */
	if (rn == NULL)
		return NULL;

	route_unlock_node(rn);
	rinfo = rn->info;
	if (rinfo == NULL)
		return NULL;

	/* Then search nexthop from this route */
	for (ALL_LIST_ELEMENTS_RO(rinfo->nexthops, node, nh))
		if (IPV4_ADDR_SAME(&nh->ip, &p.prefix)
		    || IPV4_ADDR_SAME(&nh->router_address, &p.prefix))
			return nh;

	return NULL;
}

/* Get ISIS Nexthop from IPv6 address */
static struct isis_nexthop6 *get_nexthop6_by_prefix6(struct isis_area *area,
						     struct prefix_ipv6 p)
{
	struct route_node *rn = NULL;
	struct route_table *table;
	struct isis_nexthop6 *nh6;
	struct isis_route_info *rinfo;
	struct listnode *node;
	char addrbuf[INET6_ADDRSTRLEN];

	/* Sanity Check */
	if (area == NULL)
		return NULL;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("      |-  Search Nexthop for prefix %s/%u",
			   inet_ntop(AF_INET6, &p.prefix, addrbuf,
				     sizeof(addrbuf)),
			   p.prefixlen);

	switch (area->is_type) {
	case IS_LEVEL_1:
		table = area->spftree[SPFTREE_IPV6][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_2:
		table = area->spftree[SPFTREE_IPV6][1]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_1_AND_2:
		table = area->spftree[SPFTREE_IPV6][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		if (rn == NULL) {
			table = area->spftree[SPFTREE_IPV6][1]->route_table;
			rn = route_node_lookup(table, (struct prefix *)&p);
		}
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown ISIS Level",
			 __func__);
		break;
	}

	/*
	 * Check if we found an ISIS route. May be NULL if SPF has not
	 * yet populate routing table for this prefix.
	 */
	if (rn == NULL)
		return NULL;

	route_unlock_node(rn);
	rinfo = rn->info;
	if (rinfo == NULL)
		return NULL;

	/* Then search nexthop from this route */
	for (ALL_LIST_ELEMENTS_RO(rinfo->nexthops6, node, nh6))
		if (IPV6_ADDR_SAME(&nh6->ip6, &p.prefix)
		    || IPV6_ADDR_SAME(&nh6->router_address6, &p.prefix))
			return nh6;

	return NULL;
}

/* Compute NHLFE entry for Extended Link */
static int compute_adj_nhlfe(struct isis_area * area, struct sr_adjacency *sra)
{
	struct isis_nexthop *nh;
	int rc = 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Compute NHLFE for link %s/%u",
			   inet_ntoa(sra->nhlfe.prefv4.prefix),
			   sra->nhlfe.prefv4.prefixlen);

	/* First determine the ISIS Neighbor */
	// TODO: nh = get_neighbor_by_addr(area, sra->nhlfe.nexthop);

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
	sra->nhlfe.ifindex = nh->ifindex;
	sra->nhlfe.ifindex = nh->ifindex;

	/* Update neighbor address for LAN_ADJ_SID */
	if (sra->type == LAN_ADJ_SID) {
		IPV4_ADDR_COPY(&sra->nhlfe.nexthop, &nh->ip);
	}

	/* Set Input & Output Label */
	if (CHECK_FLAG(sra->flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG))
		sra->nhlfe.label_in = sra->sid;
	else
		sra->nhlfe.label_in =
			index2label(sra->sid, sra->srn->cap.srgb);

	sra->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;

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
static int compute_prefix_nhlfe(struct isis_area *area, struct sr_prefix *srp)
{
	struct isis_nexthop *nh = NULL;
	struct sr_node *srnext;
	int rc = -1;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Compute NHLFE for prefix %s/%u",
			   inet_ntoa(srp->nhlfe.prefv4.prefix),
			   srp->nhlfe.prefv4.prefixlen);

	/* First determine the nexthop */
	// TODO: nh = get_nexthop_by_addr(srdb, srp->nhlfe.prefv4);

	/* Nexthop could be not found when ISIS Adjacency just fire up
	 * because SPF don't yet populate routing table. This NHLFE will
	 * be fixed later when SR SPF schedule will be called.
	 */
	if (nh == NULL)
		return rc;

	/* Check if NextHop has changed when call after running a new SPF */
	if (IPV4_ADDR_SAME(&nh->router_address, &srp->nhlfe.nexthop)
	    && (nh->ifindex == srp->nhlfe.ifindex))
		return 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Found new next hop for this NHLFE: %s",
			   inet_ntoa(nh->router_address));

	/*
	 * Get SR-Node for this nexthop. Could be not yet available
	 * if Extended IS / IP and Router Information TLVs are not
	 * yet present in the LSP_DB
	 */
	// TODO: srnext = get_sr_node_by_nexthop(srdb, nh->router_address);
	if (srnext == NULL)
		return rc;

	/* And store this information for later update if SR Node is found */
	srnext->neighbor = area->srdb.self;
	if (memcmp(srnext->sysid, srp->id, ISIS_SYS_ID_LEN) == 0)
		srp->nexthop = NULL;
	else
		srp->nexthop = srnext;

	/*
	 * SR Node could be known, but SRGB could be not initialized
	 */
	if ((srnext == NULL) || (srnext->cap.srgb.lower_bound == 0)
	    || (srnext->cap.srgb.range_size == 0))
		return rc;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("    |-  Found SRGB %u/%u for next hop SR-Node %s",
			   srnext->cap.srgb.range_size,
			   srnext->cap.srgb.lower_bound,
			   print_sys_hostname(srnext->sysid));

	/* Set ip addr & ifindex for this neighbor */
	IPV4_ADDR_COPY(&srp->nhlfe.nexthop, &nh->router_address);
	srp->nhlfe.ifindex = nh->ifindex;

	/* Compute Input Label with self SRGB */
	srp->nhlfe.label_in = index2label(srp->sid, area->srdb.self->cap.srgb);
	/*
	 * and Output Label with Next hop SR Node SRGB or Implicit Null label
	 * if next hop is the destination and request PHP
	 */
	if ((srp->nexthop == NULL)
	    && (!CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_NO_PHP)))
		srp->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
	else if (CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_VALUE))
		srp->nhlfe.label_out = srp->sid;
	else
		srp->nhlfe.label_out = index2label(srp->sid, srnext->cap.srgb);

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

/* Update NHLFE entry for SID
 * Make before break is not always possible if input label is the same,
 * Linux Kernel refuse to add a second entry so we must first remove the
 * old MPLS entry before adding the new one */
static inline void update_sid_nhlfe(struct sr_nhlfe n1, struct sr_nhlfe n2)
{
	del_sid_nhlfe(n1);
	add_sid_nhlfe(n2);
}

/*
 * Functions to manipulate Segment Routing Link & Prefix structures
 */

/* Compare two Segment Link: return 0 if equal, 1 otherwise */
static inline int sr_adj_cmp(struct sr_adjacency *sra1,
			     struct sr_adjacency *sra2)
{
	if ((sra1->sid == sra2->sid) && (sra1->type == sra2->type)
	    && (sra1->flags == sra2->flags))
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

/* Update Segment Link of given Segment Routing Node */
static void update_adjacency_sid(struct isis_area *area, struct sr_node *srn,
				 struct sr_adjacency *sra, uint8_t lsp_own)
{
	struct listnode *node;
	struct sr_adjacency *adj;
	bool found = false;

	/* Sanity check */
	if ((srn == NULL) || (sra == NULL))
		return;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Process Extended IS Adj/Lan-SID");

	/* Process only Local Adj/Lan_Adj SID coming from LSA SELF */
	if (!CHECK_FLAG(sra->flags, EXT_SUBTLV_LINK_ADJ_SID_LFLG)
	    || !CHECK_FLAG(sra->flags, EXT_SUBTLV_LINK_ADJ_SID_LFLG)
	    || lsp_own == 0)
		return;

	/* Search for existing Segment Link */
	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, adj))
		if (memcmp(adj->id, sra->id, ISIS_SYS_ID_LEN + 1) == 0) {
			found = true;
			break;
		}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  %s SR Adjacency %s for SR node %s",
			   found ? "Update" : "Add",
			   rawlspid_print(sra->id),
			   print_sys_hostname(srn->sysid));

	/* if not found, add new Segment Adjacency and install NHLFE */
	if (!found) {
		/* Complete SR-Link and add it to SR-Node list */
		sra->srn = srn;
		listnode_add(srn->adj_sids, sra);
		/* Try to set MPLS table */
		if (compute_adj_nhlfe(area, sra))
			add_sid_nhlfe(sra->nhlfe);
	} else {
		if (sr_adj_cmp(adj, sra)) {
			if (compute_adj_nhlfe(area, sra)) {
				update_sid_nhlfe(adj->nhlfe, sra->nhlfe);
				/* Replace Segment List */
				listnode_delete(srn->adj_sids, adj);
				XFREE(MTYPE_ISIS_SR, adj);
				sra->srn = srn;
				listnode_add(srn->adj_sids, sra);
			} else {
				/* New NHLFE was not found.
				 * Just free the SR Link
				 */
				XFREE(MTYPE_ISIS_SR, sra);
			}
		} else {
			/*
			 * This is just an LSA refresh.
			 * Stop processing and free SR Link
			 */
			XFREE(MTYPE_ISIS_SR, sra);
		}
	}
}

/* Update Segment Prefix of given Segment Routing Node */
static void update_prefix_sid(struct isis_area *area, struct sr_node *srn,
			      struct sr_prefix *srp)
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
	if (CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_LOCAL))
		return;

	/* Search for existing Segment Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, pref))
		if (memcmp(pref->id, srp->id, ISIS_SYS_ID_LEN + 1) == 0) {
			found = true;
			break;
		}

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  %s SR LSP ID %s for SR node %s",
			   found ? "Update" : "Add",
			   rawlspid_print(srp->id),
			   print_sys_hostname(srn->sysid));

	/* if not found, add new Segment Prefix and install NHLFE */
	if (!found) {
		/* Complete SR-Prefix and add it to SR-Node list */
		srp->srn = srn;
		listnode_add(srn->pref_sids, srp);
		/* Try to set MPLS table */
		if (compute_prefix_nhlfe(area, srp) == 1)
			add_sid_nhlfe(srp->nhlfe);
	} else {
		if (sr_prefix_cmp(pref, srp)) {
			if (compute_prefix_nhlfe(area, srp) == 1) {
				update_sid_nhlfe(pref->nhlfe, srp->nhlfe);
				/* Replace Segment Prefix */
				listnode_delete(srn->pref_sids, pref);
				XFREE(MTYPE_ISIS_SR, pref);
				srp->srn = srn;
				listnode_add(srn->pref_sids, srp);
			} else {
				/* New NHLFE was not found.
				 * Just free the SR Prefix
				 */
				XFREE(MTYPE_ISIS_SR, srp);
			}
		} else {
			/* This is just an LSP refresh.
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
	struct isis_sr_db *srdb = (struct isis_sr_db *)args;
	struct sr_prefix *srp;
	struct sr_nhlfe new;

	/* Process Every Extended Prefix for this SR-Node */
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp)) {
		/* Process Self SRN only if NO-PHP is requested */
		if ((srn == srdb->self)
		    && !CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_NO_PHP))
			continue;

		/* Process only SID Index */
		if (CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_VALUE))
			continue;

		/* OK. Compute new NHLFE */
		memcpy(&new, &srp->nhlfe, sizeof(struct sr_nhlfe));
		new.label_in = index2label(srp->sid, srdb->self->cap.srgb);
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

	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp)) {
		/* Process only SID Index for next hop without PHP */
		if ((srp->nexthop == NULL)
		    && (!CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_NO_PHP)))
			continue;
		memcpy(&new, &srp->nhlfe, sizeof(struct sr_nhlfe));
		new.label_out = index2label(srp->sid, srnext->cap.srgb);
		update_sid_nhlfe(srp->nhlfe, new);
		srp->nhlfe.label_out = new.label_out;
	}
}

/*
 * Following functions are call when new LSPs are received
 *  - Router Information: sr_ri_update() & sr_ri_delete()
 *  - Extended IS Reachability: sr_ext_is_update() & sr_ext_is_delete()
 *  - Extended IP Reachability: sr_prefix_update() & sr_prefix_delete()
 */
static uint8_t unset_id[ISIS_SYS_ID_LEN + 2] = {0};

/* Update Segment Routing from Router Information LSA */
static void sr_cap_update(struct isis_area *area, uint8_t *lspid,
			  struct isis_router_cap * cap)
{
	struct sr_node *srn;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	/* Get SR Node in hash table from LSP ID */
	srn = (struct sr_node *)hash_get(area->srdb.neighbors,
					 (void *)&(sysid),
					 (void *)sr_node_new);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't create SR node in hash table",
			 __func__);
		return;
	}

	if ((memcmp(srn->lspid, unset_id, ISIS_SYS_ID_LEN + 2) != 0)
	    && memcmp(srn->lspid, lspid, ISIS_SYS_ID_LEN + 2)
		       != 0) {
		flog_err(EC_ISIS_SR_INVALID_LSP_ID,
			 "SR (%s): Abort! Wrong LSP ID %s for SR node %s/%s",
			 __func__, rawlspid_print(lspid),
			 print_sys_hostname(srn->sysid),
			 rawlspid_print(srn->lspid));
		return;
	}

	/* Update Algorithms and Node MSD */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		srn->cap.algo[i] = cap->algo[i];
	srn->cap.msd = cap->msd;

	/* Check if it is a new SR Node or not */
	if (memcmp(srn->lspid, unset_id, ISIS_SYS_ID_LEN + 2) == 0) {
		/* update LSP ID  and router ID */
		memcpy(srn->lspid, lspid, ISIS_SYS_ID_LEN + 2);
		IPV4_ADDR_COPY(&srn->router_id, &cap->router_id);
		/* Copy SRGB */
		srn->cap.srgb.range_size = cap->srgb.range_size;
		srn->cap.srgb.lower_bound = cap->srgb.lower_bound;
		return;
	}

	/* Check if SRGB has changed */
	if ((srn->cap.srgb.range_size != cap->srgb.range_size)
	    || (srn->cap.srgb.lower_bound != cap->srgb.lower_bound)) {
		/* Update SRGB */
		srn->cap.srgb.range_size = cap->srgb.range_size;
		srn->cap.srgb.lower_bound = cap->srgb.lower_bound;
		/* Update NHLFE if it is a neighbor SR node */
		if (srn->neighbor == area->srdb.self)
			hash_iterate(area->srdb.neighbors,
				     (void (*)(struct hash_backet *,
					       void *))update_out_nhlfe,
				     (void *)srn);
	}
}

/*
 * Delete SR Node entry in hash table information corresponding
 * to an LSP that expired or remove SR Router Capabilities
 */
static void sr_cap_delete(struct isis_area *area, uint8_t *lspid)
{
	struct sr_node *srn;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Remove SR node %s from LSP %s",
			   __func__, print_sys_hostname(sysid),
			   rawlspid_print(lspid));

	/* Search for SYS_ID entry in SRDB hash table */
	srn = (struct sr_node *)hash_lookup(area->srdb.neighbors, &(sysid));

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_DELETE,
			 "SR (%s): Abort! no entry in SRDB for SR Node %s",
			 __func__, print_sys_hostname(sysid));
		return;
	}

	if ((memcmp(srn->lspid, unset_id, ISIS_SYS_ID_LEN + 2) != 0)
	    && memcmp(srn->lspid, lspid, ISIS_SYS_ID_LEN + 2)
		       != 0) {
		flog_err(EC_ISIS_SR_INVALID_LSP_ID,
			 "SR (%s): Abort! Wrong LSP ID %s for SR node %s/%s",
			 __func__, rawlspid_print(lspid),
			 print_sys_hostname(srn->sysid),
			 rawlspid_print(srn->lspid));
		return;
	}

	/* Remove SR node */
	hash_release(area->srdb.neighbors, &(sysid));
	sr_node_del(srn);
}

/* Update Segment Routing Adjacency from Extended IS Reachability TLV */
static void sr_adjacency_update(struct isis_area *area, uint8_t *lspid,
				uint8_t lsp_own,
				struct isis_extended_reach *ier)
{
	struct sr_node *srn;
	struct sr_adjacency *sra;
	struct isis_ext_subtlvs *exts = ier->subtlvs;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Process Extended IS LSP %s for Node %s",
			   __func__, rawlspid_print(lspid),
			   print_sys_hostname(sysid));

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(area->srdb.neighbors,
					 (void *)&(sysid),
					 (void *)sr_node_new);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't create SR node in hash table",
			 __func__);
		return;
	}

	/* Process Adjacent SID for this Extended IS Reachability */
	if (IS_SUBTLV(exts, EXT_ADJ_SID)) {
		struct isis_adj_sid *adj;
		for (adj = (struct isis_adj_sid *)exts->adj_sid.head; adj;
		     adj = adj->next) {
			sra = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_adjacency));
			memcpy(sra->id, ier->id, ISIS_SYS_ID_LEN + 1);
			sra->type = ADJ_SID;
			sra->sid = adj->sid;
			sra->flags = adj->flags;
			listnode_add(srn->adj_sids, sra);
			if (IS_DEBUG_ISIS(DEBUG_SR)) {
				zlog_debug(
					"  |-  Found %s Adj-SID %u for %s/%u",
					CHECK_FLAG(sra->flags,
						   EXT_SUBTLV_LINK_ADJ_SID_BFLG)
						? "Backup"
						: "Primary",
					sra->sid,
					inet_ntoa(sra->nhlfe.prefv4.prefix),
					sra->nhlfe.prefv4.prefixlen);
			}
		}
	}
	/* Process LAN Adjacent SID for this Extended IS Reachability */
	if (IS_SUBTLV(exts, EXT_LAN_ADJ_SID)) {
		struct isis_lan_adj_sid *lan;
		for (lan = (struct isis_lan_adj_sid *)exts->lan_sid.head; lan;
		     lan = lan->next) {
			sra = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_adjacency));
			memcpy(sra->id, ier->id, ISIS_SYS_ID_LEN + 1);
			sra->type = LAN_ADJ_SID;
			sra->sid = lan->sid;
			sra->flags = lan->flags;
			listnode_add(srn->adj_sids, sra);
			if (IS_DEBUG_ISIS(DEBUG_SR)) {
				zlog_debug(
					"  |-  Found %s Lan-SID %u for %s/%u",
					CHECK_FLAG(sra->flags,
						   EXT_SUBTLV_LINK_ADJ_SID_BFLG)
						? "Backup"
						: "Primary",
					sra->sid,
					inet_ntoa(sra->nhlfe.prefv4.prefix),
					sra->nhlfe.prefv4.prefixlen);
			}
		}
	}

	/* TODO: collect nexthop for nhlfe */
	update_adjacency_sid(area, srn, sra, lsp_own);
}

/* Delete Segment Routing Adjacency from Extended IS Reachability TLV */
static void sr_adjacency_delete(struct isis_area *area, uint8_t *lspid,
				struct isis_extended_reach *ier)
{
	struct listnode *node;
	struct sr_adjacency *sra;
	struct sr_node *srn;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Remove Adjacency from LSP %s for Node %s",
			   __func__, rawlspid_print(lspid),
			   print_sys_hostname(sysid));

	/* Search SR Node in hash table from SYS ID*/
	srn = (struct sr_node *)hash_lookup(area->srdb.neighbors,
					    (void *)&(sysid));

	/*
	 * SR-Node may be NULL if it has been remove previously when
	 * processing Router Capabilities LSP deletion
	 */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Stop! no entry in SRDB for SR Node %s",
			 __func__, print_sys_hostname(sysid));
		return;
	}

	/* Search for corresponding Adjacency SID and remove them */
	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, sra)) {
		if (memcmp(sra->id, ier->id, ISIS_SYS_ID_LEN + 1) == 0) {
			listnode_delete(srn->adj_sids, sra);
			XFREE(MTYPE_ISIS_SR, sra);
			sra = NULL;
		}
	}
}

/* Update Segment Routing prefix SID from Extended IP Reachability TLV */
static void sr_prefix_update(struct isis_area *area, uint8_t *lspid,
			     struct isis_extended_ip_reach *ipr)
{
	struct sr_node *srn;
	struct sr_prefix *srp;
	struct isis_prefix_sid *psid;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Process Extended IP LSP %s for Node %s",
			   __func__, rawlspid_print(lspid),
			   print_sys_hostname(sysid));

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(area->srdb.neighbors,
					 (void *)&(sysid),
					 (void *)sr_node_new);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't create SR node in hash table",
			 __func__);
		return;
	}

	if (ipr->subtlvs->prefix_sids.count == 0) {
		zlog_debug("SR (%s): No SID associated to this prefix %s/%d",
			   __func__, inet_ntoa(ipr->prefix.prefix),
			   ipr->prefix.prefixlen);
		return;
	}

	/* Process Prefix SID information for this Extended IP Reachability */
	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));
	srp->type = PREF_SID;
	psid = (struct isis_prefix_sid *)ipr->subtlvs->prefix_sids.head;
	srp->sid = psid->value;
	srp->flags = psid->flags;
	srp->algorithm = psid->algorithm;
	srp->srn = srn;
	// TODO: PREFIX_COPY_IPV4(srp->nhlfe.prefv4, ipr->prefix);
	apply_mask_ipv4(&srp->nhlfe.prefv4);

	/* Finally update SR prefix */
	update_prefix_sid(area, srn, srp);
}

/* Delete Segment Routing from Extended Prefix LSA */
static void sr_prefix_delete(struct isis_area *area, uint8_t *lspid,
			     struct isis_extended_ip_reach *ipr)
{
	struct listnode *node;
	struct sr_prefix *srp;
	struct sr_node *srn;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug(
			"SR (%s): Remove Extended Prefix LSP %s from %s",
			__func__, rawlspid_print(lspid),
			print_sys_hostname(sysid));

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(area->srdb.neighbors,
					    (void *)&(sysid));

	/*
	 * SR-Node may be NULL if it has been remove previously when
	 * processing Router Information LSA deletion
	 */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s):  Stop! no entry in SRDB for SR Node %s",
			 __func__, print_sys_hostname(sysid));
		return;
	}

	/* Search for corresponding Prefix SID and remove them */
	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, srp)) {
		if (memcmp(srp->id, lspid, ISIS_SYS_ID_LEN + 2) == 0) {
			listnode_delete(srn->adj_sids, srp);
			XFREE(MTYPE_ISIS_SR, srp);
			srp = NULL;
		}
	}
}

#if TO_CONFIRMED

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
	for (ALL_LIST_ELEMENTS_RO(OspfSR.self->pref_sids, node, srp)) {
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

#endif

/*
 * Following functions are used to update MPLS LFIB after a SPF run
 */

static void isis_sr_nhlfe_update(struct hash_backet *backet, void *args)
{

	struct sr_node *srn = (struct sr_node *)backet->data;
	struct isis_area *area = (struct isis_area *)args;
	struct listnode *node;
	struct sr_prefix *srp;
	struct sr_nhlfe old;
	int rc;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("  |-  Update Prefix for SR Node %s",
			   print_sys_hostname(srn->sysid));

	/* Skip Self SR Node */
	if (srn == area->srdb.self)
		return;

	/* Update Extended Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp)) {

		/* Backup current NHLFE */
		memcpy(&old, &srp->nhlfe, sizeof(struct sr_nhlfe));

		/* Compute the new NHLFE */
		rc = compute_prefix_nhlfe(area, srp);

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

	area = THREAD_ARG(t);
	area->srdb.t_sr_update = NULL;

	if (!area->srdb.update)
		return 0;

	monotime(&start_time);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Start SPF update", __func__);

	hash_iterate(area->srdb.neighbors, (void (*)(struct hash_backet *,
		     void *))isis_sr_nhlfe_update,
		     (void *)area);

	monotime(&stop_time);

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): SPF Processing Time(usecs): %lld\n",
			   __func__,
			   (stop_time.tv_sec - start_time.tv_sec) * 1000000LL
				   + (stop_time.tv_usec - start_time.tv_usec));

	area->srdb.update = false;
	return 1;
}

#define ISIS_SR_UPDATE_INTERVAL	1

void isis_sr_update_timer_add(struct isis_area *area)
{

	if (area == NULL)
		return;

	/* Check if an update is not alreday engage */
	if (area->srdb.update)
		return;

	area->srdb.update = true;

	thread_add_timer(master, isis_sr_update_schedule, area,
			 ISIS_SR_UPDATE_INTERVAL, &area->srdb.t_sr_update);
}

static int srdb_update_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct isis_extended_reach *ier;
	struct isis_extended_ip_reach *ipr;

	/* Sanity Check */
	if (lsp == NULL || lsp->tlvs == NULL)
		return rc;

	/* Check that SR is initialize and enable */
	if (IS_SR(lsp->area)) {
		if (IS_DEBUG_ISIS(DEBUG_SR))
			zlog_debug("SR (%s): SR is not enable",  __func__);
		return rc;
	}

	if (lsp->area->srdb.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return rc;
	}

	/* First Process Router Capability */
	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Process Router Capability from %s",
			   __func__, print_sys_hostname(lsp->hdr.lsp_id));

	if (lsp->tlvs->router_cap) {
		/* Check that there is Segment Routing information in this LSP */
		if (lsp->tlvs->router_cap->algo[0] == SR_ALGORITHM_UNSET
		    || lsp->tlvs->router_cap->srgb.range_size == 0
		    || lsp->tlvs->router_cap->srgb.lower_bound == 0) {
			sr_cap_delete(lsp->area, lsp->hdr.lsp_id);
		} else {
			sr_cap_update(lsp->area, lsp->hdr.lsp_id,
				      lsp->tlvs->router_cap);
		}
	} else {
		/* SR could have been stop on this Node */
		sr_cap_delete(lsp->area, lsp->hdr.lsp_id);
	}


	/* Then Extended IS Reachability */
	if (lsp->tlvs->extended_reach.count != 0) {
		ier = (struct isis_extended_reach *)
			      lsp->tlvs->extended_reach.head;
		for (; ier != NULL; ier = ier->next)
			/* Check that there is an Adjacency SID */
			if (ier->subtlvs
			    && (IS_SUBTLV(ier->subtlvs, EXT_ADJ_SID)
				|| IS_SUBTLV(ier->subtlvs, EXT_LAN_ADJ_SID)))
				sr_adjacency_update(lsp->area, lsp->hdr.lsp_id,
						    lsp->own_lsp, ier);
	}

	/* Extended IP Reachability */
	if (lsp->tlvs->extended_ip_reach.count != 0) {
		ipr = (struct isis_extended_ip_reach *)
			      lsp->tlvs->extended_ip_reach.head;
		for (; ipr; ipr = ipr->next) {
			if (ipr->subtlvs)
				sr_prefix_update(lsp->area, lsp->hdr.lsp_id,
						 ipr);
		}
	}

	/* TODO: Add Extended IPv6 prefix */

	rc = 0;
	return rc;
}


static int srdb_del_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct isis_extended_reach *ier;
	struct isis_extended_ip_reach *ipr;

	/* Sanity Check */
	if (lsp == NULL || lsp->tlvs == NULL)
		return rc;

	/* First Process Router Capability */
	if (lsp->tlvs->router_cap) {
		if (IS_DEBUG_ISIS(DEBUG_SR))
			zlog_debug(
				"SR (%s): Process Router Capability from %s",
				__func__,
				print_sys_hostname(lsp->hdr.lsp_id));

		sr_cap_delete(lsp->area, lsp->hdr.lsp_id);
	}

	/* Then Extended IS Reachebility */
	if (lsp->tlvs->extended_reach.count != 0) {
		ier = (struct isis_extended_reach *)
			      lsp->tlvs->extended_reach.head;
		for (; ier != NULL; ier = ier->next)
			if (ier->subtlvs
			    && (IS_SUBTLV(ier->subtlvs, EXT_ADJ_SID)
				|| IS_SUBTLV(ier->subtlvs, EXT_LAN_ADJ_SID)))
				sr_adjacency_delete(lsp->area, lsp->hdr.lsp_id,
						    ier);

	}

	/* Extended IP Reachability */
	if (lsp->tlvs->extended_ip_reach.count != 0) {
		ipr = (struct isis_extended_ip_reach *)
			      lsp->tlvs->extended_ip_reach.head;
		for (; ipr != NULL; ipr = ipr->next) {
			if (ier->subtlvs)
				sr_prefix_delete(lsp->area, lsp->hdr.lsp_id,
						 ipr);
		}
	}

	/* TODO: Add Extended IPv6 prefix */

	rc = 0;
	return rc;
}

/* Function call by the different Hook */
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event)
{
	int rc = 0;

	switch(event) {
	case LSP_ADD:
	case LSP_UPD:
		rc = srdb_update_lsp(lsp);
		break;
	case LSP_DEL:
		rc = srdb_del_lsp(lsp);
		break;
	case LSP_TICK:
	case LSP_INC:
		/* TODO: Add appropriate treatment if any */
	default:
		rc = 1;
		break;
	}

	return rc;
}

#if TO_BE_MOVE_IN_ISIS_CLI
/*
 * --------------------------------------
 * Followings are vty command functions.
 * --------------------------------------
 */

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
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
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
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp)) {
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

	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, srl)) {
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
	struct isis_area *area;

	if (!area->srdb.enabled) {
		vty_out(vty, "Segment Routing is disabled on this router\n");
		return CMD_WARNING;
	}

	if (uj) {
		json = json_object_new_object();
		json_node_array = json_object_new_array();
		json_object_string_add(json, "srdbID",
				       print_sys_hostname(area->srdb.self->sysid));
		json_object_object_add(json, "srNodes", json_node_array);
	} else {
		vty_out(vty,
			"\n\t\tISIS Segment Routing database for Node %s\n\n",
			print_sys_hostname(area->srdb.self->sysid));
	}

	if (argv_find(argv, argc, "self-originate", &idx)) {
		srn = area->srdb.self;
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
		srn = (struct sr_node *)hash_lookup(area->srdb.neighbors,
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
		hash_iterate(area->srdb.neighbors, (void (*)(struct hash_backet *,
							 void *))show_json_srdb,
			     (void *)json_node_array);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		hash_iterate(area->srdb.neighbors, (void (*)(struct hash_backet *,
							 void *))show_vty_srdb,
			     (void *)vty);
	}
	return CMD_SUCCESS;
}

#endif
