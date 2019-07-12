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
#include "isisd/isis_csm.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_route.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_errors.h"
#include "isisd/isis_dynhn.h"

static inline void add_sid_nhlfe(struct sr_nhlfe nhlfe, struct prefix p);
static inline void del_sid_nhlfe(struct sr_nhlfe nhlfe, struct prefix p);
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event);
static void isis_sr_circuit_update_sid_adjs(struct isis_circuit *circuit);
static void isis_sr_circuit_unset_sid_adjs(struct isis_circuit *circuit);
// static int isis_sr_circuit_type_update_hook(struct isis_circuit *circuit);
static int isis_sr_if_new_hook(struct interface *ifp);
static void update_in_nhlfe(struct hash_backet *backet, void *args);
static void update_prefix_sid(struct isis_area *area, struct sr_node *srn,
			      struct sr_prefix *srp);
static void isis_sr_register_vty(void);

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

/* Functions to remove an SR Link */
static void del_sr_adj(void *val)
{
	struct sr_adjacency *sra = (struct sr_adjacency *)val;

	del_sid_nhlfe(sra->nhlfe, sra->prefix);
	XFREE(MTYPE_ISIS_SR, sra);
}

/* Functions to remove an SR Prefix */
static void del_sr_pref(void *val)
{
	struct sr_prefix *srp = (struct sr_prefix *)val;

	del_sid_nhlfe(srp->nhlfe, srp->prefix);
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

	sr_debug("  |-  Created new SR node for %s",
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

	sr_debug("SR (%s): Starting Segment Routing", __func__);

	/* Initialize self SR Node */
	srn = (struct sr_node *)hash_get(area->srdb.neighbors,
					 (void *)&(area->isis->sysid),
					 (void *)sr_node_new);

	/* Complete & Store self SR Node */
	srn->cap.flags = ISIS_SUBTLV_SRGB_FLAG_I | ISIS_SUBTLV_SRGB_FLAG_V;
	srn->cap.srgb.lower_bound = area->srdb.lower_bound;
	srn->cap.srgb.range_size =
		area->srdb.upper_bound - area->srdb.lower_bound + 1;
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		srn->cap.algo[i] = area->srdb.algo[i];
	srn->cap.msd = area->srdb.msd;
	area->srdb.self = srn;
	srn->area = area;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
		isis_sr_circuit_update_sid_adjs(circuit);

	/* Enable SR and regenerate LSP */
	area->srdb.enabled = true;

	lsp_regenerate_schedule(area, area->is_type, 0);
}

/* Stop Segment Routing */
void isis_sr_stop(struct isis_area *area)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	sr_debug("SR (%s): Stopping Segment Routing", __func__);

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

	memset(srdb, 0, sizeof(struct isis_sr_db));
	srdb->enabled = false;

	/* Initialize SRGB, Algorithms and MSD TLVs */
	/* Only Algorithm SPF is supported */
	srdb->algo[0] = SR_ALGORITHM_SPF;
	for (int i = 1; i < SR_ALGORITHM_COUNT; i++)
		srdb->algo[i] = SR_ALGORITHM_UNSET;

	/* Initialize Hash table for neighbor SR nodes */
	srdb->neighbors =
		hash_create(sr_node_hash, sr_node_cmp, "ISIS SR Neighbors");

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
	// hook_register(isis_circuit_type_update_hook,
	// 	      isis_sr_circuit_type_update_hook);

	/* Install show command */
	isis_sr_register_vty();
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
	// hook_unregister(isis_circuit_type_update_hook,
	//	      isis_sr_circuit_type_update_hook);

	/* Stop Segment Routing */
	isis_sr_stop(area);

	/* Clear SR Node Table */
	hash_free(srdb->neighbors);

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

static void isis_sr_circuit_update_sid_adjs(struct isis_circuit *circuit)
{
	struct isis_adj_sid *adj;
	struct isis_lan_adj_sid *lan;
	struct listnode *node;
	struct list *adjdb;
	struct isis_adjacency *ad;

	/* Skip loopback */
	if (if_is_loopback(circuit->interface))
		return;

	/* Skip circuit not in state UP */
	if (circuit->state != C_STATE_UP)
		return;

	sr_debug("SR(%s): Update Adjacency SID for interface %s",
			   __func__, circuit->interface->name);

	if (circuit->ext == NULL) {
		circuit->ext = isis_alloc_ext_subtlvs();
		sr_debug("  |- Allocated new Extended subTLVs for interface %s",
			 circuit->interface->name);
	}

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		if (IS_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID)) {
			sr_debug("  |- LAN Adj-SID already set. Skip !");
			return;
		}
		/* Set LAN Adj SID for each neighbors */
		adjdb = circuit->u.bc.adjdb[circuit->is_type - 1];
		for (ALL_LIST_ELEMENTS_RO(adjdb, node, ad)) {
			/* Install Primary SID ... */
			lan = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_lan_adj_sid));
			lan->family = AF_INET;
			lan->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
			lan->weight = 0;
			memcpy(lan->neighbor_id, ad->sysid, ISIS_SYS_ID_LEN);
			lan->sid = sr_get_local_label();
			sr_debug(
				"  |- Set Primary LAN-Adj-SID %d for adjacency %s",
				lan->sid, rawlspid_print(ad->sysid));
			isis_tlvs_add_lan_adj_sid(circuit->ext, lan);
			/* ... then Backup SID */
			lan = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_lan_adj_sid));
			lan->family = AF_INET;
			lan->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_BFLG;
			lan->weight = 0;
			memcpy(lan->neighbor_id, ad->sysid, ISIS_SYS_ID_LEN);
			lan->sid = sr_get_local_label();
			sr_debug(
				"  |- Set Backup LAN-Adj-SID %d for adjacency %s",
				lan->sid, rawlspid_print(ad->sysid));
			isis_tlvs_add_lan_adj_sid(circuit->ext, lan);
		}
		SET_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID);
		break;
	case CIRCUIT_T_P2P:
		if (IS_SUBTLV(circuit->ext, EXT_ADJ_SID)) {
			sr_debug("  |- Adj-SID already set. Skip !");
			return;
		}
		if (circuit->ip_addrs != NULL
		    && listcount(circuit->ip_addrs) != 0) {
			/* Install Primary SID ... */
			adj = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_adj_sid));
			adj->family = AF_INET;
			adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
			adj->weight = 0;
			adj->sid = sr_get_local_label();
			sr_debug("  |- Set Primary Adj-SID %d for IPv4", adj->sid);
			isis_tlvs_add_adj_sid(circuit->ext, adj);
			/* ... then Backup SID */
			adj = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_adj_sid));
			adj->family = AF_INET;
			adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_BFLG;
			adj->weight = 0;
			adj->sid = sr_get_local_label();
			sr_debug("  |- Set Backup Adj-SID %d for IPv4", adj->sid);
			isis_tlvs_add_adj_sid(circuit->ext, adj);
		}
		if (circuit->ipv6_non_link != NULL
		    && listcount(circuit->ipv6_non_link) != 0) {
			/* Install Primary SID ... */
			adj = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_adj_sid));
			adj->family = AF_INET6;
			adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
			adj->weight = 0;
			adj->sid = sr_get_local_label();
			sr_debug("  |- Set Primary Adj-SID %d for IPv6", adj->sid);
			isis_tlvs_add_adj_sid(circuit->ext, adj);
			/* ... then Backup SID */
			adj = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_adj_sid));
			adj->family = AF_INET6;
			adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_LFLG
				      | EXT_SUBTLV_LINK_ADJ_SID_BFLG;
			adj->weight = 0;
			adj->sid = sr_get_local_label();
			sr_debug("  |- Set Backup Adj-SID %d for IPv6", adj->sid);
			isis_tlvs_add_adj_sid(circuit->ext, adj);
		}
		break;
	default:
		break;
	}
	sr_debug("  |- Extended subTLVS status 0x%x", circuit->ext->status);
}

static void isis_sr_circuit_unset_sid_adjs(struct isis_circuit *circuit)
{
	struct isis_item *item, *next_item;

	sr_debug("  |-  Unset Adjacency SID for interface %s",
			   circuit->interface->name);

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

struct sr_prefix *isis_sr_prefix_sid_add(struct isis_area *area,
					 const struct prefix *prefix)
{
	struct sr_prefix *srp;
	char buf[PREFIX2STR_BUFFER];

	if (!IS_SR(area) || area->srdb.self == NULL)
		return NULL;

	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));
	memcpy(&srp->prefix, prefix, sizeof(struct prefix));

	/* Set back pointer and add this prefix to self SR-Node */
	srp->srn = area->srdb.self;
	listnode_add(area->srdb.self->pref_sids, srp);

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf, PREFIX2STR_BUFFER);
	sr_debug("SR(%s): Added Prefix-SID %s/%d to self SR-Node %s",
		 __func__, buf, srp->prefix.prefixlen,
		 print_sys_hostname(area->srdb.self->sysid));

	return srp;
}

void isis_sr_prefix_commit(struct sr_prefix *srp)
{
	struct interface *ifp;

	/* Set flags & NHLFE if interface is Loopback */
	ifp = if_lookup_prefix(&srp->prefix, VRF_DEFAULT);
	if (ifp && if_is_loopback(ifp)) {
		sr_debug("  |- Add this prefix as Node-SID to Loopback");
		SET_FLAG(srp->flags, ISIS_PREFIX_SID_NODE);
		srp->nhlfe.ifindex = ifp->ifindex;
		srp->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
		srp->nhlfe.label_in = index2label(srp->sid,
						  srp->srn->cap.srgb);
		add_sid_nhlfe(srp->nhlfe, srp->prefix);
	}
}

void isis_sr_prefix_sid_del(struct sr_prefix *srp)
{
	struct isis_area *area = srp->srn->area;

	/* Delete NHLFE if NO-PHP is set */
	if (CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_NO_PHP))
		del_sid_nhlfe(srp->nhlfe, srp->prefix);

	/* OK, all is clean, remove SRP from self SR Node */
	listnode_delete(area->srdb.self->pref_sids, srp);

	XFREE(MTYPE_ISIS_SR, srp);
}

struct sr_prefix *isis_sr_prefix_sid_find(const struct isis_area *area,
					  const struct prefix *prefix)
{
	struct listnode *node;
	struct sr_prefix *srp;

	if (!IS_SR(area) || !area->srdb.self)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(area->srdb.self->pref_sids, node, srp)) {
		if (prefix_same(&srp->prefix, prefix))
			break;
		else
			srp = NULL;
	}

	return srp;
}

static int isis_sr_if_new_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;
	char buf[PREFIX2STR_BUFFER];

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return 0;

	area = circuit->area;
	if (!IS_SR(area))
		return 0;

	/* Create (LAN-)Adj-SID Sub-TLVs. */
	isis_sr_circuit_update_sid_adjs(circuit);

	/*
	 * Update the Node-SID flag of the configured Prefix-SID mappings if
	 * necessary. This needs to be done here since isisd reads the startup
	 * configuration before receiving interface information from zebra.
	 */
	if (!if_is_loopback(ifp))
		return 0;

	sr_debug("SR(%s): Update Loopback interface %s", __func__, ifp->name);
	FOR_ALL_INTERFACES_ADDRESSES(ifp, connected, node) {
		struct sr_prefix *srp;

		srp = isis_sr_prefix_sid_find(area, connected->address);
		if (srp) {
			inet_ntop(srp->prefix.family, &srp->prefix.u.prefix,
				  buf, PREFIX2STR_BUFFER);

			sr_debug("  |- Set Node SID to prefix %s/%d with ifindex %d",
				 buf, srp->prefix.prefixlen, ifp->ifindex);
			SET_FLAG(srp->flags, ISIS_PREFIX_SID_NODE);
			/* Set MPLS entry */
			srp->nhlfe.ifindex = ifp->ifindex;
			srp->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
			srp->nhlfe.label_in = index2label(srp->sid,
							  srp->srn->cap.srgb);
			add_sid_nhlfe(srp->nhlfe, srp->prefix);
		}
	}
	/* TODO: Check if it is not done in the calling function */
	lsp_regenerate_schedule(area, area->is_type, 0);
	return 0;
}

#ifdef TO_BE_IMPROVE
static int isis_sr_circuit_type_update_hook(struct isis_circuit *circuit)
{
	struct isis_area *area;

	area = circuit->area;
	if (!IS_SR(area))
		return 0;

	/* Update (LAN-)Adj-SID Sub-TLVs. */
	isis_sr_circuit_unset_sid_adjs(circuit);
	isis_sr_circuit_update_sid_adjs(circuit);

	return 0;
}
#endif

/*
 * Following functions are used to manipulate the
 * Next Hop Label Forwarding entry (NHLFE)
 */

/* Get nexthop from id */
static struct isis_adjacency *get_adj_by_id(struct isis_area *area,
					    uint8_t sysid[ISIS_SYS_ID_LEN])
{
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct listnode *node, *anode;

	/* Sanity Check */
	if (area == NULL)
		return NULL;

	sr_debug("      |-  Search adjacency for ID %s", sysid_print(sysid));
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[0], anode,
						  adj)) {
				if (memcmp(adj->sysid, sysid, ISIS_SYS_ID_LEN)
				    == 0)
					return (adj);
			}
			for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[1], anode,
						  adj)) {
				if (memcmp(adj->sysid, sysid, ISIS_SYS_ID_LEN)
				    == 0)
					return (adj);
			}
			break;
		case CIRCUIT_T_P2P:
			adj = circuit->u.p2p.neighbor;
			if (memcmp(adj->sysid, sysid, ISIS_SYS_ID_LEN) == 0)
				return (adj);
			break;
		default:
			break;
		}
	}
	return NULL;
}

/* Get ISIS Nexthop from prefix address */
static struct list *get_nexthop_by_prefix(struct isis_area *area,
					  struct prefix p)
{
	struct route_node *rn = NULL;
	struct route_table *table;
	struct isis_route_info *rinfo;
	uint8_t tree;
	char buf[PREFIX2STR_BUFFER];

	/* Sanity Check */
	if (area == NULL)
		return NULL;

	inet_ntop(p.family, &p.u.prefix, buf, PREFIX2STR_BUFFER);
	sr_debug("      |-  Search Nexthop for prefix %s/%u",
		 buf, p.prefixlen);

	switch(p.family) {
	case AF_INET:
		tree = SPFTREE_IPV4;
		break;
	case AF_INET6:
		tree = SPFTREE_IPV6;
		break;
	default:
		return NULL;
	}

	switch (area->is_type) {
	case IS_LEVEL_1:
		table = area->spftree[tree][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_2:
		table = area->spftree[tree][1]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_1_AND_2:
		table = area->spftree[tree][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		if (rn == NULL) {
			table = area->spftree[tree][1]->route_table;
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

	switch (p.family) {
	case AF_INET:
		return rinfo->nexthops;
	case AF_INET6:
		return rinfo->nexthops6;
	default:
		return NULL;
	}
}

/* Compute NHLFE entry for Extended IS Reachability */
static int compute_adj_nhlfe(struct isis_area * area, struct sr_adjacency *sra)
{
	struct isis_adjacency *adj;
	struct prefix_ipv4 *ipv4;
	struct prefix_ipv6 *ipv6;
	struct isis_circuit *circuit;
	int rc = 0;

	sr_debug("    |-  Compute NHLFE for Adjacency %s",
		 sysid_print(sra->neighbor));

	/* First determine the ISIS Adjacency */
	adj = get_adj_by_id(area, sra->neighbor);
	if (adj == NULL)
		return rc;

	circuit = adj->circuit;
	/* Set NHLFE */
	sra->nhlfe.ifindex = circuit->interface->ifindex;
	if ((sra->prefix.family == AF_INET)
	    && (circuit->ip_router && circuit->ip_addrs
		&& circuit->ip_addrs->count > 0)) {
		ipv4 = (struct prefix_ipv4 *)listgetdata(
			(struct listnode *)listhead(circuit->ip_addrs));

		IPV4_ADDR_COPY(&sra->prefix.u.prefix4, &ipv4->prefix);
		sra->prefix.prefixlen = IPV4_MAX_PREFIXLEN;
		sra->nhlfe.nexthop = adj->ipv4_addresses[0];
	}

	if ((sra->prefix.family == AF_INET6)
	    && (circuit->ipv6_router && circuit->ipv6_non_link
		&& circuit->ipv6_non_link->count > 0)) {

		ipv6 = (struct prefix_ipv6 *)listgetdata(
			(struct listnode *)listhead(circuit->ipv6_non_link));

		IPV6_ADDR_COPY(&sra->prefix.u.prefix6, &ipv6->prefix);
		sra->prefix.prefixlen = IPV6_MAX_PREFIXLEN;
		IPV6_ADDR_COPY(&sra->nhlfe.nexthop6, &adj->ipv6_addresses[0]);

	}
	sra->nhlfe.ifindex = circuit->interface->ifindex;

	/* Set Input & Output Label */
	if (CHECK_FLAG(sra->flags,
		       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
		sra->nhlfe.label_in = sra->sid;
	else
		sra->nhlfe.label_in = index2label(
			sra->sid, sra->srn->cap.srgb);
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
	struct list *nh_list;
	struct isis_nexthop *nh = NULL;
	struct isis_nexthop6 *nh6 = NULL;
	struct isis_adjacency *adj;
	struct sr_node *srnext;
	int rc = -1;
	char buf[PREFIX2STR_BUFFER];

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
		  PREFIX2STR_BUFFER);
	sr_debug("    |-  Compute NHLFE for prefix %s/%u",
		 buf, srp->prefix.prefixlen);

	/* First determine the nexthop */
	nh_list = get_nexthop_by_prefix(area, srp->prefix);

	/* Nexthop could be not found when ISIS Adjacency just fire up
	 * because SPF don't yet populate routing table. This NHLFE will
	 * be fixed later when SR SPF schedule will be called.
	 */
	if (nh_list == NULL || nh_list->count == 0)
		return rc;

	/* Process first solution TODO: Add support to ECMP by looking to the list */
	switch (srp->prefix.family) {
	case AF_INET:
		nh = (struct isis_nexthop *)listgetdata(listhead(nh_list));
		if (nh == NULL || nh->adj == NULL)
			return rc;

		/* Check if NextHop has changed when call after running a new SPF */
		if (IPV4_ADDR_SAME(&nh->ip, &srp->nhlfe.nexthop)
		    && (nh->ifindex == srp->nhlfe.ifindex))
			return 0;

		inet_ntop(AF_INET, &nh->ip, buf, PREFIX2STR_BUFFER);
		sr_debug("    |-  Found new next hop for this NHLFE: %s", buf);
		adj = nh->adj;
		break;
	case AF_INET6:
		nh6 = (struct isis_nexthop6 *)listgetdata(listhead(nh_list));
		if (nh6 == NULL || nh6->adj == NULL)
			return rc;

		/* Check if NextHop has changed when call after running a new SPF */
		if (IPV6_ADDR_SAME(&nh6->ip6, &srp->nhlfe.nexthop6)
		    && (nh6->ifindex == srp->nhlfe.ifindex))
			return 0;

		inet_ntop(AF_INET6, &nh6->ip6, buf, PREFIX2STR_BUFFER);
		sr_debug("    |-  Found new next hop for this NHLFE: %s", buf);
		adj = nh6->adj;
		break;
	default:
		return rc;
	}

	/*
	 * Get SR-Node for this nexthop. Could be not yet available
	 * if Extended IS / IP and Router Information TLVs are not
	 * yet present in the LSP_DB
	 */
	srnext = (struct sr_node *)hash_lookup(area->srdb.neighbors,
					       (void *)&(adj->sysid));
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

	sr_debug("    |-  Found SRGB %u/%u for next hop SR-Node %s",
		 srnext->cap.srgb.range_size, srnext->cap.srgb.lower_bound,
		 print_sys_hostname(srnext->sysid));

	/* Set ip addr & ifindex for this neighbor
	 * and Output Label with Next hop SR Node SRGB or Implicit Null label
	 * if next hop is the destination and request PHP
	 */
	if (srp->prefix.family == AF_INET) {
		IPV4_ADDR_COPY(&srp->nhlfe.nexthop, &nh->ip);
		srp->nhlfe.ifindex = nh->ifindex;
	} else if (srp->prefix.family == AF_INET6) {
		IPV6_ADDR_COPY(&srp->nhlfe.nexthop6, &nh6->ip6);
		srp->nhlfe.ifindex = nh6->ifindex;
	} else {
		return rc;
	}

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

	sr_debug("    |-  Computed new labels in: %u out: %u",
		 srp->nhlfe.label_in, srp->nhlfe.label_out);

	rc = 1;
	return rc;
}

/* Send MPLS Label entry to Zebra for installation or deletion */
static int isis_zebra_send_mpls_labels(int cmd, struct sr_nhlfe nhlfe,
				       struct prefix p)
{
	struct stream *s;
	char buf[PREFIX2STR_BUFFER];

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_putc(s, ZEBRA_LSP_SR);
	stream_putl(s, p.family);
	if (p.family == AF_INET) {
		stream_put_in_addr(s, &p.u.prefix4);
		stream_putc(s, p.prefixlen);
		stream_put_in_addr(s, &nhlfe.nexthop);
	} else {
		stream_write(s, (uint8_t *)&p.u.prefix6, 16);
		stream_putc(s, p.prefixlen);
		stream_write(s, (uint8_t *)&nhlfe.nexthop6, 16);
	}
	stream_putl(s, nhlfe.ifindex);
	stream_putc(s, ISIS_SR_PRIORITY_DEFAULT);
	stream_putl(s, nhlfe.label_in);
	stream_putl(s, nhlfe.label_out);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	inet_ntop(p.family, &p.u.prefix, buf, PREFIX2STR_BUFFER);
	sr_debug("    |-  %s MPLS entry %u/%u for %s via %u",
		 cmd == ZEBRA_MPLS_LABELS_ADD ? "Add" : "Delete",
		 nhlfe.label_in, nhlfe.label_out,
		 prefix2str(&p, buf, PREFIX2STR_BUFFER),
		 nhlfe.ifindex);

	return zclient_send_message(zclient);
}

/* Request zebra to install/remove FEC in FIB */
static int isis_zebra_send_mpls_ftn(int cmd, struct sr_nhlfe nhlfe,
				    struct prefix p)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	char buf[PREFIX2STR_BUFFER];

	memset(&api, 0, sizeof(struct zapi_route));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_ISIS;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, &p, sizeof(struct prefix));

	if (cmd == ZEBRA_ROUTE_ADD) {
		/* Metric value. */
		SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
		api.metric = ISIS_SR_DEFAULT_METRIC;
		/* Nexthop */
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		api_nh = &api.nexthops[0];
		if (p.family == AF_INET) {
			IPV4_ADDR_COPY(&api_nh->gate.ipv4, &nhlfe.nexthop);
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		} else {
			IPV6_ADDR_COPY(&api_nh->gate.ipv6, &nhlfe.nexthop6);
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		}
		api_nh->ifindex = nhlfe.ifindex;
		/* MPLS labels */
		SET_FLAG(api.message, ZAPI_MESSAGE_LABEL);
		api_nh->labels[0] = nhlfe.label_out;
		api_nh->label_num = 1;
		api_nh->vrf_id = VRF_DEFAULT;
		api.nexthop_num = 1;
	}

	inet_ntop(p.family, &p.u.prefix, buf, PREFIX2STR_BUFFER);
	sr_debug("    |-  %s FEC %u for %s/%u via %u",
		 cmd == ZEBRA_ROUTE_ADD ? "Add" : "Delete", nhlfe.label_out,
		 buf, p.prefixlen, nhlfe.ifindex);

	return zclient_route_send(cmd, zclient, &api);
}

/* Add new NHLFE entry for SID */
static inline void add_sid_nhlfe(struct sr_nhlfe nhlfe, struct prefix p)
{
	if ((nhlfe.label_in != 0) && (nhlfe.label_out != 0)) {
		isis_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_ADD, nhlfe, p);
		if (nhlfe.label_out != MPLS_LABEL_IMPLICIT_NULL)
			isis_zebra_send_mpls_ftn(ZEBRA_ROUTE_ADD, nhlfe, p);
	}
}

/* Remove NHLFE entry for SID */
static inline void del_sid_nhlfe(struct sr_nhlfe nhlfe, struct prefix p)
{
	if ((nhlfe.label_in != 0) && (nhlfe.label_out != 0)) {
		isis_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_DELETE, nhlfe, p);
		if (nhlfe.label_out != MPLS_LABEL_IMPLICIT_NULL)
			isis_zebra_send_mpls_ftn(ZEBRA_ROUTE_DELETE, nhlfe, p);
	}
}

/* Update NHLFE entry for SID
 * Make before break is not always possible if input label is the same,
 * Linux Kernel refuse to add a second entry so we must first remove the
 * old MPLS entry before adding the new one */
static inline void update_sid_nhlfe(struct sr_nhlfe n1, struct sr_nhlfe n2,
				    struct prefix p)
{
	del_sid_nhlfe(n1, p);
	add_sid_nhlfe(n2, p);
}

/*
 * Functions to manipulate Segment Routing Adjacency & Prefix structures
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

/* Update Adjacency SID */
static void update_adjacency_sid(struct isis_area *area, struct sr_node *srn,
				 struct sr_adjacency *sra)
{
	struct listnode *node;
	struct sr_adjacency *adj;
	bool found = false;

	/* Sanity check */
	if ((srn == NULL) || (sra == NULL))
		return;

	sr_debug("  |-  Process Extended IS Adj/Lan-SID");

	/* Search for existing Segment Adjacency */
	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, adj))
		if (prefix_same(&adj->prefix, &sra->prefix)
		    && (adj->flags == sra->flags)) {
			found = true;
			break;
		}

	sr_debug("  |-  %s SR Adjacency %s for SR node %s",
		 found ? "Update" : "Add", rawlspid_print(sra->id),
		 print_sys_hostname(srn->sysid));

	/* if not found, add new Segment Adjacency and install NHLFE */
	if (!found) {
		/* Complete SR-Link and add it to SR-Node list */
		sra->srn = srn;
		listnode_add(srn->adj_sids, sra);
		/* Try to set MPLS table */
		if (compute_adj_nhlfe(area, sra))
			add_sid_nhlfe(sra->nhlfe, sra->prefix);
	} else {
		if (sr_adj_cmp(adj, sra)) {
			if (compute_adj_nhlfe(area, sra)) {
				update_sid_nhlfe(adj->nhlfe, sra->nhlfe,
						 sra->prefix);
				/* Replace Segment List */
				listnode_delete(srn->adj_sids, adj);
				XFREE(MTYPE_ISIS_SR, adj);
				sra->srn = srn;
				listnode_add(srn->adj_sids, sra);
			} else {
				/* New NHLFE was not found.
				 * Just free the SR Adjacency
				 */
				XFREE(MTYPE_ISIS_SR, sra);
			}
		} else {
			/*
			 * This is just an LSP refresh.
			 * Stop processing and free SR Adjacency
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

	sr_debug("  |-  Process Extended Prefix SID %u", srp->sid);

	/* Process only Global Prefix SID */
	if (CHECK_FLAG(srp->flags, ISIS_PREFIX_SID_LOCAL))
		return;

	/* Search for existing Segment Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, pref))
		if (prefix_same(&pref->prefix, &srp->prefix)) {
			found = true;
			break;
		}

	sr_debug("  |-  %s SR LSP ID %s for SR node %s",
		 found ? "Update" : "Add", rawlspid_print(srp->id),
		 print_sys_hostname(srn->sysid));

	/* if not found, add new Segment Prefix and install NHLFE */
	if (!found) {
		/* Complete SR-Prefix and add it to SR-Node list */
		srp->srn = srn;
		listnode_add(srn->pref_sids, srp);
		/* Try to set MPLS table */
		if (compute_prefix_nhlfe(area, srp) == 1)
			add_sid_nhlfe(srp->nhlfe, srp->prefix);
	} else {
		if (sr_prefix_cmp(pref, srp)) {
			if (compute_prefix_nhlfe(area, srp) == 1) {
				update_sid_nhlfe(pref->nhlfe, srp->nhlfe,
						 srp->prefix);
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
		update_sid_nhlfe(srp->nhlfe, new, srp->prefix);
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
		update_sid_nhlfe(srp->nhlfe, new, srp->prefix);
		srp->nhlfe.label_out = new.label_out;
	}
}

/*
 * Following functions are call when new LSPs are received
 *  - Router Information: sr_ri_update() & sr_ri_delete()
 *  - Extended IS Reachability: sr_ext_is_update() & sr_ext_is_delete()
 *  - Extended IP Reachability: sr_prefix_update() & sr_prefix_delete()
 */
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

	/* Update Algorithms and Node MSD */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		srn->cap.algo[i] = cap->algo[i];
	/* Set Default Algorithm if unset */
	if (srn->cap.algo[0] == SR_ALGORITHM_UNSET)
		srn->cap.algo[0] = SR_ALGORITHM_SPF;
	srn->cap.msd = cap->msd;

	/* Check if it is a new SR Node or not */
	if (srn->area == NULL) {
		srn->area = area;
		/* update LSP ID */
		memcpy(srn->lspid, lspid, ISIS_SYS_ID_LEN + 2);
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

	sr_debug("SR (%s): Remove SR node %s from LSP %s", __func__,
		 print_sys_hostname(sysid), rawlspid_print(lspid));

	/* Search for SYS_ID entry in SRDB hash table */
	srn = (struct sr_node *)hash_lookup(area->srdb.neighbors,
					    (void *)&(sysid));

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_DELETE,
			 "SR (%s): Abort! no entry in SRDB for SR Node %s",
			 __func__, print_sys_hostname(sysid));
		return;
	}

	/* Remove SR node */
	hash_release(area->srdb.neighbors, &(sysid));
	sr_node_del(srn);
}

/* Update Segment Routing Adjacency from Extended IS Reachability TLV */
static void sr_adjacency_update(struct isis_area *area, uint8_t *lspid,
				struct isis_extended_reach *ier)
{
	struct sr_node *srn;
	struct sr_adjacency *sra;
	struct isis_ext_subtlvs *exts = ier->subtlvs;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	sr_debug("SR (%s): Process Extended IS LSP %s for Node %s", __func__,
		 rawlspid_print(lspid), print_sys_hostname(sysid));

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
			memcpy(sra->neighbor, ier->id, ISIS_SYS_ID_LEN);
			sra->prefix.family = adj->family;
			sra->type = ADJ_SID;
			sra->sid = adj->sid;
			sra->flags = adj->flags;

			sr_debug("  |-  Found %s Adj-SID %u for %s",
				 CHECK_FLAG(sra->flags,
					    EXT_SUBTLV_LINK_ADJ_SID_BFLG)
					 ? "Backup"
					 : "Primary",
				 sra->sid, print_sys_hostname(sra->neighbor));

			update_adjacency_sid(area, srn, sra);
		}
	}
	/* Process LAN Adjacent SID for this Extended IS Reachability */
	if (IS_SUBTLV(exts, EXT_LAN_ADJ_SID)) {
		struct isis_lan_adj_sid *lan;
		for (lan = (struct isis_lan_adj_sid *)exts->lan_sid.head; lan;
		     lan = lan->next) {
			sra = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_adjacency));
			memcpy(sra->id, ier->id, ISIS_SYS_ID_LEN + 1);
			memcpy(sra->neighbor, lan->neighbor_id, ISIS_SYS_ID_LEN);
			sra->prefix.family = lan->family;
			sra->type = LAN_ADJ_SID;
			sra->sid = lan->sid;
			sra->flags = lan->flags;

			sr_debug("  |-  Found %s Lan-SID %u for %s",
				 CHECK_FLAG(sra->flags,
					    EXT_SUBTLV_LINK_ADJ_SID_BFLG)
					 ? "Backup"
					 : "Primary",
				 sra->sid, print_sys_hostname(sra->neighbor));

			update_adjacency_sid(area, srn, sra);
		}
	}
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

	sr_debug("SR (%s): Remove Adjacency from LSP %s for Node %s", __func__,
		 rawlspid_print(lspid), print_sys_hostname(sysid));

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
	char buf[PREFIX2STR_BUFFER];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	sr_debug("SR (%s): Process Extended IP LSP %s for Node %s", __func__,
		 rawlspid_print(lspid), print_sys_hostname(sysid));

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

	/* Process Prefix SID information for this Extended IP Reachability */
	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));
	memcpy(srp->id, lspid, ISIS_SYS_ID_LEN + 1);
	srp->type = PREF_SID;
	psid = (struct isis_prefix_sid *)ipr->subtlvs->prefix_sids.head;
	srp->sid = psid->value;
	srp->flags = psid->flags;
	srp->algorithm = psid->algorithm;
	srp->srn = srn;
	srp->prefix.prefixlen = ipr->prefix.prefixlen;
	srp->prefix.family = AF_INET;
	IPV4_ADDR_COPY(&srp->prefix.u.prefix4, &ipr->prefix.prefix);
	// apply_mask(&srp->prefix);

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
		  PREFIX2STR_BUFFER);
	sr_debug("  |-  Found Prefix SID %s/%d", buf, srp->prefix.prefixlen);

	/* Finally update SR prefix */
	update_prefix_sid(area, srn, srp);
}

/* Update SR prefix SID from Multi Topology Reachable IPv6 Prefixes TLV */
static void sr_prefix6_update(struct isis_area *area, uint8_t *lspid,
			      struct isis_ipv6_reach *ipr6)
{
	struct sr_node *srn;
	struct sr_prefix *srp;
	struct isis_prefix_sid *psid;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	char buf[PREFIX2STR_BUFFER];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	sr_debug("SR (%s): Process MT Reach IPv6 LSP %s for Node %s", __func__,
		 rawlspid_print(lspid), print_sys_hostname(sysid));

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

	/* Process Prefix SID information for this Extended IP Reachability */
	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));
	srp->type = PREF_SID;
	psid = (struct isis_prefix_sid *)ipr6->subtlvs->prefix_sids.head;
	srp->sid = psid->value;
	srp->flags = psid->flags;
	srp->algorithm = psid->algorithm;
	srp->srn = srn;
	srp->prefix.prefixlen = ipr6->prefix.prefixlen;
	srp->prefix.family = AF_INET6;
	IPV6_ADDR_COPY(&srp->prefix.u.prefix6, &ipr6->prefix.prefix);
	// apply_mask(&srp->prefix);

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
		  PREFIX2STR_BUFFER);
	sr_debug("  |-  Added Prefix SID %s/%d", buf, srp->prefix.prefixlen);

	/* Finally update SR prefix */
	update_prefix_sid(area, srn, srp);
}


/* Delete Segment Routing Prefix SID */
static void sr_prefix_delete(struct isis_area *area, uint8_t *lspid)
{
	struct listnode *node;
	struct sr_prefix *srp;
	struct sr_node *srn;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	memcpy(sysid, lspid, ISIS_SYS_ID_LEN);

	sr_debug("SR (%s): Remove Extended Prefix LSP %s from %s", __func__,
		 rawlspid_print(lspid), print_sys_hostname(sysid));

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
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp)) {
		if (memcmp(srp->id, lspid, ISIS_SYS_ID_LEN + 2) == 0) {
			listnode_delete(srn->pref_sids, srp);
			XFREE(MTYPE_ISIS_SR, srp);
			srp = NULL;
		}
	}
}

/*
 * Following functions are used to update SR-DB once an LSP is received
 */
static int srdb_update_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct isis_extended_reach *ier;
	struct isis_extended_ip_reach *ipr;
	struct isis_ipv6_reach *ipr6;
	struct isis_item_list *items;

	/* Sanity Check */
	if (lsp == NULL || lsp->tlvs == NULL)
		return rc;

	if (lsp->area->srdb.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return rc;
	}

	/* Skip LSP pseudo or fragment that not carry SR information */
	if (LSP_PSEUDO_ID(lsp->hdr.lsp_id) != 0
	    || LSP_FRAGMENT(lsp->hdr.lsp_id) != 0) {
		sr_debug("SR (%s): Skip Pseudo or fragment LSP %s", __func__,
			 rawlspid_print(lsp->hdr.lsp_id));
		return rc;
	}

	/* First Process Router Capability for remote LSP */
	if (!lsp->own_lsp) {
		sr_debug("SR (%s): Process Router Capability from %s",
			 __func__,
			 print_sys_hostname(lsp->hdr.lsp_id));

		if (lsp->tlvs->router_cap) {
			/* Check that there is Segment Routing information in
			 * this LSP */
			if (lsp->tlvs->router_cap->srgb.range_size == 0
			    || lsp->tlvs->router_cap->srgb.lower_bound == 0)
				sr_cap_delete(lsp->area, lsp->hdr.lsp_id);
			else
				sr_cap_update(lsp->area, lsp->hdr.lsp_id,
					      lsp->tlvs->router_cap);
		} else {
			/* SR could have been stop on this Node */
			sr_cap_delete(lsp->area, lsp->hdr.lsp_id);
		}
	} else {
		/* Then Extended IS Reachability for own_lsp only */
		for (ier = (struct isis_extended_reach *)
				   lsp->tlvs->extended_reach.head;
		     ier != NULL; ier = ier->next)
			/* Check that there is an Adjacency SID */
			if (ier->subtlvs
			    && (IS_SUBTLV(ier->subtlvs, EXT_ADJ_SID)
				|| IS_SUBTLV(ier->subtlvs, EXT_LAN_ADJ_SID)))
				sr_adjacency_update(lsp->area, lsp->hdr.lsp_id,
						    ier);
		/* And Multi Topology Extended IS Reachability */
		items = isis_lookup_mt_items(&lsp->tlvs->mt_reach,
			     	     	     ISIS_MT_IPV6_UNICAST);
		if (items != NULL) {
			for (ier = (struct isis_extended_reach *)items->head;
			     ier != NULL; ier = ier->next)
				/* Check that there is an Adjacency SID */
				if (ier->subtlvs
				    && (IS_SUBTLV(ier->subtlvs, EXT_ADJ_SID)
					|| IS_SUBTLV(ier->subtlvs,
						     EXT_LAN_ADJ_SID)))
					sr_adjacency_update(lsp->area,
							    lsp->hdr.lsp_id,
							    ier);
		}
	}

	/* Extended IP Reachability */
	for (ipr = (struct isis_extended_ip_reach *)
			   lsp->tlvs->extended_ip_reach.head;
	     ipr != NULL; ipr = ipr->next) {
		/* Check that there is a Prefix SID */
		if (ipr->subtlvs && ipr->subtlvs->prefix_sids.count != 0)
			sr_prefix_update(lsp->area, lsp->hdr.lsp_id, ipr);
	}

	/* And Multi Topology Reachable IPv6 Prefixes */
	items = isis_lookup_mt_items(&lsp->tlvs->mt_ipv6_reach,
				     ISIS_MT_IPV6_UNICAST);
	if (items != NULL) {
		for (ipr6 = (struct isis_ipv6_reach *)items->head; ipr6;
		     ipr6 = ipr6->next) {
			/* Check that there is a Prefix SID */
			if (ipr6->subtlvs
			    && ipr6->subtlvs->prefix_sids.count != 0)
				sr_prefix6_update(lsp->area, lsp->hdr.lsp_id,
						  ipr6);
		}
	}

	rc = 0;
	return rc;
}


static int srdb_del_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct isis_extended_reach *ier;

	/* Sanity Check */
	if (lsp == NULL || lsp->tlvs == NULL)
		return rc;

	if (lsp->area->srdb.neighbors == NULL) {
		flog_err(EC_ISIS_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return rc;
	}

	/* Skip LSP pseudo or fragment that not carry SR information */
	if (LSP_PSEUDO_ID(lsp->hdr.lsp_id) != 0
	    || LSP_FRAGMENT(lsp->hdr.lsp_id) != 0) {
		sr_debug("SR (%s): Skip Pseudo or fragment LSP %s", __func__,
			 rawlspid_print(lsp->hdr.lsp_id));
		return rc;
	}

	/* First Process Router Capability */
	if (lsp->tlvs->router_cap)
		sr_cap_delete(lsp->area, lsp->hdr.lsp_id);

	/* Then Extended IS Reachability */
	if (lsp->tlvs->extended_reach.count != 0) {
		ier = (struct isis_extended_reach *)
			      lsp->tlvs->extended_reach.head;
		for (; ier; ier = ier->next)
			if (ier->subtlvs
			    && (IS_SUBTLV(ier->subtlvs, EXT_ADJ_SID)
				|| IS_SUBTLV(ier->subtlvs, EXT_LAN_ADJ_SID)))
				sr_adjacency_delete(lsp->area, lsp->hdr.lsp_id,
						    ier);
	}

	/* Remove All Prefix SID */
	sr_prefix_delete(lsp->area, lsp->hdr.lsp_id);

	rc = 0;
	return rc;
}

/* Function call by the different Hook */
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event)
{
	int rc = 0;

	/* Check that SR is initialized and enabled */
	if(!IS_SR(lsp->area))
		return rc;

	sr_debug("SR (%s): Process LSP id %s", __func__,
		 rawlspid_print(lsp->hdr.lsp_id));

	switch(event) {
	case LSP_ADD:
	case LSP_UPD:
	case LSP_INC:
		rc = srdb_update_lsp(lsp);
		break;
	case LSP_DEL:
		rc = srdb_del_lsp(lsp);
		break;
	case LSP_TICK:
		/* TODO: Add appropriate treatment if any */
		break;
	default:
		rc = 1;
		break;
	}

	return rc;
}

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

	sr_debug("  |-  Update Prefix for SR Node %s",
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
			del_sid_nhlfe(srp->nhlfe, srp->prefix);
			break;
		/* next hop has not changed, skip it */
		case 0:
			break;
		/* there is a new next hop, update NHLFE */
		case 1:
			update_sid_nhlfe(old, srp->nhlfe, srp->prefix);
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

	if (!IS_SR(area) || !area->srdb.update)
		return 0;

	monotime(&start_time);

	sr_debug("SR (%s): Start SPF update", __func__);

	hash_iterate(area->srdb.neighbors, (void (*)(struct hash_backet *,
		     void *))isis_sr_nhlfe_update,
		     (void *)area);

	monotime(&stop_time);

	sr_debug("SR (%s): SPF Processing Time(usecs): %lld\n", __func__,
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

/*
 * --------------------------------------
 * Followings are vty command functions.
 * --------------------------------------
 */

static void show_sr_node(struct vty *vty, struct json_object *json,
			 struct sr_node *srn)
{

	struct listnode *node;
	struct sr_adjacency *sra;
	struct sr_prefix *srp;
	struct interface *itf;
	char pref[19];
	char sid[22];
	char label[8];
	char buf[PREFIX2STR_BUFFER];
	json_object *json_node = NULL, *json_algo, *json_obj;
	json_object *json_prefix = NULL, *json_link = NULL;

	/* Sanity Check */
	if (srn == NULL)
		return;

	if (json) {
		json_node = json_object_new_object();
		json_object_string_add(json_node, "routerID",
				       print_sys_hostname(srn->sysid));
		json_object_int_add(json_node, "srgbSize",
				    srn->cap.srgb.range_size);
		json_object_int_add(json_node, "srgbLabel",
				    srn->cap.srgb.lower_bound);
		json_algo = json_object_new_array();
		json_object_object_add(json_node, "algorithms", json_algo);
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
			if (srn->cap.algo[i] == SR_ALGORITHM_UNSET)
				continue;
			json_obj = json_object_new_object();
			char tmp[2];

			snprintf(tmp, 2, "%u", i);
			json_object_string_add(
				json_obj, tmp,
				srn->cap.algo[i] == SR_ALGORITHM_SPF ? "SPF"
								     : "S-SPF");
			json_object_array_add(json_algo, json_obj);
		}
		if (srn->cap.msd != 0)
			json_object_int_add(json_node, "nodeMsd",
					    srn->cap.msd);
	} else {
		vty_out(vty, "SR-Node: %s", print_sys_hostname(srn->sysid));
		vty_out(vty, "\tSRGB (Size/Label): %u/%u",
			srn->cap.srgb.range_size,
			srn->cap.srgb.lower_bound);
		vty_out(vty, "\tAlgorithm(s): %s",
			srn->cap.algo[0] == SR_ALGORITHM_SPF ? "SPF" : "S-SPF");
		for (int i = 1; i < SR_ALGORITHM_COUNT; i++) {
			if (srn->cap.algo[i] == SR_ALGORITHM_UNSET)
				continue;
			vty_out(vty, "/%s",
				srn->cap.algo[i] == SR_ALGORITHM_SPF ? "SPF"
								 : "S-SPF");
		}
		if (srn->cap.msd != 0)
			vty_out(vty, "\tMSD: %u", srn->cap.msd);
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
		inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
			  PREFIX2STR_BUFFER);
		snprintf(pref, 19, "%s/%u", buf, srp->prefix.prefixlen);
		snprintf(sid, 22, "SR Pfx (idx %u)", srp->sid);
		if (srp->nhlfe.label_out == MPLS_LABEL_IMPLICIT_NULL)
			sprintf(label, "pop");
		else
			sprintf(label, "%u", srp->nhlfe.label_out);
		itf = if_lookup_by_index(srp->nhlfe.ifindex, VRF_DEFAULT);
		if (srp->prefix.family == AF_INET)
			inet_ntop(AF_INET, &srp->nhlfe.nexthop, buf,
				  PREFIX2STR_BUFFER);
		else
			inet_ntop(AF_INET6, &srp->nhlfe.nexthop6, buf,
				  PREFIX2STR_BUFFER);
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
			json_object_string_add(json_obj, "nexthop", buf);
			json_object_array_add(json_prefix, json_obj);
		} else {
			vty_out(vty, "%18s  %8u  %9s  %21s  %9s  %15s\n", pref,
				srp->nhlfe.label_in, label, sid,
				itf ? itf->name : "-", buf);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, sra)) {
		inet_ntop(sra->prefix.family, &sra->prefix.u.prefix, buf,
			  PREFIX2STR_BUFFER);
		snprintf(pref, 19, "%s/%u", buf, sra->prefix.prefixlen);
		snprintf(sid, 22, "SR Adj. (lbl %u)", sra->sid);
		if (sra->nhlfe.label_out == MPLS_LABEL_IMPLICIT_NULL)
			sprintf(label, "pop");
		else
			sprintf(label, "%u", sra->nhlfe.label_out);
		itf = if_lookup_by_index(sra->nhlfe.ifindex, VRF_DEFAULT);
		if (sra->prefix.family == AF_INET)
			inet_ntop(AF_INET, &sra->nhlfe.nexthop, buf,
				  PREFIX2STR_BUFFER);
		else
			inet_ntop(AF_INET6, &sra->nhlfe.nexthop6, buf,
				  PREFIX2STR_BUFFER);
		if (json) {
			if (!json_link) {
				json_link = json_object_new_array();
				json_object_object_add(
					json_node, "extendedLink", json_link);
			}
			json_obj = json_object_new_object();
			json_object_string_add(json_obj, "prefix", pref);
			json_object_int_add(json_obj, "sid", sra->sid);
			json_object_int_add(json_obj, "inputLabel",
					    sra->nhlfe.label_in);
			json_object_string_add(json_obj, "outputLabel", label);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_add(json_obj, "nexthop", buf);
			json_object_array_add(json_link, json_obj);

		} else {
			vty_out(vty, "%18s  %8u  %9s  %21s  %9s  %15s\n", pref,
				sra->nhlfe.label_in, label, sid,
				itf ? itf->name : "-", buf);
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

DEFUN (show_isis_srdb,
       show_isis_srdb_cmd,
       "show isis database segment-routing [WORD] [json]",
       SHOW_STR
       PROTO_HELP
       "Database summary\n"
       "Show Segment Routing Data Base\n"
       "Advertising SR node ID (as SYS-ID address)\n"
       JSON_STR)
{
	int idx = 0;
	struct sr_node *srn;
	bool uj = use_json(argc, argv);
	bool alone = false;
	char *sr_id;
	json_object *json = NULL, *json_area = NULL;
	json_object *json_area_array = NULL, *json_node_array = NULL;
	struct isis_dynhn *dynhn;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	struct listnode *node;
	struct isis_area *area;

	if (isis->area_list->count == 0)
		return CMD_SUCCESS;

	sr_id = argv_find(argv, argc, "WORD", &idx) ? argv[idx]->arg : NULL;

	if (uj) {
		json = json_object_new_object();
		json_area_array = json_object_new_array();
		json_object_object_add(json, "Area", json_area_array);
	}

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		if (!IS_SR(area)) {
			vty_out(vty,
				"    Segment Routing is disabled on this area\n\n");
			continue;
		}

		memset(sysid, 0, ISIS_SYS_ID_LEN);
		if (sr_id) {
			if (sysid2buff(sysid, sr_id) == 0) {
				dynhn = dynhn_find_by_name(sr_id);
				if (dynhn == NULL) {
					if (memcmp(sr_id, cmd_hostname_get(),
						   strlen(sr_id)) == 0) {
						memcpy(sysid, isis->sysid,
						       ISIS_SYS_ID_LEN);
					} else {
						vty_out(vty,
							"Invalid system id %s\n",
							sr_id);
						return CMD_SUCCESS;
					}
				} else
					memcpy(sysid, dynhn->id,
					       ISIS_SYS_ID_LEN);
			}
			alone = true;
		}

		if (uj) {
			json_area = json_object_new_object();
			json_object_string_add(json_area, "name",
					       area->area_tag);
			json_node_array = json_object_new_array();
			json_object_string_add(
				json_area, "srdbID",
				print_sys_hostname(area->srdb.self->sysid));
			json_object_object_add(json_area, "srNodes",
					       json_node_array);
		} else {
			vty_out(vty,
				"\n\t\tISIS Segment Routing database for Node %s\n\n",
				print_sys_hostname(area->srdb.self->sysid));
		}

		if (alone) {
			/* Get the SR Node from the SRDB */
			srn = (struct sr_node *)hash_lookup(
				area->srdb.neighbors, (void *)&sysid);
			/* SR Node may be not part of this area */
			if (srn == NULL)
				continue;

			show_sr_node(vty, json_node_array, srn);
			if (uj) {
				json_object_array_add(json_area_array,
						      json_area);
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			}
			return CMD_SUCCESS;
		}

		/* No parameters have been provided, Iterate through all the
		 * SRDB */
		if (uj) {
			hash_iterate(area->srdb.neighbors,
				     (void (*)(struct hash_backet *,
					       void *))show_json_srdb,
				     (void *)json_node_array);
			json_object_array_add(json_area_array, json_area);
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
			json_object_free(json);
		} else {
			hash_iterate(area->srdb.neighbors,
				     (void (*)(struct hash_backet *,
					       void *))show_vty_srdb,
				     (void *)vty);
		}
	}
	return CMD_SUCCESS;
}

/* Install new CLI commands */
void isis_sr_register_vty(void)
{
	install_element(VIEW_NODE, &show_isis_srdb_cmd);

}
