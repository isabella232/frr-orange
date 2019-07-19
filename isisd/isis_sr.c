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
#include "sbuf.h"
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
static void sr_circuit_update_sid_adjs(struct isis_circuit *circuit,
				       struct prefix *nexthop);
static void sr_circuit_unset_sid_adjs(struct isis_adjacency *adj);
static int sr_if_new_hook(struct interface *ifp);
static int sr_update_adj_hook(struct isis_adjacency *adj);
static void update_in_nhlfe(struct sr_node *self, struct sr_prefix *srp);

static void isis_sr_register_vty(void);

const char *sr_status2str[] = {"Idle", "Added", "Updated", "Unchanged"};

/*
 * Segment Routing Data Base functions
 */

/* Declaration of SR Node RB Tree */
static inline int sr_node_cmp(const struct sr_node *srn1,
			      const struct sr_node *srn2)
{
	return memcmp(srn1->sysid, srn2->sysid, ISIS_SYS_ID_LEN);
}

RB_GENERATE(srdb_node_head, sr_node, entry, sr_node_cmp)

/* Declaration of SR Prefix RB Tree */
static inline int sr_prefix_cmp(const struct sr_prefix *srp1,
				const struct sr_prefix *srp2)
{
	if (srp1->prefix.family < srp2->prefix.family)
		return -1;
	if (srp1->prefix.family > srp2->prefix.family)
		return 1;

	if (srp1->prefix.prefixlen < srp2->prefix.prefixlen)
		return -1;
	if (srp1->prefix.prefixlen > srp2->prefix.prefixlen)
		return 1;

	switch (srp1->prefix.family) {
	case AF_INET:
		if (ntohl(srp1->prefix.u.prefix4.s_addr)
		    < ntohl(srp2->prefix.u.prefix4.s_addr))
			return -1;
		if (ntohl(srp1->prefix.u.prefix4.s_addr)
		    > ntohl(srp2->prefix.u.prefix4.s_addr))
			return 1;
		break;
	case AF_INET6:
		if (memcmp(&srp1->prefix.u.prefix6, &srp2->prefix.u.prefix6,
			   sizeof(struct in6_addr))
		    < 0)
			return -1;
		if (memcmp(&srp1->prefix.u.prefix6, &srp2->prefix.u.prefix6,
			   sizeof(struct in6_addr))
		    > 0)
			return 1;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown prefix family",
			 __func__);
		exit(1);
	}

	return 0;
}

RB_GENERATE(srdb_prefix_head, sr_prefix, entry, sr_prefix_cmp)

/* Functions to remove an SR Link */
static void del_sr_adj(void *val)
{
	struct sr_adjacency *sra = (struct sr_adjacency *)val;

	if (sra->adj_sid)
		isis_tlvs_del_adj_sid(sra->adj->circuit->ext, sra->adj_sid);
	if (sra->lan_sid)
		isis_tlvs_del_lan_adj_sid(sra->adj->circuit->ext, sra->lan_sid);
	del_sid_nhlfe(sra->nhlfe, sra->prefix);
	XFREE(MTYPE_ISIS_SR, sra);
}

/* Functions to remove an SR Prefix */
static void del_sr_pref(void *val)
{
	struct sr_prefix *srp = (struct sr_prefix *)val;
	struct listnode *node;
	struct sr_nhlfe *nhlfe;

	for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, node, nhlfe))
		del_sid_nhlfe(*nhlfe, srp->prefix);
	list_delete(&srp->nhlfes);
	XFREE(MTYPE_ISIS_SR, srp);
}

/* Get Label for (LAN-)Adj-SID */
static uint32_t sr_get_local_label(void)
{
	return isis_zebra_request_dynamic_label();
}

/* Functions to create and remove an SR Prefix */
static struct sr_prefix *sr_prefix_new(struct sr_node *srn,
				       const struct prefix *prefix)
{
	struct sr_prefix *srp;

	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));
	srp->nhlfes = list_new();
	memcpy(&srp->prefix, prefix, sizeof(struct prefix));

	/* Set back pointer and add this prefix to self SR-Node and SR-DB */
	srp->srn = srn;
	RB_INSERT(srdb_prefix_head, &srn->area->srdb.prefix_sids, srp);
	listnode_add(srn->pref_sids, srp);

	return srp;
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

	sr_debug(" |- Remove SR Node %s", print_sys_hostname(srn->sysid));
	/* Clean Extended Link */
	list_delete(&srn->adj_sids);

	/* Clean Prefix List */
	list_delete(&srn->pref_sids);

	/* Remove the SR Node from the SRDB */
	if (srn->area != NULL)
		RB_REMOVE(srdb_node_head, &srn->area->srdb.sr_nodes, srn);
	XFREE(MTYPE_ISIS_SR, srn);
}

/* Get SR Node self */
static struct sr_node *get_self_by_area(struct isis_area * area)
{
	struct sr_node *self = NULL;

	if (IS_SR(area))
		self = area->srdb.self;

	return self;
}

static struct sr_node *get_self_by_node(struct sr_node *srn)
{
	return srn ? get_self_by_area(srn->area) : NULL;
}

/*
 * Functions to management Segment Routing on a per ISIS Area
 *  - isis_sr_start() call when segment routing is activate
 *  - isis_sr_stop() call when segment routing is deactivate
 *  - isis_sr_init() call when isis start
 *  - isis_sr_term() call when isis stop
 */
void isis_sr_start(struct isis_area *area)
{
	struct sr_node *srn;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct listnode *cnode, *anode;
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("SR (%s): Starting Segment Routing", __func__);

	if (!srdb->srgb_lm) {
		flog_err(
			EC_ISIS_SR_LABEL_MANAGER,
			"SR(%s): Can't start SR. Label ranges are not reserved",
			__func__);
		return;
	}

	/* Initialize self SR Node */
	srn = sr_node_new(area->isis->sysid);

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
	RB_INSERT(srdb_node_head, &area->srdb.sr_nodes, srn);

	/* Initialize Adjacency for all circuit belongs to this area */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2;
			     level++) {
				struct list *adjdb =
					circuit->u.bc.adjdb[level - 1];
				for (ALL_LIST_ELEMENTS_RO(adjdb, anode, adj))
					sr_update_adj_hook(adj);
			}
		} else if (circuit->circ_type == CIRCUIT_T_P2P) {
			sr_update_adj_hook(circuit->u.p2p.neighbor);
		}
	}

	/* Enable SR and regenerate LSP */
	area->srdb.enabled = true;

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_stop(struct isis_area *area)
{
	struct sr_node *srn;
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("SR (%s): Stopping Segment Routing", __func__);

	/* Release Labels range of SRGB */
	if (srdb->srgb_lm)
		isis_zebra_release_label_range(srdb->lower_bound,
					       srdb->upper_bound);

	/* Stop SR */
	srdb->enabled = false;
	srdb->self = NULL;

	/*
	 * Remove all SR Nodes from the RB Tree. Prefix and Link SID will
	 * be remove though list_delete() call. See sr_node_del()
	 */
	while (!RB_EMPTY(srdb_node_head, &srdb->sr_nodes)) {
		srn = RB_ROOT(srdb_node_head, &srdb->sr_nodes);
		sr_node_del(srn);
	}

	sr_debug("SR (%s): Segment Routing stopped!\n", __func__);

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_init(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;
	uint32_t size;

	memset(srdb, 0, sizeof(struct isis_sr_db));
	srdb->enabled = false;
	srdb->self = NULL;

	/* Initialize SRGB, Algorithms and MSD TLVs */
	/* Only Algorithm SPF is supported */
	srdb->algo[0] = SR_ALGORITHM_SPF;
	for (int i = 1; i < SR_ALGORITHM_COUNT; i++)
		srdb->algo[i] = SR_ALGORITHM_UNSET;

	/* Initialize RB Tree for neighbor SR nodes */
	RB_INIT(srdb_node_head, &srdb->sr_nodes);

	/* Default values */
	srdb->msd = 0;
#ifndef FABRICD
	srdb->lower_bound = yang_get_default_uint32(
		"/frr-isisd:isis/instance/segment-routing/srgb/lower-bound");
	srdb->upper_bound = yang_get_default_uint32(
		"/frr-isisd:isis/instance/segment-routing/srgb/upper-bound");
#endif /* ifndef FABRICD */

	/* Reserve Labels Range for SRGB */
	size = srdb->upper_bound - srdb->lower_bound + 1;
	if (isis_zebra_request_label_range(srdb->lower_bound, size) == 0)
		srdb->srgb_lm = true;

	/* Register Various event hook */
	hook_register_prio(isis_lsp_event_hook, 100, srdb_lsp_event);
	hook_register(isis_if_new_hook, sr_if_new_hook);
	hook_register(isis_adj_state_change_hook, sr_update_adj_hook);

	/* Install show command */
	isis_sr_register_vty();
}

void isis_sr_term(void)
{
	/* Unregister various event hook */
	hook_unregister(isis_lsp_event_hook, srdb_lsp_event);
	hook_unregister(isis_if_new_hook, sr_if_new_hook);
	hook_unregister(isis_adj_state_change_hook, sr_update_adj_hook);
}

/*
 * Segment Routing configuration functions call by isis_northbound.c
 *  - isis_sr_srgb_update() call when SRGB is set or modified
 *  - isis_sr_msd_update() call when MSD is set or modified
 */
void isis_sr_srgb_update(struct isis_area *area)
{
	struct sr_node *self;
	struct sr_prefix *srp;
	struct isis_sr_db *srdb = &area->srdb;
	uint32_t size;

	/* Sanity check */
	self = get_self_by_area(area);
	if (self == NULL)
		return;

	/* Release old Label Range */
	if (srdb->srgb_lm)
		isis_zebra_release_label_range(
			self->cap.srgb.lower_bound,
			self->cap.srgb.lower_bound + self->cap.srgb.range_size
				- 1);

	/* Reserve new range */
	size = srdb->upper_bound - srdb->lower_bound + 1;
	if (isis_zebra_request_label_range(srdb->lower_bound, size) == 0) {
		/* Set SID/Label range SRGB */
		srdb->srgb_lm = true;
		self->cap.srgb.lower_bound = srdb->lower_bound;
		self->cap.srgb.range_size = size;

		sr_debug("SR(%s): Update SRGB with new range %d-%d",
			__func__, srdb->lower_bound, srdb->upper_bound);
		/* Update NHLFE entries */
		RB_FOREACH (srp, srdb_prefix_head, &srdb->prefix_sids)
			update_in_nhlfe(self, srp);
	} else {
		flog_err(EC_ISIS_SR_LABEL_MANAGER,
			 "SR(%s): Error getting MPLS Label Range. Disable SR!",
			 __func__);
		isis_sr_stop(area);
	}

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_msd_update(struct isis_area *area)
{
	struct sr_node *self;
	/* Set this router MSD */
	self = get_self_by_area(area);
	if (self != NULL)
		self->cap.msd = area->srdb.msd;

	lsp_regenerate_schedule(area, area->is_type, 0);
}

/*
 * Functions to install MPLS entry corresponding to Prefix a Adjacency SID
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

/* Send MPLS Label entry to Zebra for installation or deletion */
static int sr_zebra_send_mpls_labels(int cmd, struct sr_nhlfe nhlfe,
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

	sr_debug("    |-  %s MPLS entry %u/%u for %s via %u",
		 cmd == ZEBRA_MPLS_LABELS_ADD ? "Add" : "Delete",
		 nhlfe.label_in, nhlfe.label_out,
		 prefix2str(&p, buf, PREFIX2STR_BUFFER),
		 nhlfe.ifindex);

	return zclient_send_message(zclient);
}

/* Request zebra to install/remove FEC in FIB */
static int sr_zebra_send_mpls_ftn(int cmd, struct sr_nhlfe nhlfe,
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
	if ((nhlfe.label_in != 0) && (nhlfe.label_out != MPLS_INVALID_LABEL)) {
		sr_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_ADD, nhlfe, p);
		if (nhlfe.label_out > MPLS_LABEL_RESERVED_MAX)
			sr_zebra_send_mpls_ftn(ZEBRA_ROUTE_ADD, nhlfe, p);
	}
}

/* Remove NHLFE entry for SID */
static inline void del_sid_nhlfe(struct sr_nhlfe nhlfe, struct prefix p)
{
	if ((nhlfe.label_in != 0)  && (nhlfe.label_out != MPLS_INVALID_LABEL)) {
		sr_zebra_send_mpls_labels(ZEBRA_MPLS_LABELS_DELETE, nhlfe, p);
		if (nhlfe.label_out > MPLS_LABEL_RESERVED_MAX)
			sr_zebra_send_mpls_ftn(ZEBRA_ROUTE_DELETE, nhlfe, p);
	}
}

/*
 * Update NHLFE entry for SID
 * Make before break is not always possible if input label is the same,
 * Linux Kernel refuse to add a second entry so we must first remove the
 * old MPLS entry before adding the new one
 * TODO: Add new ZAPI for Make Before Break if Linux Kernel support it.
 */
static inline void update_sid_nhlfe(struct sr_nhlfe n1, struct sr_nhlfe n2,
				    struct prefix p)
{
	del_sid_nhlfe(n1, p);
	add_sid_nhlfe(n2, p);
}

/* Compute MPLS label */
static void update_mpls_labels(struct sr_nhlfe *nhlfe, struct sr_prefix *srp)
{
	struct sr_node *self;
	struct sr_nhlfe old;
	char label[16];

	self = get_self_by_node(srp->srn);
	if ((nhlfe->srnext == NULL) && (srp->srn != self)) {
		nhlfe->state = UNACTIVE_NH;
		del_sid_nhlfe(*nhlfe, srp->prefix);
		return;
	}

	nhlfe->state = ACTIVE_NH;

	/* Backup NHLFE */
	memcpy(&old, nhlfe, sizeof(struct sr_nhlfe));

	/* Compute Input Label with self SRGB */
	if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_VALUE))
		nhlfe->label_in = srp->sid.value;
	else
		nhlfe->label_in = index2label(srp->sid.value, self->cap.srgb);

	/*
	 * and Output Label with
	 *  - Implicit Null label if it is the self node and request NO-PHP,
	 *    MPLS_INVALIDE_LABEL otherwise
	 *  - Implicit / Explicit Null label if next hop is the destination and
	 *    request NO_PHP / EXPLICIT NULL label
	 *  - Value label or SID in Next hop SR Node SRGB for other cases
	 */

	if (srp->srn == self) {
		if CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP)
			nhlfe->label_out = MPLS_LABEL_IMPLICIT_NULL;
		else
			nhlfe->label_out = MPLS_INVALID_LABEL;
	} else if (nhlfe->srnext == srp->srn) {
		if (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP))
			nhlfe->label_out = MPLS_LABEL_IMPLICIT_NULL;
		if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_EXPLICIT_NULL)) {
			if (srp->prefix.family == AF_INET)
				nhlfe->label_out =
					MPLS_LABEL_IPV4_EXPLICIT_NULL;
			else
				nhlfe->label_out =
					MPLS_LABEL_IPV6_EXPLICIT_NULL;
		}
	} else {
		if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_VALUE))

			nhlfe->label_out = srp->sid.value;
		else
			nhlfe->label_out = index2label(srp->sid.value,
						       nhlfe->srnext->cap.srgb);
	}

	switch (nhlfe->label_out) {
	case MPLS_LABEL_IMPLICIT_NULL:
		sprintf(label, "pop");
		break;
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		sprintf(label, "null");
		break;
	case MPLS_INVALID_LABEL:
		sprintf(label, "no-label");
		break;
	default:
		sprintf(label, "%u", nhlfe->label_out);
		break;
	}
	sr_debug("    |-  Computed new labels in: %u out: %s",
		 nhlfe->label_in, label);

	/* Check if it is an update or a new NHLFE */
	if ((old.label_in != nhlfe->label_in)
	    || (old.label_out != nhlfe->label_out))
		update_sid_nhlfe(old, *nhlfe, srp->prefix);
	else
		add_sid_nhlfe(*nhlfe, srp->prefix);
}

/* Functions to manage ADJ-SID:
 *  - isis_sr_circuit_update_sid_adjs() call when isis adjacency is up
 *    to update ADJ-SID for the given circuit
 *  - isis_sr_circuit_unset_sid_adjs() call when SR is stop to remove ADJ-SID
 *  - isis_sr_if_new_hook() hook trigger to complete Prefix SID for the
 *    Loopback interface
 *  - isis_sr_update_adj_hook() call when isis adjacency is up to create
 *    ADJ-SID and configure corresponding MPLS entries
 */

static struct sr_adjacency *sr_adj_add(struct isis_circuit *circuit,
				       struct isis_adjacency *isis_adj,
				       struct prefix *nexthop, bool backup)
{
	struct sr_adjacency *sra;
	struct isis_adj_sid *adj;
	struct prefix_ipv4 *ipv4;
	struct prefix_ipv6 *ipv6;

	/* Create new Adjacency subTLVs */
	adj = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_adj_sid));
	adj->family = nexthop->family;
	adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
		      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
	if (backup)
		SET_FLAG(adj->flags, EXT_SUBTLV_LINK_ADJ_SID_BFLG);
	adj->weight = 0;
	adj->sid = sr_get_local_label();
	sr_debug(
		"  |- Set %s Adj-SID %d for %s",
		backup ? "Backup" : "Primary",
		adj->sid, rawlspid_print(isis_adj->sysid));
	isis_tlvs_add_adj_sid(circuit->ext, adj);

	/* Create corresponding SR Adjacency */
	sra = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_adjacency));
	sra->adj_sid = adj;
	sra->adj = isis_adj;

	/* Set NHLFE ifindex and nexthop */
	sra->nhlfe.ifindex = circuit->interface->ifindex;
	if ((nexthop->family == AF_INET) && listcount(circuit->ip_addrs)) {
		ipv4 = (struct prefix_ipv4 *)listgetdata(
			(struct listnode *)listhead(circuit->ip_addrs));
		PREFIX_COPY_IPV4(&sra->prefix, ipv4);
		IPV4_ADDR_COPY(&sra->nhlfe.nexthop, &nexthop->u.prefix4);
	}
	if ((nexthop->family == AF_INET6)
	    && listcount(circuit->ipv6_non_link)) {
		ipv6 = (struct prefix_ipv6 *)listgetdata(
			(struct listnode *)listhead(circuit->ipv6_non_link));
		PREFIX_COPY_IPV6(&sra->prefix, ipv6);
		IPV6_ADDR_COPY(&sra->nhlfe.nexthop6, &nexthop->u.prefix6);
	}
	/* Set Input & Output Label */
	sra->nhlfe.label_in = sra->adj_sid->sid;
	sra->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;

	/* Finish by configuring MPLS entry */
	add_sid_nhlfe(sra->nhlfe, sra->prefix);

	return sra;
}

static struct sr_adjacency *sr_lan_adj_add(struct isis_circuit *circuit,
					   struct isis_adjacency *isis_adj,
					   struct prefix *nexthop, bool backup)
{
	struct sr_adjacency *sra;
	struct isis_lan_adj_sid *lan;
	struct prefix_ipv4 *ipv4;
	struct prefix_ipv6 *ipv6;

	/* Create new LAN Adjacency subTLVs */
	lan = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_lan_adj_sid));
	lan->family = nexthop->family;
	lan->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
		      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
	if (backup)
		SET_FLAG(lan->flags, EXT_SUBTLV_LINK_ADJ_SID_BFLG);
	lan->weight = 0;
	memcpy(lan->neighbor_id, isis_adj->sysid, ISIS_SYS_ID_LEN);
	lan->sid = sr_get_local_label();
	sr_debug(
		"  |- Set %s LAN-Adj-SID %d for %s",
		backup ? "Backup" : "Primary",
		lan->sid, rawlspid_print(isis_adj->sysid));
	isis_tlvs_add_lan_adj_sid(circuit->ext, lan);

	/* Create corresponding SR Adjacency */
	sra = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_adjacency));
	sra->lan_sid = lan;
	sra->adj = isis_adj;

	/* Set NHLFE ifindex and nexthop */
	sra->nhlfe.ifindex = circuit->interface->ifindex;
	if ((nexthop->family == AF_INET) && listcount(circuit->ip_addrs)) {
		ipv4 = (struct prefix_ipv4 *)listgetdata(
			(struct listnode *)listhead(circuit->ip_addrs));
		PREFIX_COPY_IPV4(&sra->prefix, ipv4);
		IPV4_ADDR_COPY(&sra->nhlfe.nexthop, &nexthop->u.prefix4);
	}
	if ((nexthop->family == AF_INET6)
	    && listcount(circuit->ipv6_non_link)) {
		ipv6 = (struct prefix_ipv6 *)listgetdata(
			(struct listnode *)listhead(circuit->ipv6_non_link));
		PREFIX_COPY_IPV6(&sra->prefix, ipv6);
		IPV6_ADDR_COPY(&sra->nhlfe.nexthop6, &nexthop->u.prefix6);
	}
	/* Set Input & Output Label */
	sra->nhlfe.label_in = sra->lan_sid->sid;
	sra->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;

	/* Finish by configuring MPLS entry */
	add_sid_nhlfe(sra->nhlfe, sra->prefix);

	return sra;
}

static void sr_circuit_update_sid_adjs(struct isis_circuit *circuit,
				       struct prefix *nexthop)
{
	struct sr_node *self;
	struct sr_adjacency *sra;
	struct listnode *node;
	struct list *adjdb;
	struct isis_adjacency *ad;
	char buf[PREFIX2STR_BUFFER];

	self = get_self_by_area(circuit->area);

	inet_ntop(nexthop->family, &nexthop->u.prefix, buf, PREFIX2STR_BUFFER);
	sr_debug("SR(%s): Update Adj-SID for interface %s with nexthop %s",
		 __func__, circuit->interface->name, buf);

	if (circuit->ext == NULL) {
		circuit->ext = isis_alloc_ext_subtlvs();
		sr_debug("  |- Allocated new Extended subTLVs for interface %s",
			 circuit->interface->name);
	}

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		/* Set LAN Adj SID for each neighbors */
		adjdb = circuit->u.bc.adjdb[circuit->is_type - 1];
		for (ALL_LIST_ELEMENTS_RO(adjdb, node, ad)) {
			/* Install Primary SID ... */
			sra = sr_lan_adj_add(circuit, ad, nexthop, false);
			sra->srn = self;
			listnode_add(self->adj_sids, sra);
			/* ... then Backup SID */
			sra = sr_lan_adj_add(circuit, ad, nexthop, true);
			sra->srn = self;
			listnode_add(self->adj_sids, sra);
		}
		SET_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID);
		break;
	case CIRCUIT_T_P2P:
		/* Install Primary SID ... */
		sra = sr_adj_add(circuit, circuit->u.p2p.neighbor, nexthop,
				 false);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
		/* ... then Backup SID */
		sra = sr_adj_add(circuit, circuit->u.p2p.neighbor, nexthop,
				 true);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
		break;
	default:
		break;
	}
}

static void sr_circuit_unset_sid_adjs(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit;
	struct sr_node *self;
	struct listnode *node, *nnode;
	struct sr_adjacency *sra;

	/* Sanity Check */
	if (adj == NULL || adj->circuit == NULL)
		return;

	circuit = adj->circuit;
	if (!IS_SR(circuit->area) || (circuit->ext == NULL))
		return;

	sr_debug("  |-  Unset Adjacency SID for interface %s",
		 circuit->interface->name);

	/* remove corresponding SR Adjacency */
	self = get_self_by_area(circuit->area);
	for (ALL_LIST_ELEMENTS(self->adj_sids, node, nnode, sra)) {
		if (sra->adj == adj) {
			list_delete_node(self->adj_sids, node);
			del_sr_adj((void *)sra);
		}
	}
}

static int sr_update_adj_hook(struct isis_adjacency *adj)
{

	struct prefix nexthop;

	/* Sanity Check */
	if (adj == NULL || adj->circuit == NULL)
		return 1;

	/* Skip loopback */
	if (if_is_loopback(adj->circuit->interface))
		return 0;

	/* Check is SR is enable */
	if (!IS_SR(adj->circuit->area))
		return 0;

	switch (adj->adj_state) {
	case ISIS_ADJ_UP:
		/* IPv4 first */
		if (adj->ipv4_address_count > 0) {
			nexthop.family = AF_INET;
			IPV4_ADDR_COPY(&nexthop.u.prefix4,
				       &adj->ipv4_addresses[0]);
			sr_circuit_update_sid_adjs(adj->circuit, &nexthop);
		}

		/* and IPv6 */
		if (adj->ipv6_address_count > 0) {
			nexthop.family = AF_INET6;
			IPV6_ADDR_COPY(&nexthop.u.prefix6,
				       &adj->ipv6_addresses[0]);
			sr_circuit_update_sid_adjs(adj->circuit, &nexthop);
		}
		break;
	case ISIS_ADJ_DOWN:
		sr_circuit_unset_sid_adjs(adj);
		break;
	default:
		break;
	}

	return 0;
}

static int sr_if_new_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;
	struct sr_nhlfe *nhlfe;
	char buf[PREFIX2STR_BUFFER];

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return 0;

	area = circuit->area;
	if (!IS_SR(area))
		return 0;

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

		srp = isis_sr_prefix_find(area, connected->address);
		if (srp) {
			inet_ntop(srp->prefix.family, &srp->prefix.u.prefix,
				  buf, PREFIX2STR_BUFFER);

			sr_debug("  |- Set Node SID to prefix %s/%d ifindex %d",
				 buf, srp->prefix.prefixlen, ifp->ifindex);
			SET_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NODE);
			sr_debug("  |- New flags: 0x%x", srp->sid.flags);
			/* Set MPLS entry */
			if (listcount(srp->nhlfes) == 0) {
				nhlfe = XCALLOC(MTYPE_ISIS_SR,
						sizeof(struct sr_nhlfe));
				listnode_add(srp->nhlfes, nhlfe);
			} else {
				nhlfe = (struct sr_nhlfe *)listgetdata(
					(struct listnode *)listhead(
						srp->nhlfes));
			}
			nhlfe->ifindex = ifp->ifindex;
			update_mpls_labels(nhlfe, srp);
		}
	}

	return 0;
}

/*
 * Functions that manage local Prefix SID
 *  - isis_sr_prefix_add() call by isis_northbound.c when a prefix SID is
 *    configured
 *  - isis_sr_prefix_commit() to finalyse the prefix configuration
 *  - isis_sr_prefix_del() to remove a local prefix SID
 *  - isis_sr_prefix_find() to get SR prefix from a given IPv4 or IPv6 prefix
 */
struct sr_prefix *isis_sr_prefix_add(struct isis_area *area,
				     const struct prefix *prefix)
{
	struct sr_prefix *srp;
	struct sr_node *self;
	char buf[PREFIX2STR_BUFFER];

	self = get_self_by_area(area);
	if (self == NULL)
		return NULL;

	srp = sr_prefix_new(self, prefix);

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
		  PREFIX2STR_BUFFER);
	sr_debug("SR(%s): Added Prefix-SID %s/%d to self SR-Node %s", __func__,
		 buf, srp->prefix.prefixlen,
		 print_sys_hostname(self->sysid));

	return srp;
}

void isis_sr_prefix_commit(struct sr_prefix *srp)
{
	struct interface *ifp;
	struct sr_nhlfe *nhlfe;

	/* Set flags & NHLFE if interface is Loopback */
	ifp = if_lookup_prefix(&srp->prefix, VRF_DEFAULT);
	if (ifp && if_is_loopback(ifp)) {
		sr_debug("  |- Add this prefix as Node-SID to Loopback");
		SET_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NODE);
		sr_debug("  |- New flags: 0x%x", srp->sid.flags);
		if (listcount(srp->nhlfes) == 0) {
			nhlfe = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_nhlfe));
			listnode_add(srp->nhlfes, nhlfe);
		} else {
			nhlfe = (struct sr_nhlfe *)listgetdata(
				(struct listnode *)listhead(srp->nhlfes));
		}
		nhlfe->ifindex = ifp->ifindex;
		update_mpls_labels(nhlfe, srp);
	}
}

static void sr_prefix_del(struct sr_node *srn, struct sr_prefix *srp)
{
	struct isis_area *area;
	struct listnode *node;
	struct sr_nhlfe *nhlfe;

	/* Remove SRP from SR Node & SR-DB */
	listnode_delete(srn->pref_sids, srp);
	for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, node, nhlfe))
		del_sid_nhlfe(*nhlfe, srp->prefix);
	list_delete(&srp->nhlfes);
	area = srn->area;
	RB_REMOVE(srdb_prefix_head, &area->srdb.prefix_sids, srp);
	XFREE(MTYPE_ISIS_SR, srp);
}

void isis_sr_prefix_del(struct sr_prefix *srp)
{
	char buf[PREFIX2STR_BUFFER];

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
		  PREFIX2STR_BUFFER);
	sr_debug("SR(%s): Remove Prefix-SID %s/%d to self SR-Node %s", __func__,
		 buf, srp->prefix.prefixlen,
		 print_sys_hostname(srp->srn->sysid));

	sr_prefix_del(srp->srn, srp);
}

struct sr_prefix *isis_sr_prefix_find(const struct isis_area *area,
				      const struct prefix *prefix)
{
	struct sr_prefix srp = {};

	if (!IS_SR(area))
		return NULL;

	prefix_copy(&srp.prefix, prefix);
	return RB_FIND(srdb_prefix_head, &area->srdb.prefix_sids, &srp);
}

/*
 * Following functions are used to manipulate the
 * Next Hop Label Forwarding entry (NHLFE)
 */

/* Merge nexthop IPv4 list and NHLFE for a given SR Prefix */
static void nhlfe_merge_nexthop(struct isis_area *area, struct sr_prefix *srp,
				struct list *nexthop)
{
	struct listnode *node, *snode;
	struct isis_nexthop *nh;
	struct sr_nhlfe *nhlfe;
	struct sr_node key = {};
	struct sr_node *srnext;
	bool found;

	/* Compare both list, mark unchanged if found or create new one
	 * old value will be remove later */
	for (ALL_LIST_ELEMENTS_RO(nexthop, node, nh)) {
		found = false;
		for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, snode, nhlfe)) {
			if (IPV4_ADDR_SAME(&nhlfe->nexthop, &nh->ip)) {
				nhlfe->state = UNCHANGED_NH;
				found = true;
				continue;
			}
		}
		if (!found) {
			nhlfe = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_nhlfe));
			IPV4_ADDR_COPY(&nhlfe->nexthop, &nh->ip);
			nhlfe->ifindex = nh->ifindex;
			nhlfe->state = NEW_NH;
			memcpy(key.sysid, nh->adj->sysid, ISIS_SYS_ID_LEN);
			srnext = RB_FIND(srdb_node_head, &area->srdb.sr_nodes,
					 &key);
			nhlfe->srnext = srnext;
			srnext->neighbor = get_self_by_area(area);
			listnode_add(srp->nhlfes, nhlfe);
		}
	}
}

/* Merge nexthop IPv6 list and NHLFE for a given SR Prefix */
static void nhlfe_merge_nexthop6(struct isis_area *area, struct sr_prefix *srp,
				 struct list *nexthop)
{
	struct listnode *node, *snode;
	struct isis_nexthop6 *nh6;
	struct sr_nhlfe *nhlfe;
	struct sr_node key = {};
	struct sr_node *srnext;
	bool found;

	/* Compare both list, mark unchanged if found or create new one
	 * old value will be remove later */
	for (ALL_LIST_ELEMENTS_RO(nexthop, node, nh6)) {
		found = false;
		for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, snode, nhlfe)) {
			if (IPV6_ADDR_SAME(&nhlfe->nexthop6, &nh6->ip6)) {
				nhlfe->state = UNCHANGED_NH;
				found = true;
				continue;
			}
		}
		if (!found) {
			nhlfe = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_nhlfe));
			IPV6_ADDR_COPY(&nhlfe->nexthop6, &nh6->ip6);
			nhlfe->ifindex = nh6->ifindex;
			nhlfe->state = NEW_NH;
			memcpy(key.sysid, nh6->adj->sysid, ISIS_SYS_ID_LEN);
			srnext = RB_FIND(srdb_node_head, &area->srdb.sr_nodes,
					 &key);
			nhlfe->srnext = srnext;
			srnext->neighbor = get_self_by_area(area);
			listnode_add(srp->nhlfes, nhlfe);
		}
	}
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

/* Compute NHLFE entry for Extended Prefix */
static int update_prefix_nhlfe(struct isis_area *area, struct sr_prefix *srp)
{
	struct list *nh_list;
	struct listnode *node, *nnode;
	struct sr_nhlfe *nhlfe;
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

	/* Merge nexthop list to NHLFE list */
	switch (srp->prefix.family) {
	case AF_INET:
		nhlfe_merge_nexthop(area, srp, nh_list);
		break;
	case AF_INET6:
		nhlfe_merge_nexthop6(area, srp, nh_list);
		break;
	default:
		return rc;
	}

	/* Process NHLFE list */
	for (ALL_LIST_ELEMENTS(srp->nhlfes, node, nnode, nhlfe)) {
		switch(nhlfe->state) {
		case UNCHANGED_NH:
			/* Update NHLFE if SID info have been modified */
			if (srp->status == MODIFIED_SID)
				update_mpls_labels(nhlfe, srp);
			break;
		case NEW_NH:
			/* Add new NHLFE */
			update_mpls_labels(nhlfe, srp);
			break;
		case IDLE_NH:
			/* Remove NHLFE */
			del_sid_nhlfe(*nhlfe, srp->prefix);
			list_delete_node(srp->nhlfes, node);
			XFREE(MTYPE_ISIS_SR, nhlfe);
			break;
		default:
			break;
		}
	}

	rc = 1;
	return rc;
}

/*
 * Functions to manipulate Segment Routing Adjacency & Prefix structures
 */

/*
 * When change the FRR Self SRGB, update the NHLFE Input Label
 * for all Extended Prefix with SID index
 */
static void update_in_nhlfe(struct sr_node *self, struct sr_prefix *srp)
{
	struct sr_nhlfe old;
	struct sr_nhlfe *nhlfe;
	struct listnode *node;

	/* Process Self SR-Node only if NO-PHP is requested */
	if ((srp->srn == self)
	    && !CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP))
		return;

	/* Process only SID Index */
	if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_VALUE))
		return;

	/* OK. Update all NHLFE with new incoming label */
	for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, node, nhlfe)) {
		memcpy(&old, nhlfe, sizeof(struct sr_nhlfe));
		/* Update Input Label */
		nhlfe->label_in = index2label(srp->sid.value, self->cap.srgb);
		/* Update MPLS LFIB */
		update_sid_nhlfe(old, *nhlfe, srp->prefix);
	}
}

/*
 * When SRGB has changed, update NHLFE Output Label for all Extended Prefix
 * with SID index which use the given SR-Node as nexthop
 */
static void update_out_nhlfe(struct sr_prefix *srp, struct sr_node *srnext)
{
	struct sr_nhlfe old;
	struct sr_nhlfe *nhlfe;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, node, nhlfe)) {
		/* Process only SID Index for next hop without PHP and equal
		 * to SR Node */
		if ((nhlfe->srnext != srnext)
		    || (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP)))
			continue;

		memcpy(&old, nhlfe, sizeof(struct sr_nhlfe));
		nhlfe->label_out =
			index2label(srp->sid.value, srnext->cap.srgb);
		update_sid_nhlfe(old, *nhlfe, srp->prefix);
	}
}

/*
 * Following functions are call when new LSPs are received
 *  - Router Information: sr_ri_update() & sr_ri_delete()
 *  - Extended IS Reachability: sr_ext_is_update() & sr_ext_is_delete()
 *  - Extended IP Reachability: sr_prefix_update() & sr_prefix_delete()
 */
/* Update Segment Routing from Router Information LSA */
static struct sr_node *sr_cap_update(struct isis_area *area, uint8_t *lspid,
				     struct isis_router_cap *cap)
{
	struct sr_node *srn;
	struct sr_node key = {};

	/* Get SR Node in SRDB from LSP ID, create a new one if not exist */
	memcpy(&key.sysid, lspid, ISIS_SYS_ID_LEN);
	srn = RB_FIND(srdb_node_head, &area->srdb.sr_nodes, &key);
	if (srn == NULL) {
		srn = sr_node_new(key.sysid);
		/* Sanity check in case of */
		if (srn == NULL) {
			flog_err(EC_ISIS_SR_NODE_CREATE,
				 "SR (%s): Abort! can't create SR node in SRDB",
				 __func__);
			return NULL;
		}
		RB_INSERT(srdb_node_head, &area->srdb.sr_nodes, srn);
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
		/* Copy SRGB */
		srn->cap.srgb.range_size = cap->srgb.range_size;
		srn->cap.srgb.lower_bound = cap->srgb.lower_bound;
		return srn;
	}

	/* Check if SRGB has changed */
	if ((srn->cap.srgb.range_size != cap->srgb.range_size)
	    || (srn->cap.srgb.lower_bound != cap->srgb.lower_bound)) {
		/* Update SRGB */
		srn->cap.srgb.range_size = cap->srgb.range_size;
		srn->cap.srgb.lower_bound = cap->srgb.lower_bound;
		/* Update NHLFE if it is a direct neighbor of self SR node */
		if (srn->neighbor == area->srdb.self) {
			struct sr_prefix *srp;
			RB_FOREACH (srp, srdb_prefix_head,
				    &area->srdb.prefix_sids)
				update_out_nhlfe(srp, srn);
		}
	}

	return srn;
}

/* Update Segment Routing prefix SID from Extended IP Reachability TLV */
static void sr_prefix_update(struct sr_node *srn, union prefixconstptr prefix,
			     struct isis_prefix_sid *psid)
{
	struct sr_prefix *srp;
	struct listnode *node;
	bool found = false;
	char buf[PREFIX2STR_BUFFER];

	/* Process only Global Prefix SID */
	if (CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_LOCAL))
		return;

	sr_debug("  |- Process Extended IP LSP for Node %s",
		 print_sys_hostname(srn->sysid));

	/* Search for existing Segment Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp))
		if (prefix_same(prefix.p, &srp->prefix)) {
			found = true;
			break;
		}

	if (!found) {
		/* Create new Prefix SID information */
		srp = sr_prefix_new(srn, prefix.p);
		srp->status = NEW_SID;
		srp->sid = *psid;
	} else {
		/* Update Prefix SID information if there is new values */
		if ((srp->sid.value != psid->value)
		    || (srp->sid.flags != psid->flags)
		    || (srp->sid.algorithm != psid->algorithm)) {
			srp->sid = *psid;
			srp->status = MODIFIED_SID;
		} else {
			srp->status = UNCHANGED_SID;
		}
	}

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
		  PREFIX2STR_BUFFER);
	sr_debug("  |-  %s Prefix SID %s/%d for SR-Node %s",
		 sr_status2str[srp->status], buf, srp->prefix.prefixlen,
		 print_sys_hostname(srn->sysid));
}

/*
 * Following functions are used to update SR-DB once an LSP is received
 */
/* Commit all Prefix SID for the Given SR Node */
static void srdb_commit_prefix(struct sr_node *srn)
{
	struct listnode *node, *nnode;
	struct sr_prefix *srp;

	for (ALL_LIST_ELEMENTS(srn->pref_sids, node, nnode, srp)) {
		switch (srp->status) {
		case IDLE_SID:
			sr_prefix_del(srn, srp);
			break;
		case MODIFIED_SID:
		case NEW_SID:
			/* Update the SR Prefix & NHLFE */
			update_prefix_nhlfe(srn->area, srp);
			break;
		case UNCHANGED_SID:
		default:
			break;
		}
		/* Reset status for next update */
		srp->status = IDLE_SID;
	}
}

static int srdb_update_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct sr_node *srn;
	struct isis_extended_ip_reach *ipr;
	struct isis_ipv6_reach *ipr6;
	struct isis_prefix_sid *psid;
	struct isis_item_list *items;

	/* First Process Router Capability for remote LSP */
	sr_debug(" |- Process Segment Routing Capability for %s",
		 print_sys_hostname(lsp->hdr.lsp_id));

	if (!lsp->own_lsp)
		srn = sr_cap_update(lsp->area, lsp->hdr.lsp_id,
				    lsp->tlvs->router_cap);
	else
		srn = get_self_by_area(lsp->area);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't get SR node in SRDB",
			 __func__);
		return rc;
	}

	/* Then, Extended IP Reachability */
	for (ipr = (struct isis_extended_ip_reach *)
			   lsp->tlvs->extended_ip_reach.head;
	     ipr != NULL; ipr = ipr->next) {
		/* Check that there is a Prefix SID */
		if (ipr->subtlvs && ipr->subtlvs->prefix_sids.count != 0) {
			psid = (struct isis_prefix_sid *)
				       ipr->subtlvs->prefix_sids.head;
			sr_prefix_update(srn, &ipr->prefix, psid);
		}
	}

	/* And, Multi Topology Reachable IPv6 Prefixes */
	items = isis_lookup_mt_items(&lsp->tlvs->mt_ipv6_reach,
				     ISIS_MT_IPV6_UNICAST);
	if (items != NULL) {
		for (ipr6 = (struct isis_ipv6_reach *)items->head; ipr6;
		     ipr6 = ipr6->next) {
			/* Check that there is a Prefix SID */
			if (ipr6->subtlvs
			    && ipr6->subtlvs->prefix_sids.count != 0) {
				psid = (struct isis_prefix_sid *)
					       ipr6->subtlvs->prefix_sids.head;
				sr_prefix_update(srn, &ipr6->prefix, psid);
			}
		}
	}

	/* Finally, commit new Prefix SID configuration */
	srdb_commit_prefix(srn);

	rc = 0;
	return rc;
}

static int srdb_del_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct sr_node *srn;
	struct sr_node key = {};

	/* Self Node is managed by CLI or Northbound interface */
	if (lsp->own_lsp)
		return 0;

	/* Get SR Node in SRDB from LSP ID */
	memcpy(&key.sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
	srn = RB_FIND(srdb_node_head, &lsp->area->srdb.sr_nodes, &key);

	/* Node may not be in SRDB if it has never announced SR capabilities */
	if (srn == NULL) {
		sr_debug("SR (%s): No entry in SRDB for SR Node %s",
			 __func__, print_sys_hostname(key.sysid));
		return rc;
	}

	/* OK. Let's proceed to SR node removal */
	sr_debug(" |- Remove SR node %s from LSP %s",
		 print_sys_hostname(srn->sysid),
		 rawlspid_print(lsp->hdr.lsp_id));

	sr_node_del(srn);

	rc = 0;
	return rc;
}

/* Function call by the different LSP Hook to parse LSP */
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event)
{
	int rc = 0;

	/* Sanity Check */
	if (lsp == NULL || lsp->tlvs == NULL)
		return rc;

	/* Check that SR is initialized and enabled */
	if(!IS_SR(lsp->area))
		return rc;

	/* Skip LSP pseudo or fragment that not carry SR information */
	if (LSP_PSEUDO_ID(lsp->hdr.lsp_id) != 0
	    || LSP_FRAGMENT(lsp->hdr.lsp_id) != 0) {
		sr_debug("SR (%s): Skip Pseudo or fragment LSP %s", __func__,
			 rawlspid_print(lsp->hdr.lsp_id));
		return rc;
	}

	sr_debug("SR (%s): Process LSP id %s", __func__,
		 rawlspid_print(lsp->hdr.lsp_id));

	switch(event) {
	case LSP_ADD:
	case LSP_UPD:
		/* Check that there is a valid SR info in this LSP */
		if ((lsp->tlvs->router_cap != NULL)
		    && (lsp->tlvs->router_cap->srgb.range_size != 0)
		    && (lsp->tlvs->router_cap->srgb.lower_bound
			> MPLS_LABEL_RESERVED_MAX))
			rc = srdb_update_lsp(lsp);
		else
			rc = srdb_del_lsp(lsp);
		break;
	case LSP_DEL:
		rc = srdb_del_lsp(lsp);
		break;
	case LSP_INC:
		/* Self SR-Node is process directly */
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

static int sr_update_schedule(struct thread *t)
{

	struct isis_area *area;
	struct sr_node *srn;
	struct listnode *node;
	struct sr_prefix *srp;
	struct timeval start_time, stop_time;

	area = THREAD_ARG(t);
	area->srdb.t_sr_update = NULL;

	if (!IS_SR(area) || !area->srdb.update)
		return 0;

	monotime(&start_time);

	sr_debug("SR (%s): Start SPF update", __func__);

	RB_FOREACH(srn, srdb_node_head, &area->srdb.sr_nodes) {
		/* Skip Self SR Node */
		if (IS_SR_SELF(srn, area))
			continue;

		/* Update Extended Prefix */
		for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp))
			update_prefix_nhlfe(area, srp);
	}

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

	if (!IS_SR(area))
		return;

	/* Check if an update is not already engaged */
	if (area->srdb.update)
		return;

	area->srdb.update = true;

	thread_add_timer(master, sr_update_schedule, area,
			 ISIS_SR_UPDATE_INTERVAL, &area->srdb.t_sr_update);
}

void isis_sr_prefix_update(struct isis_area *area, struct prefix *prefix)
{
	struct sr_prefix *srp;
	char buf[PREFIX2STR_BUFFER];
	struct timeval start_time, stop_time;

	sr_debug("SR(%s): Update Prefix %s/%d after SPF update", __func__,
		 inet_ntop(prefix->family, &prefix->u.prefix, buf,
			   PREFIX2STR_BUFFER),
		 prefix->prefixlen);

	monotime(&start_time);

	srp = isis_sr_prefix_find(area, prefix);
	if (!srp)
		return;

	/* Compute the new NHLFE */
	update_prefix_nhlfe(area, srp);

	monotime(&stop_time);
	sr_debug("SR (%s): SPF Processing Time(usecs): %lld\n", __func__,
		 (stop_time.tv_sec - start_time.tv_sec) * 1000000LL
			 + (stop_time.tv_usec - start_time.tv_usec));
}

/*
 * --------------------------------------
 * Followings are vty command functions.
 * --------------------------------------
 */
static void show_sr_prefix(struct sbuf *sbuf, struct json_object *json,
			   struct sr_prefix *srp)
{
	struct listnode *node;
	struct sr_nhlfe *nhlfe;
	struct interface *itf;
	char pref[19];
	char sid[22];
	char label[8];
	int indent = 0;
	char buf[PREFIX2STR_BUFFER];
	json_object *json_prefix = NULL, *json_obj;
	json_object *json_nh = NULL;

	inet_ntop(srp->prefix.family, &srp->prefix.u.prefix, buf,
		  PREFIX2STR_BUFFER);
	snprintf(pref, 19, "%s/%u", buf, srp->prefix.prefixlen);
	snprintf(sid, 22, "SR Pfx (idx %u)", srp->sid.value);
	if (json) {
		json_prefix = json_object_new_object();
		json_object_string_add(json_prefix, "prefix", pref);
		json_object_int_add(json_prefix, "sid", srp->sid.value);
		json_nh = json_object_new_array();
		json_object_object_add(json_prefix, "nhlfe", json_nh);
	} else
		sbuf_push(sbuf, 0, "%18s  %21s  ", pref, sid);

	for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, node, nhlfe)) {
		if (nhlfe->label_out == MPLS_LABEL_IMPLICIT_NULL)
			sprintf(label, "pop");
		else
			sprintf(label, "%u", nhlfe->label_out);
		itf = if_lookup_by_index(nhlfe->ifindex, VRF_DEFAULT);
		if (srp->prefix.family == AF_INET)
			inet_ntop(AF_INET, &nhlfe->nexthop, buf,
				  PREFIX2STR_BUFFER);
		else
			inet_ntop(AF_INET6, &nhlfe->nexthop6, buf,
				  PREFIX2STR_BUFFER);
		if (json) {
			json_obj = json_object_new_object();
			json_object_int_add(json_obj, "inputLabel",
					    nhlfe->label_in);
			json_object_string_add(json_obj, "outputLabel", label);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_add(json_obj, "nexthop", buf);
			json_object_array_add(json_nh, json_obj);
		} else {
			sbuf_push(sbuf, indent, "%8u  %9s  %9s  %15s\n",
				  nhlfe->label_in, label,
				  itf ? itf->name : "-", buf);
			indent = 43;
		}
	}
	if (json)
		json_object_array_add(json, json_prefix);
}

static void show_sr_node(struct vty *vty, struct json_object *json,
			 struct sr_node *srn)
{

	struct listnode *node;
	struct sr_adjacency *sra;
	struct sr_prefix *srp;
	struct interface *itf;
	struct sbuf sbuf;
	char pref[19];
	char sid[22];
	char label[8];
	char buf[PREFIX2STR_BUFFER];
	int value;
	json_object *json_node = NULL, *json_algo, *json_obj;
	json_object *json_prefix = NULL, *json_link = NULL;

	/* Sanity Check */
	if (srn == NULL)
		return;

	sbuf_init(&sbuf, NULL, 0);

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
		sbuf_push(&sbuf, 0, "SR-Node: %s",
			  print_sys_hostname(srn->sysid));
		sbuf_push(&sbuf, 0, "\tSRGB (Size/Label): %u/%u",
			  srn->cap.srgb.range_size, srn->cap.srgb.lower_bound);
		sbuf_push(&sbuf, 0, "\tAlgorithm(s): %s",
			srn->cap.algo[0] == SR_ALGORITHM_SPF ? "SPF" : "S-SPF");
		for (int i = 1; i < SR_ALGORITHM_COUNT; i++) {
			if (srn->cap.algo[i] == SR_ALGORITHM_UNSET)
				continue;
			sbuf_push(&sbuf, 0, "/%s",
				srn->cap.algo[i] == SR_ALGORITHM_SPF ? "SPF"
								 : "S-SPF");
		}
		if (srn->cap.msd != 0)
			sbuf_push(&sbuf, 0, "\tMSD: %u", srn->cap.msd);
	}

	if (!json) {
		sbuf_push(&sbuf, 0,
			"\n\n    Prefix or Link       Node or Adj. SID  "
			"Label In  Label Out  Interface          Nexthop\n");
		sbuf_push(&sbuf, 0,
			"------------------  ---------------------  --------  "
			"---------  ---------  ---------------\n");
	}
	for (ALL_LIST_ELEMENTS_RO(srn->pref_sids, node, srp)) {
		if (json) {
			if (!json_prefix) {
				json_prefix = json_object_new_array();
				json_object_object_add(json_node,
						       "extendedPrefix",
						       json_prefix);
			}
			show_sr_prefix(NULL, json_prefix, srp);
		} else
			show_sr_prefix(&sbuf, NULL, srp);
	}

	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, sra)) {
		inet_ntop(sra->prefix.family, &sra->prefix.u.prefix, buf,
			  PREFIX2STR_BUFFER);
		snprintf(pref, 19, "%s/%u", buf, sra->prefix.prefixlen);
		if (sra->adj_sid)
			value = sra->adj_sid->sid;
		else if (sra->lan_sid)
			value = sra->lan_sid->sid;
		else
			value = 0;
		snprintf(sid, 22, "SR Adj. (lbl %u)", value);
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
			json_object_int_add(json_obj, "sid", value);
			json_object_int_add(json_obj, "inputLabel",
					    sra->nhlfe.label_in);
			json_object_string_add(json_obj, "outputLabel", label);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_add(json_obj, "nexthop", buf);
			json_object_array_add(json_link, json_obj);

		} else {
			sbuf_push(&sbuf, 0, "%18s  %21s  %8u  %9s  %9s  %15s\n",
				  pref, sid, sra->nhlfe.label_in, label,
				  itf ? itf->name : "-", buf);
		}
	}
	if (json)
		json_object_array_add(json, json_node);
	else
		vty_out(vty, "%s\n", sbuf_buf(&sbuf));

	sbuf_free(&sbuf);
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
			struct sr_node key = {};
			memcpy(&key.sysid, sysid, ISIS_SYS_ID_LEN);
			srn = RB_FIND(srdb_node_head, &area->srdb.sr_nodes,
				      &key);

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
			RB_FOREACH(srn, srdb_node_head, &area->srdb.sr_nodes)
				show_sr_node(NULL, json, srn);
			json_object_array_add(json_area_array, json_area);
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
			json_object_free(json);
		} else {
			RB_FOREACH(srn, srdb_node_head, &area->srdb.sr_nodes)
				show_sr_node(vty, NULL, srn);
		}
	}
	return CMD_SUCCESS;
}

/* Install new CLI commands */
void isis_sr_register_vty(void)
{
	install_element(VIEW_NODE, &show_isis_srdb_cmd);

}
