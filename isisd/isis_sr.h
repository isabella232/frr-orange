/*
 * This is an implementation of Segment Routing for IS-IS
 * as per draft draft-ietf-isis-segment-routing-extensions-24
 *
 * Module name: Segment Routing header definitions
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

#ifndef _FRR_ISIS_SR_H
#define _FRR_ISIS_SR_H

#include "stream.h"

/*
 * Segment Routing information are transport through LSP:
 *  - Extended IS Reachability          TLV = 22   (RFC5305)
 *  - Extended IP Reachability          TLV = 135  (RFC5305)
 *
 *  and support following sub-TLV:
 *
 * Name					Value	TLVs
 * ____________________________________________________________
 * SID Label				 1
 *
 * Prefix Segment Identifier		 3	135 (235,236 and 237)
 *
 * Adjacency Segment Identifier		31	22 (23, 141, 222 and 223)
 * LAN Adjacency Segment Identifier	32	22 (23, 141, 222 and 223)
 *
 * Segment Routing Capability		 2	242
 * Segment Routing Algorithm		19	242
 * Node Maximum Stack Depth (MSD)	23	242
 *
 */
/* Default Route priority for ISIS Segment Routing */
#define ISIS_SR_PRIORITY_DEFAULT	10

/* Label range for Adj-SID attribution purpose. Start just right after SRGB */
#define ADJ_SID_MIN                     MPLS_DEFAULT_MAX_SRGB_LABEL
#define ADJ_SID_MAX                     (MPLS_DEFAULT_MAX_SRGB_LABEL + 1000)

#define ISIS_SR_DEFAULT_METRIC		1

/* Segment Routing TLVs as per draft-ietf-isis-segment-routing-extensions-24 */

/* Segment ID could be a Label (3 bytes) or an Index (4 bytes) */
#define SID_LABEL	3
#define SID_LABEL_SIZE(U) (U - 1)
#define SID_INDEX	4
#define SID_INDEX_SIZE(U) (U)

/*
 * subTLVs definition, serialization and de-serialization
 * are defined in isis_tlvs.[c,h]
 */

/*
 * Following section define structure for Segment Routing management
 */
#define IS_SR(a)	(a && a->srdb.enabled)

/* SID type to make difference between loopback interfaces and others */
enum sid_type { PREF_SID, ADJ_SID, LAN_ADJ_SID };

/* Structure aggregating all ISIS Segment Routing information for the node */
struct isis_sr_db {
	/* Status of Segment Routing: enable or disable */
	bool enabled;

	/* Ongoing Update following an ISIS SPF */
	bool update;
	struct thread *t_sr_update;

	/* IPv4 or IPv6 Segment Routing */
	uint8_t flags;

	/* FRR SR node */
	struct sr_node *self;

	/* List of neighbour SR nodes */
	struct hash *neighbors;

	/* Configured Prefix-SID mappings. */
	struct route_table *prefix4_sids;
	struct route_table *prefix6_sids;

	/* Local SR info announced in Router Capability TLV 242 */

	/* Algorithms supported by the node */
	uint8_t algo[SR_ALGORITHM_COUNT];
	/*
	 * Segment Routing Global Block lower & upper bound
	 * Only one range supported in this code
	 */
	uint32_t lower_bound;
	uint32_t upper_bound;

	/* Maximum SID Depth supported by the node */
	uint8_t msd;
};

/* Structure aggregating all received SR info from LSPs by node */
struct sr_node {

	/* System ID of the SR Node */
	uint8_t sysid[ISIS_SYS_ID_LEN];

	/* Router ID for prefix lookup */
	struct in_addr router_id;

	/* LSP ID used to identify the corresponding LSP */
	/* TODO: To be replace by a back pointer to the LSP ??? */
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];

	char is_type; /* level-1 level-1-2 or level-2-only */

	/* Router Capabilities */
	struct isis_router_cap cap;

	/* List of Prefix & IS advertise by this node */
	struct list *pref_sids;	/* For Prefix SID inc. Node SID*/
	struct list *adj_sids;	/* For Adjacency SID inc. LAN */

	/* Pointer to FRR SR-Node or NULL if it is not a neighbor */
	struct sr_node *neighbor;
};


/* Segment Routing - NHLFE info: support IPv4 Only */
struct sr_nhlfe {
	struct prefix_ipv4 prefv4;
	struct in_addr nexthop;
//	struct prefix prefix;
//	union g_addr nexthop;
	ifindex_t ifindex;
	mpls_label_t label_in;
	mpls_label_t label_out;
};

/* Structure aggregating all Segment Routing Adjacency information */
/* which are generally advertised by pair: primary + backup */
struct sr_adjacency {
	uint8_t id[7]; /* Extended IS Reachability Identifier */
	uint8_t neighbor[6]; /* Neighbor ID for Lan Adj SID */

	/* Flags to manage this Adjacency parameters. */
	uint8_t flags;

	/* Segment Routing ID */
	uint32_t sid;
	enum sid_type type;

	/* SR NHLFE for this Adjacency */
	struct sr_nhlfe nhlfe;

	/* Back pointer to SR Node which advertise this Adjacency */
	struct sr_node *srn;
};

/* Structure aggregating all Segment Routing Prefix information */
struct sr_prefix {
	uint8_t id[8]; /* LSP Identifier */

	/* Flags & Algo to manage this prefix parameters. */
	uint8_t flags;
	uint8_t algorithm;

	/* Segment Routing ID */
	uint32_t sid;
	enum sid_type type;

	/* SR NHLFE for this prefix */
	struct sr_nhlfe nhlfe;

	/* Back pointer to SR Node which advertise this Prefix */
	struct sr_node *srn;

	/*
	 * Pointer to SR Node which is the next hop for this Prefix
	 * or NULL if next hop is the destination of the prefix
	 */
	struct sr_node *nexthop;
};

/* Prototypes definition */
/* Segment Routing initialization functions */
extern void isis_sr_init(struct isis_area *area);
extern void isis_sr_start(struct isis_area *area);
extern void isis_sr_stop(struct isis_area *area);
extern void isis_sr_term(struct isis_area *area);
extern void isis_sr_srgb_update(struct isis_area *area);
extern void isis_sr_msd_update(struct isis_area *area);
extern struct sr_prefix *isis_sr_prefix_sid_add(struct isis_area *area,
						const struct prefix *prefix);
extern void isis_sr_prefix_sid_del(struct sr_prefix *srp);
extern struct sr_prefix *isis_sr_prefix_sid_find(const struct isis_area *area,
						 const struct prefix *prefix);

/* Segment Routing re-routing function */
extern void isis_sr_update_timer_add(struct isis_area *area);

#endif /* _FRR_ISIS_SR_H */
