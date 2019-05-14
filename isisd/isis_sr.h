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

/* macros and constants for segment routing */
#define SET_RANGE_SIZE_MASK             0xffffff00
#define GET_RANGE_SIZE_MASK             0x00ffffff
#define SET_LABEL_MASK                  0xffffff00
#define GET_LABEL_MASK                  0x00ffffff
#define GET_INDEX(index)		ntohl(index)
#define GET_LABEL(label)		(ntohl(label) >> 8) & GET_LABEL_MASK
#define GET_RANGE_SIZE(srgb)                                                 \
	(((srgb.range[0] << 16) | (srgb.range[1] << 8) | (srgb.range[2]))    \
	 & GET_RANGE_SIZE_MASK)
#define GET_RANGE_BASE(srgb)                                                 \
	(SUBTLV_LEN(srgb.lower) == 3 ? GET_LABEL(srgb.lower.value)           \
				     : GET_INDEX(srgb.lower.value))

#define SET_LABEL(label)		((label << 8) & SET_LABEL_MASK)
#define SET_INDEX(index)		htonl(index)

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

/* SID/Label Sub TLV - section 2.3 */
#define SUBTLV_SID_LABEL		1
#define SUBTLV_SID_LABEL_SIZE		6
struct subtlv_sid_label {
	/* Length is 3 (20 rightmost bits MPLS label) or 4 (32 bits SID) */
	struct subtlv_header header;
	uint32_t value;
} __attribute__((__packed__));

/*
 * Following section defines Segment Routing sub-TLVs (tag, length, value)
 * structures, used in Router Information TLV-242 defined in RFC7981.
 */

/* SID/Label Range TLV - section 3.1 */
#define SR_SUBTLV_SID_LABEL_RANGE	2
#define SR_SUBTLV_SID_LABEL_RANGE_SIZE	12
struct sr_subtlv_sid_label_range {
	struct subtlv_header header;
#define SR_SUBTLV_SRGB_FLAG_I		0x80
#define SR_SUBTLV_SRGB_FLAG_V		0x40
	uint8_t flags; /* Bit 0: I = IPv4, Bit 1: V = IPv6 */
/* Only 24 upper most bits are significant */
#define SID_RANGE_LABEL_LENGTH	3
	uint8_t range[SID_RANGE_LABEL_LENGTH];
	/* A SID/Label sub-TLV will follow. */
	struct subtlv_sid_label lower;
} __attribute__((__packed__));

#define IS_SR_IPV4(srgb)	(srgb.flags & SR_SUBTLV_SRGB_FLAG_I)
#define IS_SR_IPV6(srgb)	(srgb.flags & SR_SUBTLV_SRGB_FLAG_V)

/* SR-Algorithm TLV - section 3.2 */
#define SR_SUBTLV_ALGORITHM		19
#define SR_SUBTLV_ALGORITHM_SIZE	4
struct sr_subtlv_sr_algorithm {
	struct subtlv_header header;
#define SR_ALGORITHM_SPF         0
#define SR_ALGORITHM_STRICT_SPF  1
#define SR_ALGORITHM_UNSET       255
#define ALGORITHM_COUNT          2
	/* Only 4 algorithms supported in this code */
	uint8_t value[ALGORITHM_COUNT];
} __attribute__((__packed__));

/* Node/MSD TLV as per RFC 8491 - Node MSD only */
#define SR_SUBTLV_NODE_MSD		23
#define SR_SUBTLV_NODE_MSD_SIZE		4
struct sr_subtlv_node_msd {
	struct subtlv_header header;
	uint8_t subtype; /* always = 1 (Base MPLS Imposition MSD */
	uint8_t value;
} __attribute__((__packed__));

/* SR Local block and SRMS are not yet supported */

/*
 * Following section defines Segment Routing sub-TLVs (tag, length, value)
 * structures, used in Extended IPv4 Reachability TLV-135 and
 * Extended IS Reachabillity TLV-22 defined in RFC5305.
 */

/* Prefix SID sub-TLVs flags */
#define EXT_SUBTLV_PREFIX_SID_RFLG	0x80
#define EXT_SUBTLV_PREFIX_SID_NFLG	0x40
#define EXT_SUBTLV_PREFIX_SID_PFLG	0x20
#define EXT_SUBTLV_PREFIX_SID_EFLG	0x10
#define EXT_SUBTLV_PREFIX_SID_VFLG	0x08
#define EXT_SUBTLV_PREFIX_SID_LFLG	0x04

/* Prefix SID Sub-TLV - section 2.1 */
#define EXT_SUBTLV_PREFIX_SID		3
#define EXT_SUBTLV_PREFIX_SID_SIZE	8
struct ext_subtlv_prefix_sid {
	struct subtlv_header header;
	uint8_t flags;
	uint8_t algorithm;
	uint32_t value;
} __attribute__((__packed__));

/*
 * Following section define structure used to manage Segment Routing
 * information and TLVs / SubTLVs
 */

/* Structure aggregating SRGB info retrieved from an lsa */
struct sr_srgb {
	uint32_t range_size;
	uint32_t lower_bound;
};

/* SID type to make difference between loopback interfaces and others */
enum sid_type { PREF_SID, ADJ_SID, LAN_ADJ_SID };

/* Structure aggregating all ISIS Segment Routing information for the node */
struct isis_sr_db {
	/* Status of Segment Routing: enable or disable */
	bool enabled;

	/* Ongoing Update following an ISIS SPF */
	bool update;

	/* Flooding Scope: Level-1 or Level-2 */
	uint8_t scope;

	/* FRR SR node */
	struct sr_node *self;

	/* List of neighbour SR nodes */
	struct hash *neighbors;

	/* List of SR prefix */
	struct route_table *prefix;

	/* Local SR info announced in Router Capability TLV 242 */

	/* Algorithms supported by the node */
	uint8_t algo[ALGORITHM_COUNT];
	/*
	 * Segment Routing Global Block i.e. label range
	 * Only one range supported in this code
	 */
	struct sr_srgb srgb;
	/* Maximum SID Depth supported by the node */
	uint8_t msd;
};

/* Structure aggregating all received SR info from LSAs by node */
struct sr_node {
	struct in_addr router_id; /* used to identify sender of LSP */

	uint8_t algo[ALGORITHM_COUNT]; /* Algorithms supported by the node */
	/* Segment Routing Global Block i.e. label range */
	struct sr_srgb srgb;
	uint8_t msd; /* Maximum SID Depth */

	/* List of Prefix & Link advertise by this node */
	struct list *ext_prefix; /* For Node SID */
	struct list *ext_link;   /* For Adj and LAN SID */

	/* Pointer to FRR SR-Node or NULL if it is not a neighbor */
	struct sr_node *neighbor;
};


/* Segment Routing - NHLFE info: support IPv4 Only */
struct sr_nhlfe {
	struct prefix_ipv4 prefv4;
	struct in_addr nexthop;
	ifindex_t ifindex;
	mpls_label_t label_in;
	mpls_label_t label_out;
};

/* Structure aggregating all Segment Routing Link information */
/* Link are generally advertised by pair: primary + backup */
struct sr_link {
	uint8_t id[7]; /* Extended Reachability Identifier */

	/* Flags to manage this link parameters. */
	uint8_t flags[2];

	/* Segment Routing ID */
	uint32_t sid[2];
	enum sid_type type;

	/* SR NHLFE for this link */
	struct sr_nhlfe nhlfe[2];

	/* Back pointer to SR Node which advertise this Link */
	struct sr_node *srn;
};

/* Structure aggregating all Segment Routing Prefix information */
struct sr_prefix {
	struct prefix_ipv4 prefix;

	/* Flags to manage this prefix parameters. */
	uint8_t flags;

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

/* Structure aggregating all Segment Routing information for a circuit */
struct sr_extended {
	uint8_t type; /* Extended IS (22) or Extended IP (135) */

	/* Reference pointer to a Zebra-interface. */
	struct interface *ifp;

	/* Area info in which this SR link belongs to. */
	struct isis_area *area;

	/* Flags to manage this link parameters. */
	uint32_t flags;

	/* SID type: Node, Adjacency or LAN Adjacency */
	enum sid_type stype;

	/* extended link/prefix TLV information */
	struct ext_tlv_prefix prefix;
	struct ext_subtlv_prefix_sid node_sid;
	struct ext_tlv_link link;
	struct ext_subtlv_adj_sid adj_sid[2];
	struct ext_subtlv_lan_adj_sid lan_sid[2];
};

/* Prototypes definition */
struct sr_extended *sr_circuit_new(void);
#ifdef SR_FUNC
/* Segment Routing initialization functions */
extern int isis_sr_init(void);
extern void isis_sr_term(void);
extern void isis_sr_finish(void);
/* Segment Routing LSA update & delete functions */
extern void isis_sr_ri_lsa_update(struct isis_lsa *lsa);
extern void isis_sr_ri_lsa_delete(struct isis_lsa *lsa);
extern void isis_sr_ext_link_lsa_update(struct isis_lsa *lsa);
extern void isis_sr_ext_link_lsa_delete(struct isis_lsa *lsa);
extern void isis_sr_ext_prefix_lsa_update(struct isis_lsa *lsa);
extern void isis_sr_ext_prefix_lsa_delete(struct isis_lsa *lsa);
/* Segment Routing configuration functions */
extern uint32_t get_ext_link_label_value(void);
extern void isis_sr_config_write_router(struct vty *vty);
extern void isis_sr_update_prefix(struct interface *ifp, struct prefix *p);
/* Segment Routing re-routing function */
extern void isis_sr_update_timer_add(struct isis *isis);
#endif
#endif /* _FRR_ISIS_SR_H */
