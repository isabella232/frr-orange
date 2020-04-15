/*
 * Link State Database definition - ted.h
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2020 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_LINK_STATE_H_
#define _FRR_LINK_STATE_H_

#include "typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This file defines the model used to implement a Link State Database
 * suitable to be used by various protocol like RSVP-TE, BGP-LS, PCEP ...
 * This database is normally fulfill by the link state routing protocol,
 * commonly OSPF or ISIS, carrying Traffic Engineering information within
 * Link State Attributes. See, RFC3630.(OSPF-TE) and RFC5305 (ISIS-TE).
 *
 * At least, 3 types of Link State structure are defined:
 *  - Link State Node that groups all information related to a node
 *  - Link State Attributes that groups all information related to a link
 *  - Link State Prefix that groups all information related to a prefix
 *
 * These 3 types of structures are those handled by BGP-LS (see RFC7752).
 */

/* Type of Node */
enum node_type {
	STANDARD,	/* a P or PE node */
	ABR,		/* an Array Border Node */
	ASBR,		/* an Autonomous System Border Node */
	PSEUDO,		/* a Pseudo Node */
};

/* Link State Node */
struct ls_node {
	char *name;			/* Name of the Node. Could be null */
	struct in_addr router_id;	/* IPv4 Router ID */
	struct in6_addr router6_id;	/* IPv6 Router ID */
	enum node_type type;		/* Type of Node */
	struct {			/* Segment Routing Global Block */
		uint32_t lower_bound;		/* MPLS label lower bound */
		uint32_t range_size;		/* MPLS label range size */
	} srgb;
	/* AS number. May be different from the AS number of the IGP domain
	 * for ASBR type */
	uint32_t as_number;
};

/* Link State Attributes */
struct ls_attributes {
	uint32_t metric;		/* IGP standard metric */
	uint32_t te_metric;		/* Traffic Engineering metric */
	uint32_t admin_group;		/* Administrative Group */
	struct in_addr local;		/* Local IPv4 address */
	struct in_addr remote;		/* Remote IPv4 address */
	struct in6_addr local6;		/* Local IPv6 address */
	struct in6_addr remote6;	/* Remote IPv6 address */
	uint32_t local_id;		/* Local Identifier */
	uint32_t remote_id;		/* Remote Identifier */
	float max_bw;			/* Maximum Link Bandwidth */
	float max_rsv_bw;		/* Maximum Reservable Bandwidth */
	float unrsv_bw[8];		/* Unreserved BW per Class Type (8) */
	uint32_t remote_as;		/* Remote AS number */
	struct in_addr remote_addr;	/* Remote IPv4 address */
	struct in6_addr remote_addr6;	/* Remote IPv6 address */
	uint32_t delay;			/* Unidirectional average delay */
	uint32_t min_delay;		/* Unidirectional minimum delay */
	uint32_t max_delay;		/* Unidirectional maximum delay */
	uint32_t jitter;		/* Unidirectional delay variation */
	uint32_t pkt_loss;		/* Unidirectional packet loss */
	float ava_bw;			/* Available Bandwidth */
	float rsv_bw;			/* Reserved Bandwidth */
	float used_bw;			/* Utilized Bandwidth */
	uint32_t adj_sid;		/* Adjacency Segment Routing ID */
	uint32_t bkp_adj_sid;		/* Backup Adjacency Segment ID */
	struct list *srlgs;		/* List of Shared Risk Link Group */
};


/* Link State Prefix */
struct ls_prefix {
	struct ls_node *node;		/* Back pointer to the Node owner */
	struct prefix pref;		/* Prefix value itself */
	uint32_t sid;			/* Segment Routing ID */
	uint8_t algo;			/* Algorithm for Segment Routing */
};

/* Origin of the Link State information */
enum igp_origin {STATIC, OSPF, ISIS};

/**
 * In addition a Graph model is defined as an overlay on top of link state
 * database in order to ease Path Computation algorithm implementation.
 * Denoted G(V, E), a graph is composed by a list of Vertices (V) which
 * represents the network Node and a list of Edges (E) which represents node
 * Link. An additional list of prefixes (P) is also added.
 * A prefix (P) is also attached to the Vertex (V) which advertise it.
 *
 * Vertex (V) contains the list of outgoing Edges (E) that connect this Vertex
 * with its direct neighbors and the list of incoming Edges (E) that connect
 * the direct neighbors to this Vertex. Indeed, the Edge (E) is unidirectional,
 * thus, it is necessary to add 2 Edges to model a bidirectional relation
 * between 2 Vertices.
 *
 * Edge (E) contains the source and destination Vertex that this Edge
 * is connecting.
 *
 * A unique Key is used to identify both Vertices and Edges within the Graph.
 * An easy way to build this key is to used the IP address: i.e. loopback
 * address for Vertices and link IP address for Edges.
 *
 *      --------------     ---------------------------    --------------
 *      | Connected  |---->| Connected Edge Va to Vb |--->| Connected  |
 *  --->|  Vertex    |     ---------------------------    |  Vertex    |---->
 *      |            |                                    |            |
 *      | - Key (Va) |                                    | - Key (Vb) |
 *  <---| - Vertex   |     ---------------------------    | - Vertex   |<----
 *      |            |<----| Connected Edge Vb to Va |<---|            |
 *      --------------     ---------------------------    --------------
 *
 */

/* RB tree structure to store Graph elements */
PREDECL_RBTREE_UNIQ(vertices)
PREDECL_RBTREE_UNIQ(edges)
PREDECL_RBTREE_UNIQ(prefixes)

/* Vertex structure */
struct vertex {
	struct vertices_item entry;	/* Entry in RB Tree */
	uint64_t key;			/* Unique Key identifier */
	struct ls_node node;		/* Link State Node */
	struct list *incoming_edges;	/* List of incoming Link State links */
	struct list *outgoing_edges;	/* List of outgoing Link State links */
	struct list *prefixes;		/* List of advertised prefix */
};

/* Edge structure */
struct edge {
	struct edges_item entry;	/* Entry in RB tree */
	uint64_t key;			/* Unique Key identifier */
	char *name;			/* Name of the Edge. Could be null */
	struct ls_attributes attributes;	/* Link State attributes */
	struct vertex *source;		/* pointer to the source Vertex */
	struct vertex *destination; 	/* pointer to the destination Vertex */
};

/* Prefix structure */
struct gr_prefix {
	struct prefixes_item entry;	/* Entry in RB tree */
	struct ls_prefix prefix;	/* Link State Prefix */
};

/* Graph Structure */
struct graph {
	uint32_t key;		/* Unique identifier */
	char *name;		/* Name of this graph. Could be null */
	enum igp_origin origin;	/* Routing protocol which fulfill this graph */
	uint32_t as_number;	/* AS number of the modeled network */
	struct vertices_head *vertices;		/* List of Vertices */
	struct edges_head *edges;		/* List of Edges */
	struct prefixes_head *prefixes;		/* List of Prefixes */
};

#ifdef __cplusplus
}
#endif

#endif /* _FRR_LINK_STATE_H_ */
