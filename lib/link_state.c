/*
 * Link State Database - link_state.c
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

#include "prefix.h"
#include "link_state.h"

/**
 * Declaration of Vertices, Edges and Prefixes RB Trees
 */
DEFINE_MTYPE_STATIC(LIB, LS_DB, "Link State Database")

static inline int key_cmp(const uint64_t key1, const uint64_t key2)
{
    return (key1 - key2);
}
DECLARE_RBTREE_UNIQ(vertices, struct vertex, entry, key_cmp)
DECLARE_RBTREE_UNIQ(edges, struct edge, entry, key_cmp)

static inline int pref_cmp(const struct ls_prefix *a, const struct ls_prefix *b)
{
    return prefix_cmp(&a->pref, &b->pref);
}
DECLARE_RBTREE_UNIQ(prefixes, struct gr_prefix, entry, pref_cmp)

/* Vertices management functions */
struct vertex *link_state_vertex_add(struct graph *gr,
				     const struct ls_node *lsn)
{
	struct vertex *new;

	new = XCALLOC(MTYPE_LS_DB, sizeof(*new));
	new->node = lsn;
	/* Key is the IPv4 Router ID or lower 64 bits of IPv6 Router ID */
	if (!IPV4_NET0(lsn->router_id))
		new->key = ((uint64_t)lsn->router_id) & 0xffffffff;
	if (!IN6_IS_ADDR_UNSPECIFIED(lsn->router6_id))
		new->key = (uint64_t)(lsn->router6_id & 0xffffffffffffffff);

	/* Remove Vertex if key is not set */
	if (new->key == 0) {
		XFREE(MTYPE_LS_DB, new);
		return NULL;
	}

	vertices_add(&gr->vertices, new);

	return new;
}

void link_state_vertex_del(struct graph *gr, struct vertex *node)
{
    vertices_del(&gr->vertices, node);
    XFREE(MTYPE_LS_DB, node);
}

struct vertex *link_state_vertex_find(struct graph *gr, const uint64_t key)
{
    struct vertex node = {};

    node.key = key;
    return vertices_find(&gr->vertices, &node);
}

