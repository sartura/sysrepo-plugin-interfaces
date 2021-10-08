#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/limits.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <net/if.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include "routing.h"
#include "rib.h"
#include "rib/list.h"
#include "rib/description_pair.h"
#include "route/list.h"
#include "route/list_hash.h"
#include "control_plane_protocol.h"
#include "control_plane_protocol/list.h"
#include "utils/memory.h"

// dir for storing data used by the plugin - usually build directory of the plugin
#define ROUTING_PLUGIN_DATA_DIR "ROUTING_PLUGIN_DATA_DIR"

// other #define's used in the plugin
#define ROUTING_PROTOS_MAP_FNAME "protos_map"
#define ROUTING_RIBS_DESCRIPTIONS_MAP_FNAME "ribs_map"
#define ROUTING_RIBS_COUNT 256
#define ROUTING_PROTOS_COUNT 256

#define BASE_YANG_MODEL "ietf-routing"

// base of all - routing container
#define ROUTING_CONTAINER_YANG_PATH "/" BASE_YANG_MODEL ":routing"

// router ID
#define ROUTING_ROUTER_ID_YANG_PATH ROUTING_CONTAINER_YANG_PATH "/router-id"

// interfaces container
#define ROUTING_INTERFACES_CONTAINER_YANG_PATH ROUTING_CONTAINER_YANG_PATH "/interfaces"
#define ROUTING_INTERFACE_LEAF_LIST_YANG_PATH ROUTING_INTERFACES_CONTAINER_YANG_PATH "/interface"

// control plane protocols container
#define ROUTING_CONTROL_PLANE_PROTOCOLS_CONTAINER_YANG_PATH ROUTING_CONTAINER_YANG_PATH "/control-plane-protocols"
#define ROUTING_CONTROL_PLANE_PROTOCOL_LIST_YANG_PATH ROUTING_CONTROL_PLANE_PROTOCOLS_CONTAINER_YANG_PATH "/control-plane-protocol"

// ribs
#define ROUTING_RIBS_CONTAINER_YANG_PATH ROUTING_CONTAINER_YANG_PATH "/ribs"
#define ROUTING_RIB_LIST_YANG_PATH ROUTING_RIBS_CONTAINER_YANG_PATH "/rib"
#define ROUTING_RIB_LIST_ACTIVE_ROUTE_RPC_PATH ROUTING_RIB_LIST_YANG_PATH "/active-route"

// sysrepocfg
#define SYSREPOCFG_EMPTY_CHECK_COMMAND "sysrepocfg -X -d running -m " BASE_YANG_MODEL

// module change
static int routing_module_change_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

// module change helpers - changing/deleting values
static int set_control_plane_protocol_value(char *xpath, const char *value);
static int delete_control_plane_protocol_value(const char *xpath);
static int set_rib_value(const char *node_xpath, const char *node_value);
static int delete_rib_value(const char *node_xpath);

// getting xpath from the node
static char *routing_xpath_get(const struct lyd_node *node);

// control-plane-protocol list module changes
static int routing_control_plane_protocol_set_description(const char *type, const char *name, const char *description);

// rib list module changes
static int routing_rib_set_address_family(const char *name, const char *address_family);
static int routing_rib_set_description(const char *name, const char *description);

// operational callbacks
static int routing_state_data_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

// rpc callbacks
static int routing_rpc_active_route_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data);

// initial loading into the datastore
static int routing_load_data(sr_session_ctx_t *session);
static int routing_load_ribs(sr_session_ctx_t *session, struct lyd_node *routing_container_node);
static int routing_collect_ribs(struct nl_cache *routes_cache, struct rib_list *ribs);
static int routing_collect_routes(struct nl_cache *routes_cache, struct nl_cache *link_cache, struct rib_list *ribs);
static int routing_load_control_plane_protocols(sr_session_ctx_t *session, struct lyd_node *routing_container_node);
static int routing_build_rib_descriptions(struct rib_list *ribs);
static inline int routing_is_rib_known(int table);
static int routing_build_protos_map(struct control_plane_protocol map[ROUTING_PROTOS_COUNT]);
static inline int routing_is_proto_type_known(int type);
static bool routing_running_datastore_is_empty(void);

static struct route_list_hash *ipv4_static_routes = NULL;
static struct route_list_hash *ipv6_static_routes = NULL;

static int static_routes_init(struct route_list_hash **ipv4_routes, struct route_list_hash **ipv6_routes);
static void foreach_nexthop(struct rtnl_nexthop *nh, void *arg);
static int update_ipv4_static_routes(struct route_list_hash *ipv4_static_routes);
static int update_ipv6_static_routes(struct route_list_hash *ipv6_static_routes);

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;

	// sysrepo
	sr_session_ctx_t *startup_session = NULL;
	sr_conn_ctx_t *connection = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	*private_data = NULL;

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error: %d -> %s", error, sr_strerror(error));
	}

	*private_data = startup_session;

	error = static_routes_init(&ipv4_static_routes, &ipv6_static_routes);
	if (error) {
		SRP_LOG_ERR("static_routes_init error");
		goto error_out;
	}

	if (routing_running_datastore_is_empty()) {
		SRP_LOG_INF("running datasore is empty -> loading data");
		error = routing_load_data(session);
		if (error) {
			SRP_LOG_ERR("error loading initial data into the datastore... exiting");
			goto error_out;
		}
		error = sr_copy_config(startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	SRP_LOG_INF("subscribing to module change");

	// control-plane-protocol list module changes
	error = sr_module_change_subscribe(session, BASE_YANG_MODEL, "/" BASE_YANG_MODEL ":*//.", routing_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INF("subscribing to interfaces operational data");

	// interface leaf-list oper data
	error = sr_oper_get_items_subscribe(session, BASE_YANG_MODEL, "/" BASE_YANG_MODEL ":routing/*", routing_state_data_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INF("subscribing to plugin RPCs/actions");

	// active-route RPC/action
	error = sr_rpc_subscribe(session, ROUTING_RIB_LIST_ACTIVE_ROUTE_RPC_PATH, routing_rpc_active_route_cb, NULL, 1, SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_rpc_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	goto out;
error_out:
	SRP_LOG_ERR("error occured while initializing the plugin -> %d", error);
out:
	return error;
}

static int static_routes_init(struct route_list_hash **ipv4_routes, struct route_list_hash **ipv6_routes)
{
	int nl_err = 0;
	int error = 0;

	struct nl_sock *socket = NULL;
	struct rtnl_route *route = NULL;
	struct nl_cache *cache = NULL;
	struct nl_cache *link_cache = NULL;
	struct route tmp_route = {0};
	struct rtnl_link *iface = NULL;
	char *if_name = NULL;
	int ifindex = 0;

	*ipv4_routes = xmalloc(sizeof(struct route_list_hash));
	*ipv6_routes = xmalloc(sizeof(struct route_list_hash));

	route_list_hash_init(*ipv4_routes);
	route_list_hash_init(*ipv6_routes);

	socket = nl_socket_alloc();
	if (socket == NULL) {
		SRP_LOG_ERR("unable to init nl_sock struct...");
		goto error_out;
	}

	nl_err = nl_connect(socket, NETLINK_ROUTE);
	if (nl_err != 0) {
		SRP_LOG_ERR("nl_connect failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_alloc_cache(socket, AF_UNSPEC, 0, &cache);
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_alloc_cache failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_link_alloc_cache(socket, AF_UNSPEC, &link_cache);
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_alloc_cache failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}


	route = (struct rtnl_route *) nl_cache_get_first(cache);
	while (route != NULL) {
		const int PROTO = rtnl_route_get_protocol(route);

		if (PROTO == RTPROT_STATIC) {
			const int AF = rtnl_route_get_family(route);
			// fill the route with info and add to the hash of the current RIB
			route_init(&tmp_route);
			route_set_preference(&tmp_route, rtnl_route_get_priority(route));

			// next-hop container -> TODO: see what about special type
			const int NEXTHOP_COUNT = rtnl_route_get_nnexthops(route);
			if (NEXTHOP_COUNT == 1) {
				struct rtnl_nexthop *nh = rtnl_route_nexthop_n(route, 0);
				ifindex = rtnl_route_nh_get_ifindex(nh);
				iface = rtnl_link_get(link_cache, ifindex);
				if_name = xstrdup(rtnl_link_get_name(iface));
				route_next_hop_set_simple(&tmp_route.next_hop, ifindex, if_name, rtnl_route_nh_get_gateway(nh));
				rtnl_link_put(iface);
			} else {
				rtnl_route_foreach_nexthop(route, foreach_nexthop, &tmp_route.next_hop);
			}

			// route-metadata/source-protocol
			route_set_source_protocol(&tmp_route, "ietf-routing:static");

			// add the route to the protocol's container
			if (AF == AF_INET) {
				// v4
				route_list_hash_add(*ipv4_routes, rtnl_route_get_dst(route), &tmp_route);
			} else if (AF == AF_INET6) {
				// v6
				route_list_hash_add(*ipv6_routes, rtnl_route_get_dst(route), &tmp_route);
			}

			route_free(&tmp_route);
		}
		route = (struct rtnl_route *) nl_cache_get_next((struct nl_object *) route);
	}

	goto out;

error_out:
	SRP_LOG_ERR("error initializing static routes");
	error = -1;
out:
	nl_cache_free(cache);
	nl_cache_free(link_cache);
	nl_socket_free(socket);
	return error;
}


void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	route_list_hash_free(ipv4_static_routes);
	route_list_hash_free(ipv6_static_routes);
	FREE_SAFE(ipv4_static_routes);
	FREE_SAFE(ipv6_static_routes);

}

static int routing_module_change_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = 0;

	// sysrepo
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;
	sr_change_iter_t *routing_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;

	// libyang
	const struct lyd_node *node = NULL;

	// temp helper vars
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	int prev_default = false;
	char *node_xpath = NULL;
	const char *node_value = NULL;

	bool ipv4_update = false;
	bool ipv6_update = false;

	SRP_LOG_INF("module_name: %s, xpath: %s, event: %d, request_id: %u", module_name, xpath, event, request_id);

	if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto error_out;
	} else if (event == SR_EV_DONE) {
		error = sr_copy_config(startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	} else if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &routing_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}

		while (sr_get_change_tree_next(session, routing_change_iter, &operation, &node, &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = routing_xpath_get(node);

			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				node_value = xstrdup(lyd_get_value(node));
			}

			SRP_LOG_DBG("node_xpath: %s; prev_val: %s; node_val: %s; operation: %d", node_xpath, prev_value, node_value, operation);


			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				if (strstr(node_xpath, "ietf-ipv4-unicast-routing:ipv4")) {
					ipv4_update = true;
				} else if (strstr(node_xpath, "ietf-ipv6-unicast-routing:ipv6")) {
					ipv6_update = true;
				}

				if (operation == SR_OP_CREATED || operation == SR_OP_MODIFIED) {
					if (strstr(node_xpath, "/ietf-routing:routing/ribs")) {
						error = set_rib_value(node_xpath, node_value);
						if (error) {
							SRP_LOG_ERR("set_control_plane_protocol_value error (%d)", error);
							goto error_out;
						}
					} else if (strstr(node_xpath, "ietf-routing:routing/control-plane-protocols")) {
						error = set_control_plane_protocol_value(node_xpath, node_value);
						if (error) {
							SRP_LOG_ERR("set_control_plane_protocol_value error (%d)", error);
							goto error_out;
						}
					}
				} else if (operation == SR_OP_DELETED) {
					if (strstr(node_xpath, "/ietf-routing:routing/ribs")) {
						error = delete_rib_value(node_xpath);
						if (error) {
							SRP_LOG_ERR("set_control_plane_protocol_value error (%d)", error);
							goto error_out;
						}
					} else if (strstr(node_xpath, "ietf-routing:routing/control-plane-protocols")) {
						error = delete_control_plane_protocol_value(node_xpath);
						if (error) {
							SRP_LOG_ERR("set_control_plane_protocol_value error (%d)", error);
							goto error_out;
						}
					}
				}
			}
			FREE_SAFE(node_xpath);
			FREE_SAFE(node_value);
		}

		if (ipv4_update) {
			update_ipv4_static_routes(ipv4_static_routes);
		}

		if (ipv6_update) {
			update_ipv6_static_routes(ipv6_static_routes);
		}
	}
	goto out;

error_out:
	SRP_LOG_ERR("error applying control plane protocols module changes");
	error = -1;
	FREE_SAFE(node_xpath);
	FREE_SAFE(node_value);

out:
	sr_free_change_iter(routing_change_iter);

	return error != 0 ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int update_ipv4_static_routes(struct route_list_hash *routes)
{
	struct nl_sock *socket = NULL;
	struct rtnl_route *route = NULL;
	struct rtnl_nexthop *next_hop = NULL;
	int error = 0;
	int nl_err = 0;

	socket = nl_socket_alloc();
	if (socket == NULL) {
		error = -1;
		SRP_LOG_ERR("unable to init nl_sock struct...");
		goto error_out;
	}

	nl_err = nl_connect(socket, NETLINK_ROUTE);
	if (nl_err != 0) {
		error = -1;
		SRP_LOG_ERR("nl_connect failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	for (size_t i = 0; i < routes->size; i++) {
		route = rtnl_route_alloc();
		if (route == NULL) {
			error = -1;
			SRP_LOG_ERR("unable to alloc rtnl_route struct");
			goto error_out;
		}

		rtnl_route_set_table(route, RT_TABLE_MAIN);
		rtnl_route_set_protocol(route, RTPROT_STATIC);
		rtnl_route_set_family(route, AF_INET);
		rtnl_route_set_priority(route, routes->list_route[i].list[0].preference);

		if (routes->list_route[i].list[0].next_hop.kind == route_next_hop_kind_simple) {
			next_hop = rtnl_route_nh_alloc();
			if (next_hop == NULL) {
				error = -1;
				SRP_LOG_ERR("unable to alloc rtnl_nexthop struct");
				goto error_out;
			}

			rtnl_route_nh_set_ifindex(next_hop, routes->list_route[i].list[0].next_hop.value.simple.ifindex);
			rtnl_route_nh_set_gateway(next_hop, routes->list_route[i].list[0].next_hop.value.simple.addr);
			rtnl_route_add_nexthop(route, next_hop);
		} else if (routes->list_route[i].list[0].next_hop.kind == route_next_hop_kind_list) {
			for (size_t j = 0; j < routes->list_route[i].list[0].next_hop.value.list.size; j++) {
				next_hop = rtnl_route_nh_alloc();
				if (next_hop == NULL) {
					error = -1;
					SRP_LOG_ERR("unable to alloc rtnl_nexthop struct");
					goto error_out;
				}

				rtnl_route_nh_set_ifindex(next_hop, routes->list_route[i].list[0].next_hop.value.list.list[j].ifindex);
				rtnl_route_nh_set_gateway(next_hop, routes->list_route[i].list[0].next_hop.value.list.list[j].addr);
				rtnl_route_add_nexthop(route, next_hop);

			}
		}

		rtnl_route_set_dst(route, nl_addr_clone(routes->list_addr[i]));
		rtnl_route_set_scope(route, rtnl_route_guess_scope(route));

		nl_err = rtnl_route_add(socket, route, NLM_F_REPLACE);
		if (nl_err != 0) {
			error = -1;
			SRP_LOG_ERR("rtnl_route_add failed (%d): %s", nl_err, nl_geterror(nl_err));
			goto error_out;
		}
	}
error_out:
	if (route) {
		rtnl_route_put(route);
	}

	if (socket) {
		nl_socket_free(socket);
	}

	return error;
}

static int update_ipv6_static_routes(struct route_list_hash *routes)
{
	return 0;
}

static int set_control_plane_protocol_value(char *node_xpath, const char *node_value)
{
	sr_xpath_ctx_t xpath_ctx = {0};

	struct nl_addr *destination_prefix_addr = NULL;
	struct nl_addr *next_hop_addr = NULL;

	struct route_list *route_list = NULL;

	char *node_name = NULL;
	char *name_key = NULL;
	char *type_key = NULL;
	char *orig_xpath = NULL;
	char *next_hop_list = NULL;
	char *destination_prefix = NULL;
	char ipv4_addr[16] = {0};
	int prefix_len = 0;
	int ifindex = 0;

	int error = SR_ERR_OK;

	orig_xpath = xstrdup(node_xpath);

	node_name = sr_xpath_node_name(node_xpath);
	name_key = sr_xpath_key_value(node_xpath, "control-plane-protocol", "name", &xpath_ctx);
	type_key = sr_xpath_key_value(node_xpath, "control-plane-protocol", "type", &xpath_ctx);

	if (!strcmp(node_name, "description") && !strstr(orig_xpath, "ietf-ipv4-unicast-routing:ipv4")
			&& !strstr(orig_xpath, "ietf-ipv6-unicast-routing:ipv6")) {
		error = routing_control_plane_protocol_set_description(type_key, name_key, node_value);
		if (error != 0) {
			SRP_LOG_ERR("routing_control_plane_protocol_set_description failed");
			goto out;
		}
	} else if (strstr(orig_xpath, "ietf-ipv4-unicast-routing:ipv4")) {
		// todo refactor into set_ipv4_value
		next_hop_list = sr_xpath_key_value(orig_xpath, "next-hop", "index", &xpath_ctx);
		destination_prefix = sr_xpath_key_value(orig_xpath, "route", "destination-prefix", &xpath_ctx);

		if (destination_prefix == NULL) {
			error = -1;
			SRP_LOG_ERR("destination-prefix couldn't be retrieved");
			goto out;
		}

		error = sscanf(destination_prefix, "%15[0123456789.]/%d", ipv4_addr, &prefix_len);
		if (error != 2) {
			error = -1;
			SRP_LOG_ERR("destination-prefix couldn't be parsed %s, %d %s", ipv4_addr, prefix_len, destination_prefix);
			goto out;
		}

		error = nl_addr_parse(ipv4_addr, AF_INET, &destination_prefix_addr);
		if (error != 0) {
			error = -1;
			SRP_LOG_ERR("failed to parse destination-prefix into nl_addr");
			goto out;
		}

		nl_addr_set_prefixlen(destination_prefix_addr, prefix_len);

		if (next_hop_list != NULL) {
			SRP_LOG_INF("got list node_name = %s, name_key = %s, type_key = %s, orig_xpath = %s", node_name, name_key, type_key, orig_xpath);
			route_list = route_list_hash_get_by_addr(ipv4_static_routes, destination_prefix_addr);
			route_list->list[0].next_hop.kind = route_next_hop_kind_list;

			printf("next_hop_list index = %s\n", index);
			if (!strcmp(node_name, "next-hop-address")) {
			} else if (!strcmp(node_name, "outgoing-interface")) {
			}
		} else if (!strcmp(node_name, "destination-prefix")) {
			SRP_LOG_INF("got dest prefix  node_name = %s, name_key = %s, type_key = %s, orig_xpath = %s", node_name, name_key, type_key, orig_xpath);
			route_list_hash_add(ipv4_static_routes, destination_prefix_addr, &(struct route){0});

		} else if (!strcmp(node_name, "description")) {
			SRP_LOG_INF("got descr node_name = %s, name_key = %s, type_key = %s, orig_xpath = %s", node_name, name_key, type_key, orig_xpath);
			route_list = route_list_hash_get_by_addr(ipv4_static_routes, destination_prefix_addr);
			if (route_list == NULL) {
				error = -1;
				SRP_LOG_ERR("description %s matching destination-prefix %s not found", node_value, destination_prefix);
				goto out;
			}

			route_list->list[0].metadata.description = xstrdup(node_value);
		} else if (!strcmp(node_name, "next-hop-address")) {
			// refactor into general function for setting simple next hops, reuse that in list
			SRP_LOG_INF("got next-hop-address node_name = %s, name_key = %s, type_key = %s, orig_xpath = %s", node_name, name_key, type_key, orig_xpath);
			route_list = route_list_hash_get_by_addr(ipv4_static_routes, destination_prefix_addr);
			if (route_list == NULL) {
				error = -1;
				SRP_LOG_ERR("next-hop-address %s matching destination-prefix %s not found", node_value, destination_prefix);
				goto out;
			}
			route_list->list[0].next_hop.kind = route_next_hop_kind_simple;

			error = sscanf(node_value, "%15[0123456789.]", ipv4_addr);
			if (error != 1) {
				error = -1;
				SRP_LOG_ERR("next-hop-address couldn't be parsed %s, %d %s", ipv4_addr, prefix_len, destination_prefix);
				goto out;
			}

			error = nl_addr_parse(ipv4_addr, AF_INET, &next_hop_addr);
			if (error != 0) {
				error = -1;
				SRP_LOG_ERR("failed to parse next-hop-address into nl_addr");
				goto out;
			}

			route_list->list[0].next_hop.value.simple.addr = nl_addr_clone(next_hop_addr);

		} else if (!strcmp(node_name, "outgoing-interface")) {
			// refactor into general function for setting simple next hops, reuse that in list
			SRP_LOG_INF("got outgoing-interface node_name = %s, name_key = %s, type_key = %s, orig_xpath = %s", node_name, name_key, type_key, orig_xpath);
			route_list = route_list_hash_get_by_addr(ipv4_static_routes, destination_prefix_addr);
			if (route_list == NULL) {
				error = -1;
				SRP_LOG_ERR("outgoing-interface %s matching destination-prefix %s not found", node_value, destination_prefix);
				goto out;
			}

			route_list->list[0].next_hop.kind = route_next_hop_kind_simple;
			route_list->list[0].next_hop.value.simple.if_name = xstrdup(node_value);
			ifindex = if_nametoindex(node_value);
			if (ifindex == 0) {
				error = -1;
				SRP_LOG_ERR("failed to get ifindex for %s", node_value);
				goto out;
			}

			route_list->list[0].next_hop.value.simple.ifindex = ifindex;
		}
	} else if (strstr(orig_xpath, "ietf-ipv6-unicast-routing:ipv6")) {
	}

out:
	if (next_hop_addr) {
		nl_addr_put(next_hop_addr);
	}

	if (destination_prefix_addr) {
		nl_addr_put(destination_prefix_addr);
	}

	if (orig_xpath) {
		FREE_SAFE(orig_xpath);
	}

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int delete_control_plane_protocol_value(const char *node_xpath)
{
	return 0;
}

static int set_rib_value(const char *node_xpath, const char *node_value)
{
	sr_xpath_ctx_t xpath_ctx = {0};

	char *name_key = NULL;
	char *node_name = NULL;

	int error = SR_ERR_OK;

	node_name = sr_xpath_node_name(node_xpath);
	name_key = sr_xpath_key_value(node_xpath, "rib", "name", &xpath_ctx);

	if (!strcmp(node_name, "description")) {
		error = routing_rib_set_description(name_key, node_value);
		if (error != 0) {
			SRP_LOG_ERR("routing_rib_set_description failed");
			goto out;
		}
	}

out:
	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int delete_rib_value(const char *node_xpath)
{
	return 0;
}

static int routing_module_change_rib_list_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = 0;

	// sysrepo
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;
	sr_change_iter_t *routing_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	sr_xpath_ctx_t xpath_ctx = {0};

	// libyang
	const struct lyd_node *node = NULL;

	// temp helper vars
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	int prev_default = false;
	char *node_xpath = NULL;
	const char *node_value = NULL;

	// node stuff
	char *name_key = NULL;
	char *node_name = NULL;

	SRP_LOG_INF("module_name: %s, xpath: %s, event: %d, request_id: %u", module_name, xpath, event, request_id);

	if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto error_out;
	} else if (event == SR_EV_DONE) {
		error = sr_copy_config(startup_session, BASE_YANG_MODEL, SR_DS_RUNNING, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	} else if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &routing_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}

		while (sr_get_change_tree_next(session, routing_change_iter, &operation, &node, &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = routing_xpath_get(node);

			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				node_value = xstrdup(lyd_get_value(node));
			}

			SRP_LOG_DBG("node_xpath: %s; prev_val: %s; node_val: %s; operation: %d", node_xpath, prev_value, node_value, operation);

			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				node_name = sr_xpath_last_node(node_xpath, &xpath_ctx);
				name_key = sr_xpath_key_value(node_xpath, "rib", "name", &xpath_ctx);

				if (strncmp(node_name, "description", sizeof("description") - 1) == 0) {
					error = routing_rib_set_description(name_key, node_value);
					if (error != 0) {
						SRP_LOG_ERR("routing_rib_set_description failed");
						goto error_out;
					}
				}
			}
			FREE_SAFE(node_xpath);
			node_value = NULL;
		}
	}
	goto out;

error_out:
	SRP_LOG_ERR("error applying ribs module changes");
	error = -1;

out:
	FREE_SAFE(node_xpath);
	sr_free_change_iter(routing_change_iter);

	return error != 0 ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static int routing_control_plane_protocol_set_description(const char *type, const char *name, const char *description)
{
	int error = 0;

	struct control_plane_protocol protos[ROUTING_PROTOS_COUNT] = {0};

	// temp variables and buffers
	char *data_dir = NULL;
	char path_buffer[PATH_MAX] = {0};
	char line_buffer[PATH_MAX] = {0};
	int tmp_type = 0;
	char type_buffer[100] = {0};
	char desc_buffer[256] = {0};
	FILE *fptr = NULL;

	data_dir = getenv(ROUTING_PLUGIN_DATA_DIR);
	if (data_dir == NULL) {
		SRP_LOG_ERR("unable to use environment variable for the plugin data dir: %s", ROUTING_PLUGIN_DATA_DIR);
		goto error_out;
	}

	for (int i = 0; i < ROUTING_PROTOS_COUNT; i++) {
		control_plane_protocol_init(&protos[i]);
	}

	// check if file exists first
	snprintf(path_buffer, sizeof(path_buffer), "%s%s%s", data_dir, (data_dir[strlen(data_dir) - 1] == '/' ? "" : "/"), ROUTING_PROTOS_MAP_FNAME);

	if (access(path_buffer, F_OK) != 0) {
		SRP_LOG_ERR("protocols map file doesnt exist - error");
		goto error_out;
	} else {
		fptr = fopen(path_buffer, "r");
		if (fptr == NULL) {
			SRP_LOG_ERR("unable to open file %s", path_buffer);
			goto error_out;
		}

		SRP_LOG_DBG("protocols map file exists - reading map values and changing description of '%s' to %s", name, description);

		while (fgets(line_buffer, sizeof(line_buffer), fptr) != NULL) {
			const int read_n = sscanf(line_buffer, "%d %s \"%256[^\"]\"", &tmp_type, type_buffer, desc_buffer);
			if (read_n == 3) {
				if (tmp_type >= 0 && tmp_type <= ROUTING_PROTOS_COUNT) {
					rtnl_route_proto2str(tmp_type, protos[tmp_type].name, sizeof(protos[tmp_type].name));
					protos[tmp_type].type = xstrdup(type_buffer);

					if (strcmp(protos[tmp_type].name, name) == 0) {
						// don't read this description - change it
						protos[tmp_type].description = xstrdup(description);
					} else {
						protos[tmp_type].description = xstrdup(desc_buffer);
					}
					protos[tmp_type].initialized = 1;
				} else {
					SRP_LOG_ERR("invalid protocol type found in the protocol types map file: %d", tmp_type);
					goto error_out;
				}
			} else {
				SRP_LOG_ERR("unable to properly read the protocol types map file format; read %d values", read_n);
				goto error_out;
			}
		}

		// return to the beginning and write protocols again - reopen because clearing the content of a file is needed
		fclose(fptr);
		fptr = fopen(path_buffer, "w");

		for (int i = 0; i < ROUTING_PROTOS_COUNT; i++) {
			if (protos[i].initialized == 1) {
				fprintf(fptr, "%d\t%s\t\"%s\"\n", i, protos[i].type, protos[i].description);
			}
		}
	}
	goto out;

error_out:
	error = -1;
out:
	if (fptr) {
		fclose(fptr);
	}

	for (int i = 0; i < ROUTING_PROTOS_COUNT; i++) {
		control_plane_protocol_free(&protos[i]);
	}
	return error;
}

static int routing_rib_set_address_family(const char *name, const char *address_family)
{
	int error = 0;
	return error;
}

static int routing_rib_set_description(const char *name, const char *description)
{
	int error = 0;

	// calcualte sizes for faster string comparisons later
	const size_t DESC_LEN = strlen(description);
	const size_t NAME_LEN = strlen(name);

	// file stream
	FILE *fptr = NULL;

	// buffers and temporary values
	char path_buffer[PATH_MAX] = {0};
	char line_buffer[PATH_MAX] = {0};
	const char *data_dir = NULL;
	struct rib_description_pair tmp_description = {0};

	// list of descriptions
	struct {
		struct rib_description_pair *list;
		int size;
	} rib_descriptions = {0};

	// first read all descriptions from the map file and change the wanted description
	// after that -> write those descriptions back to the file

	// get the data_dir variable using getenv
	data_dir = getenv(ROUTING_PLUGIN_DATA_DIR);
	if (data_dir == NULL) {
		SRP_LOG_ERR("unable to use environment variable for the plugin data dir: %s", ROUTING_PLUGIN_DATA_DIR);
		goto error_out;
	}

	// create file path and see if it exists
	snprintf(path_buffer, sizeof(path_buffer), "%s%s%s", data_dir, (data_dir[strlen(data_dir) - 1] == '/') ? "" : "/", ROUTING_RIBS_DESCRIPTIONS_MAP_FNAME);
	SRP_LOG_DBG("RIBs description map file path: %s", path_buffer);

	if (access(path_buffer, F_OK) == 0) {
		// file exists
		fptr = fopen(path_buffer, "r");
		if (fptr == NULL) {
			SRP_LOG_ERR("unable to open file %s", path_buffer);
			goto error_out;
		}

		while (fgets(line_buffer, sizeof(line_buffer), fptr) != NULL) {
			const int read_n = sscanf(line_buffer, "%s \"%256[^\"]\"", tmp_description.name, tmp_description.description);
			if (read_n == 2) {
				// add the description to the list
				rib_descriptions.list = xrealloc(rib_descriptions.list, sizeof(struct rib_description_pair) * (unsigned) (rib_descriptions.size + 1));
				memcpy(&rib_descriptions.list[rib_descriptions.size], &tmp_description, sizeof(struct rib_description_pair));
				rib_descriptions.size += 1;
			} else {
				SRP_LOG_ERR("unable to correctly read 2 values from the RIBs map file");
				goto error_out;
			}
		}
	} else {
		// file doesn't exist -> error
		SRP_LOG_ERR("%s file doesn't exist", path_buffer);
		goto error_out;
	}

	bool description_changed = false;

	SRP_LOG_DBG("setting description of %s to \"%s\"", name, description);

	for (int i = 0; i < rib_descriptions.size; i++) {
		struct rib_description_pair *PAIR = &rib_descriptions.list[i];
		if (strncmp(PAIR->name, name, NAME_LEN) == 0) {
			// found description -> change it
			if (DESC_LEN <= ROUTING_RIB_DESCRIPTION_SIZE) {
				memcpy(PAIR->description, description, DESC_LEN);
				PAIR->description[DESC_LEN] = 0;
				SRP_LOG_DBG("description = %s", PAIR->description);
				description_changed = true;
			} else {
				SRP_LOG_ERR("unable to set description: %d characters max...", ROUTING_RIB_DESCRIPTION_SIZE);
				goto error_out;
			}
			break;
		}
	}

	if (description_changed == false) {
		goto error_out;
	}

	// write changes back to the file
	fclose(fptr);
	fptr = fopen(path_buffer, "w");

	for (int i = 0; i < rib_descriptions.size; i++) {
		SRP_LOG_DBG("%s = %s", rib_descriptions.list[i].name, rib_descriptions.list[i].description);
		fprintf(fptr, "%s\t\"%s\"\n", rib_descriptions.list[i].name, rib_descriptions.list[i].description);
	}

	goto out;

error_out:
	SRP_LOG_ERR("unable to set description for %s", name);
	error = -1;

out:
	FREE_SAFE(rib_descriptions.list);
	if (fptr != NULL) {
		fclose(fptr);
	}
	return error;
}

static char *routing_xpath_get(const struct lyd_node *node)
{
	char *xpath_node = NULL;
	char *xpath_leaflist_open_bracket = NULL;
	size_t xpath_trimed_size = 0;
	char *xpath_trimed = NULL;

	if (node->schema->nodetype == LYS_LEAFLIST) {
		xpath_node = lyd_path(node, LYD_PATH_STD, NULL, 0);
		xpath_leaflist_open_bracket = strrchr(xpath_node, '[');
		if (xpath_leaflist_open_bracket == NULL) {
			return xpath_node;
		}

		xpath_trimed_size = (size_t) xpath_leaflist_open_bracket - (size_t) xpath_node + 1;
		xpath_trimed = xcalloc(1, xpath_trimed_size);
		strncpy(xpath_trimed, xpath_node, xpath_trimed_size - 1);
		xpath_trimed[xpath_trimed_size - 1] = '\0';

		FREE_SAFE(xpath_node);

		return xpath_trimed;
	} else {
		return lyd_path(node, LYD_PATH_STD, NULL, 0);
	}
}

static int routing_state_data_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	return 0;
}

static int routing_oper_get_interfaces_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	// error handling
	int error = SR_ERR_OK;
	LY_ERR ly_err = LY_SUCCESS;

	// libyang
	const struct ly_ctx *ly_ctx = NULL;

	// libnl
	struct nl_sock *socket = NULL;
	struct nl_cache *cache = NULL;
	struct rtnl_link *link = NULL;

	if (*parent == NULL) {
		ly_ctx = sr_get_context(sr_session_get_connection(session));
		if (ly_ctx == NULL) {
			goto error_out;
		}
		ly_err = lyd_new_path(*parent, ly_ctx, request_xpath, NULL, 0, NULL);
		if (ly_err != LY_SUCCESS) {
			SRP_LOG_ERR("unable to create new node");
			goto error_out;
		}
	}

	socket = nl_socket_alloc();
	if (socket == NULL) {
		SRP_LOG_ERR("unable to init nl_sock struct...");
		goto error_out;
	}

	error = nl_connect(socket, NETLINK_ROUTE);
	if (error != 0) {
		SRP_LOG_ERR("nl_connect failed (%d): %s", error, nl_geterror(error));
		goto error_out;
	}

	error = rtnl_link_alloc_cache(socket, AF_UNSPEC, &cache);
	if (error != 0) {
		SRP_LOG_ERR("rtnl_link_alloc_cache failed (%d): %s", error, nl_geterror(error));
		goto error_out;
	}

	SRP_LOG_DBG("adding interfaces to the list");

	link = (struct rtnl_link *) nl_cache_get_first(cache);
	while (link) {
		const char *name = rtnl_link_get_name(link);
		SRP_LOG_DBG("adding interface '%s' ", name);
		ly_err = lyd_new_path(*parent, ly_ctx, ROUTING_INTERFACE_LEAF_LIST_YANG_PATH, (void *) name, 0, NULL);
		if (ly_err != LY_SUCCESS) {
			SRP_LOG_ERR("unable to create new interface node");
			goto error_out;
		}

		link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
	}

	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;
out:
	// free allocated objects
	nl_cache_free(cache);
	nl_socket_free(socket);

	return error;
}

static void foreach_nexthop(struct rtnl_nexthop *nh, void *arg)
{
	struct route_next_hop *nexthop = arg;
	struct nl_cache *link_cache = NULL;
	struct nl_sock *socket = NULL;
	struct rtnl_link *iface = NULL;
	int ifindex = 0;
	char *if_name = NULL;
	int nl_err = 0;

	nl_err = nl_socket_alloc();
	if (socket == NULL) {
		SRP_LOG_ERR("unable to init nl_sock struct...");
		return;
	}

	nl_err = nl_connect(socket, NETLINK_ROUTE);
	if (nl_err != 0) {
		SRP_LOG_ERR("nl_connect failed (%d): %s", nl_err, nl_geterror(nl_err));
		return;
	}

	nl_err = rtnl_link_alloc_cache(socket, AF_UNSPEC, &link_cache);
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_alloc_cache failed (%d): %s", nl_err, nl_geterror(nl_err));
		return;
	}

	ifindex = rtnl_route_nh_get_ifindex(nh);
	iface = rtnl_link_get(link_cache, ifindex);
	if_name = xstrdup(rtnl_link_get_name(iface));

	route_next_hop_add_list(nexthop, ifindex, if_name, rtnl_route_nh_get_gateway(nh));

	rtnl_link_put(iface);
	nl_cache_free(link_cache);
	nl_socket_free(socket);
}

static int routing_oper_get_rib_routes_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
	int error = SR_ERR_OK;
	int nl_err = 0;
	LY_ERR ly_err = LY_SUCCESS;

	// libyang
	const struct ly_ctx *ly_ctx = NULL;
	const struct lys_module *ly_uv4mod = NULL, *ly_uv6mod = NULL;
	struct lyd_node *ly_node = NULL, *routes_node = NULL, *nh_node = NULL, *nh_list_node = NULL;

	// libnl
	struct nl_sock *socket = NULL;
	struct nl_cache *cache = NULL;
	struct nl_cache *link_cache = NULL;
	struct rib_list ribs = {0};

	// temp buffers
	char routes_buffer[PATH_MAX];
	char value_buffer[PATH_MAX];
	char ip_buffer[INET6_ADDRSTRLEN];
	char prefix_buffer[INET6_ADDRSTRLEN + 1 + 3];

	ly_ctx = sr_get_context(sr_session_get_connection(session));

	ly_uv4mod = ly_ctx_get_module(ly_ctx, "ietf-ipv4-unicast-routing", "2018-03-13");
	ly_uv6mod = ly_ctx_get_module(ly_ctx, "ietf-ipv6-unicast-routing", "2018-03-13");

	socket = nl_socket_alloc();
	if (socket == NULL) {
		SRP_LOG_ERR("unable to init nl_sock struct...");
		goto error_out;
	}

	nl_err = nl_connect(socket, NETLINK_ROUTE);
	if (nl_err != 0) {
		SRP_LOG_ERR("nl_connect failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_alloc_cache(socket, AF_UNSPEC, 0, &cache);
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_alloc_cache failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_link_alloc_cache(socket, AF_UNSPEC, &link_cache);
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_link_alloc_cache failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_read_table_names("/etc/iproute2/rt_tables");
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_read_table_names failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_read_protocol_names("/etc/iproute2/rt_protos");
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_read_table_names failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	error = routing_collect_routes(cache, link_cache, &ribs);
	if (error != 0) {
		goto error_out;
	}

	for (int hash_iter = 0; hash_iter < ribs.size; hash_iter++) {
		// create new routes container for every table
		const struct route_list_hash *ROUTES_HASH = &ribs.list[hash_iter].routes;
		const int ADDR_FAMILY = ribs.list[hash_iter].address_family;
		const char *TABLE_NAME = ribs.list[hash_iter].name;
		snprintf(routes_buffer, sizeof(routes_buffer), "%s[name='%s-%s']/routes", ROUTING_RIB_LIST_YANG_PATH, ADDR_FAMILY == AF_INET ? "ipv4" : "ipv6", TABLE_NAME);
		ly_err = lyd_new_path(*parent, ly_ctx, routes_buffer, NULL, LYD_NEW_PATH_UPDATE, &routes_node);
		if (ly_err != LY_SUCCESS) {
			SRP_LOG_ERR("unable to create new routes node");
			goto error_out;
		}

		for (int i = 0; i < ROUTES_HASH->size; i++) {
			struct route_list *list_ptr = &ROUTES_HASH->list_route[i];
			struct nl_addr *dst_prefix = ROUTES_HASH->list_addr[i];
			nl_addr2str(dst_prefix, ip_buffer, sizeof(ip_buffer));

			// check for prefix - libnl doesn't write prefix into the buffer if its 8*4/8*6 i.e. only that address/no subnet
			if (strchr(ip_buffer, '/') == NULL) {
				snprintf(prefix_buffer, sizeof(prefix_buffer), "%s/%d", ip_buffer, nl_addr_get_prefixlen(dst_prefix));
			} else {
				snprintf(prefix_buffer, sizeof(prefix_buffer), "%s", ip_buffer);
			}

			for (int j = 0; j < list_ptr->size; j++) {
				const struct route *ROUTE = &list_ptr->list[j];
				// create a new list and after that add properties to it
				ly_err = lyd_new_path(routes_node, ly_ctx, "routes/route", NULL, 0, &ly_node);
				if (ly_err != LY_SUCCESS) {
					SRP_LOG_ERR("unable to create new route node");
					goto error_out;
				}

				// route-preference
				snprintf(value_buffer, sizeof(value_buffer), "%u", ROUTE->preference);
				SRP_LOG_DBG("route-preference = %s", value_buffer);
				ly_err = lyd_new_path(ly_node, ly_ctx, "route-preference", (void *) value_buffer, 0, NULL);
				if (ly_err != LY_SUCCESS) {
					SRP_LOG_ERR("unable to create new route-preference node");
					goto error_out;
				}

				// next-hop container
				const union route_next_hop_value *NEXTHOP = &ROUTE->next_hop.value;
				ly_err = lyd_new_path(ly_node, ly_ctx, "next-hop", NULL, 0, &nh_node);
				if (ly_err != LY_SUCCESS) {
					SRP_LOG_ERR("unable to create new next-hop node");
					goto error_out;
				}

				switch (ROUTE->next_hop.kind) {
					case route_next_hop_kind_none:
						break;
					case route_next_hop_kind_simple: {
						struct rtnl_link *iface = rtnl_link_get(link_cache, ROUTE->next_hop.value.simple.ifindex);
						const char *if_name = rtnl_link_get_name(iface);

						// outgoing-interface
						SRP_LOG_DBG("outgoing-interface = %s", if_name);
						ly_err = lyd_new_path(nh_node, ly_ctx, "outgoing-interface", (void *) if_name, 0, NULL);
						if (ly_err != LY_SUCCESS) {
							SRP_LOG_ERR("unable to create new outgoing-interface node");
							goto error_out;
						}

						// next-hop-address
						if (NEXTHOP->simple.addr) {
							nl_addr2str(NEXTHOP->simple.addr, ip_buffer, sizeof(ip_buffer));
							if (ADDR_FAMILY == AF_INET && ly_uv4mod != NULL) {
								SRP_LOG_DBG("IPv4 next-hop-address = %s", ip_buffer);
								ly_err = lyd_new_term(nh_node, ly_uv4mod, "next-hop-address", ip_buffer, false, NULL);
								if (ly_err != LY_SUCCESS) {
									SRP_LOG_ERR("unable to create new IPv4 next-hop-address node");
									goto error_out;
								}
							} else if (ADDR_FAMILY == AF_INET6 && ly_uv6mod != NULL) {
								SRP_LOG_DBG("IPv6 next-hop-address = %s", ip_buffer);
								ly_err = lyd_new_term(nh_node, ly_uv6mod, "next-hop-address", ip_buffer, false, NULL);
								if (ly_err != LY_SUCCESS) {
									SRP_LOG_ERR("unable to create new IPv6 next-hop-address node");
									goto error_out;
								}
							}
						}
						rtnl_link_put(iface);
						break;
					}
					case route_next_hop_kind_special:
						break;
					case route_next_hop_kind_list: {
						const struct route_next_hop_list *NEXTHOP_LIST = &ROUTE->next_hop.value.list;
						ly_err = lyd_new_path(nh_node, ly_ctx, "next-hop-list/next-hop", NULL, 0, &nh_list_node);
						if (ly_err != LY_SUCCESS) {
							SRP_LOG_ERR("unable to create new next-hop-list/next-hop node");
							goto error_out;
						}

						for (int k = 0; k < NEXTHOP_LIST->size; k++) {
							struct rtnl_link *iface = rtnl_link_get(link_cache, NEXTHOP_LIST->list[k].ifindex);
							const char *if_name = rtnl_link_get_name(iface);

							// outgoing-interface
							SRP_LOG_DBG("outgoing-interface = %s", if_name);
							ly_err = lyd_new_path(nh_list_node, ly_ctx, "outgoing-interface", (void *) if_name, 0, NULL);
							if (ly_err != LY_SUCCESS) {
								SRP_LOG_ERR("unable to create new outgoing-interface node");
								goto error_out;
							}

							// next-hop-address
							if (NEXTHOP_LIST->list[k].addr) {
								nl_addr2str(NEXTHOP_LIST->list[k].addr, ip_buffer, sizeof(ip_buffer));
								if (ADDR_FAMILY == AF_INET && ly_uv4mod != NULL) {
									SRP_LOG_DBG("IPv4 next-hop/next-hop-list/next-hop/next-hop-address = %s", ip_buffer);
									ly_err = lyd_new_term(nh_list_node, ly_uv4mod, "next-hop-address", ip_buffer, false, NULL);
									if (ly_err != LY_SUCCESS) {
										SRP_LOG_ERR("unable to create new IPv4 next-hop-address node");
										goto error_out;
									}
								} else if (ADDR_FAMILY == AF_INET6 && ly_uv6mod != NULL) {
									SRP_LOG_DBG("IPv6 next-hop/next-hop-list/next-hop/next-hop-address = %s", ip_buffer);
									ly_err = lyd_new_term(nh_list_node, ly_uv6mod, "next-hop-address", ip_buffer, false, NULL);
									if (ly_err != LY_SUCCESS) {
										SRP_LOG_ERR("unable to create new IPv6 next-hop-address node");
										goto error_out;
									}
								}
							}
							rtnl_link_put(iface);
						}
						break;
					}
				}

				// destination-prefix
				if (ADDR_FAMILY == AF_INET && ly_uv4mod != NULL) {
					if (strncmp("none/0", prefix_buffer, strnlen(prefix_buffer, sizeof(prefix_buffer))) == 0) {
						strcpy(prefix_buffer, "0.0.0.0/0");
					}

					SRP_LOG_DBG("destination-prefix = %s", prefix_buffer);
					ly_err = lyd_new_term(ly_node, ly_uv4mod, "destination-prefix", prefix_buffer, false, NULL);
					if (ly_err != LY_SUCCESS) {
						SRP_LOG_ERR("unable to create new IPv4 destination-prefix node");
						goto error_out;
					}
				} else if (ADDR_FAMILY == AF_INET6 && ly_uv6mod != NULL) {
					if (strncmp("none/0", prefix_buffer, strnlen(prefix_buffer, sizeof(prefix_buffer))) == 0) {
						strcpy(prefix_buffer, "::/0");
					}

					SRP_LOG_DBG("destination-prefix = %s", prefix_buffer);
					ly_err = lyd_new_term(ly_node, ly_uv6mod, "destination-prefix", prefix_buffer, false, NULL);
					if (ly_err != LY_SUCCESS) {
						SRP_LOG_ERR("unable to create new IPv6 destination-prefix node");
						goto error_out;
					}
				}

				// route-metadata/source-protocol
				SRP_LOG_DBG("source-protocol = %s", ROUTE->metadata.source_protocol);
				ly_err = lyd_new_path(ly_node, ly_ctx, "source-protocol", ROUTE->metadata.source_protocol, 0, NULL);
				if (ly_err != LY_SUCCESS) {
					SRP_LOG_ERR("unable to create new source-protocol node");
					goto error_out;
				}

				// route-metadata/active
				if (ROUTE->metadata.active == 1) {
					SRP_LOG_DBG("active = %d", ROUTE->metadata.active);
					ly_err = lyd_new_path(ly_node, ly_ctx, "active", NULL, 0, NULL);
					if (ly_err != LY_SUCCESS) {
						SRP_LOG_ERR("unable to create new active node");
						goto error_out;
					}
				}
			}
		}
	}

	if (error != 0) {
		goto error_out;
	}

	goto out;

error_out:
	SRP_LOG_ERR("unable to return routes for routing tables");
	error = SR_ERR_CALLBACK_FAILED;

out:
	rib_list_free(&ribs);
	nl_socket_free(socket);
	nl_cache_free(cache);
	nl_cache_free(link_cache);
	return error;
}

static int routing_rpc_active_route_cb(sr_session_ctx_t *session, uint32_t subscription_id, const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
	int error = SR_ERR_OK;
	SRP_LOG_DBG("xpath for RPC: %s", xpath);
	return error;
}

static int routing_load_data(sr_session_ctx_t *session)
{
	int error = 0;
	LY_ERR ly_err = LY_SUCCESS;
	const struct ly_ctx *ly_ctx = NULL;
	struct lyd_node *routing_container_node = NULL;

	ly_ctx = sr_get_context(sr_session_get_connection(session));
	if (ly_ctx == NULL) {
		SRP_LOG_ERR("unable to get ly_ctx variable... exiting immediately");
		goto error_out;
	}

	// create the routing container node and pass it to other functions which will add to the given node
	ly_err = lyd_new_path(NULL, ly_ctx, ROUTING_CONTAINER_YANG_PATH, NULL, 0, &routing_container_node);
	if (ly_err != LY_SUCCESS) {
		SRP_LOG_ERR("unable to create the routing container ly node");
		goto error_out;
	}

	error = routing_load_ribs(session, routing_container_node);
	if (error) {
		SRP_LOG_ERR("routing_load_ribs failed : %d", error);
		goto error_out;
	}

	error = routing_load_control_plane_protocols(session, routing_container_node);
	if (error) {
		SRP_LOG_ERR("routing_load_control_plane_protocols failed : %d", error);
		goto error_out;
	}

	// after all nodes have been added with no error -> edit the values and apply changes
	error = sr_edit_batch(session, routing_container_node, "merge");
	if (error != SR_ERR_OK) {
		SRP_LOG_ERR("sr_edit_batch error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}
	error = sr_apply_changes(session, 0);
	if (error != 0) {
		SRP_LOG_ERR("sr_apply_changes error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	goto out;
error_out:
	SRP_LOG_ERR("unable to load initial data");
out:
	if (routing_container_node) {
		lyd_free_tree(routing_container_node);
	}
	return error;
}

static int routing_load_ribs(sr_session_ctx_t *session, struct lyd_node *routing_container_node)
{
	// error handling
	int error = 0;
	int nl_err = 0;
	LY_ERR ly_err = LY_SUCCESS;

	// libyang
	struct lyd_node *ribs_node = NULL, *rib_node = NULL, *added_node = NULL;
	const struct ly_ctx *ly_ctx = NULL;
	const struct lys_module *ly_uv4mod = NULL, *ly_uv6mod = NULL;

	// libnl
	struct nl_sock *socket = NULL;
	struct nl_cache *cache = NULL;
	struct rib_list ribs = {0};

	// temp buffers
	char list_buffer[PATH_MAX] = {0};

	ly_ctx = sr_get_context(sr_session_get_connection(session));
	if (ly_ctx) {
		ly_uv4mod = ly_ctx_get_module(ly_ctx, "ietf-ipv4-unicast-routing", "2018-03-13");
		ly_uv6mod = ly_ctx_get_module(ly_ctx, "ietf-ipv6-unicast-routing", "2018-03-13");
	} else {
		SRP_LOG_ERR("unable to load external modules... exiting");
		error = -1;
		goto error_out;
	}

	rib_list_init(&ribs);

	socket = nl_socket_alloc();
	if (socket == NULL) {
		SRP_LOG_ERR("unable to init nl_sock struct...");
		goto error_out;
	}

	nl_err = nl_connect(socket, NETLINK_ROUTE);
	if (nl_err != 0) {
		SRP_LOG_ERR("nl_connect failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_alloc_cache(socket, AF_UNSPEC, 0, &cache);
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_alloc_cache failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_read_table_names("/etc/iproute2/rt_tables");
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_read_table_names failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_read_protocol_names("/etc/iproute2/rt_protos");
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_read_table_names failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	error = routing_collect_ribs(cache, &ribs);
	if (error != 0) {
		goto error_out;
	}

	ly_err = lyd_new_path(routing_container_node, ly_ctx, ROUTING_RIBS_CONTAINER_YANG_PATH, NULL, 0, &ribs_node);
	if (ly_err != LY_SUCCESS) {
		SRP_LOG_ERR("unable to create rib list container...");
		goto error_out;
	}

	// all RIBs loaded - add them to the initial config
	struct rib *iter = NULL;
	for (int i = 0; i < ribs.size; i++) {
		iter = &ribs.list[i];
		SRP_LOG_DBG("adding table %s to the list", iter->name);

		// write the current adding table into the buffer
		snprintf(list_buffer, sizeof(list_buffer), "%s[name='%s-%s']", ROUTING_RIB_LIST_YANG_PATH, iter->address_family == AF_INET ? "ipv4" : "ipv6", iter->name);
		ly_err = lyd_new_path(ribs_node, ly_ctx, list_buffer, NULL, 0, &rib_node);
		if (ly_err != LY_SUCCESS) {
			SRP_LOG_ERR("unable to add new list...");
			goto error_out;
		}

		// address family
		ly_err = lyd_new_path(rib_node, ly_ctx, "address-family", iter->address_family == AF_INET ? "ipv4" : "ipv6", 0, &added_node);
		if (ly_err != LY_SUCCESS) {
			SRP_LOG_ERR("unable to add 'address-family' node to the tree");
			goto error_out;
		}

		// description
		if (iter->description[0] != 0) {
			ly_err = lyd_new_path(rib_node, ly_ctx, "description", iter->description, 0, &added_node);
			if (ly_err != LY_SUCCESS) {
				SRP_LOG_ERR("unable to add 'description' node to the rib");
				goto error_out;
			}
		}
	}

	goto out;
error_out:
	SRP_LOG_ERR("error loading initial data");
	error = -1;

out:
	rib_list_free(&ribs);
	nl_socket_free(socket);
	nl_cache_free(cache);

	return error;
}

static int routing_collect_ribs(struct nl_cache *routes_cache, struct rib_list *ribs)
{
	int error = 0;
	struct rtnl_route *route = NULL;
	char table_buffer[32] = {0};
	char name_buffer[32 + 5] = {0};

	route = (struct rtnl_route *) nl_cache_get_first(routes_cache);

	while (route != NULL) {
		// fetch table name
		const int table_id = (int) rtnl_route_get_table(route);
		const uint8_t af = rtnl_route_get_family(route);
		rtnl_route_table2str(table_id, table_buffer, sizeof(table_buffer));
		snprintf(name_buffer, sizeof(name_buffer), "%s-%s", af == AF_INET ? "ipv4" : "ipv6", table_buffer);

		// add the table to the list and set properties
		rib_list_add(ribs, table_buffer, af);

		// default table is main (same as iproute2) - for both ipv4 and ipv6 addresses
		if (strncmp(table_buffer, "main", sizeof("main") - 1) == 0) {
			rib_list_set_default(ribs, table_buffer, af, 1);
		}

		route = (struct rtnl_route *) nl_cache_get_next((struct nl_object *) route);
	}

	// after the list is finished -> build descriptions for all ribs
	error = routing_build_rib_descriptions(ribs);
	if (error != 0) {
		goto error_out;
	}

	goto out;

error_out:
	SRP_LOG_ERR("error collecting RIBs: %d", error);

out:
	return error;
}

static int routing_collect_routes(struct nl_cache *routes_cache, struct nl_cache *link_cache, struct rib_list *ribs)
{
	int error = 0;
	struct rtnl_route *route = NULL;
	struct route tmp_route = {0};
	char table_buffer[32] = {0};
	struct rib *tmp_rib = NULL;
	struct rtnl_link *iface = NULL;
	int ifindex = 0;
	char *if_name = NULL;

	error = routing_collect_ribs(routes_cache, ribs);
	if (error != 0) {
		goto error_out;
	}

	// gather all routes for each table
	route = (struct rtnl_route *) nl_cache_get_first(routes_cache);
	while (route != NULL) {
		// fetch table name
		const int table_id = (int) rtnl_route_get_table(route);
		const uint8_t af = rtnl_route_get_family(route);
		rtnl_route_table2str(table_id, table_buffer, sizeof(table_buffer));

		// get the current RIB of the route
		tmp_rib = rib_list_get(ribs, table_buffer, af);
		if (tmp_rib == NULL) {
			error = -1;
			goto error_out;
		}

		// fill the route with info and add to the hash of the current RIB
		route_init(&tmp_route);
		route_set_preference(&tmp_route, rtnl_route_get_priority(route));

		// next-hop container -> TODO: see what about special type
		const int NEXTHOP_COUNT = rtnl_route_get_nnexthops(route);
		if (NEXTHOP_COUNT == 1) {
			struct rtnl_nexthop *nh = rtnl_route_nexthop_n(route, 0);
			ifindex = rtnl_route_nh_get_ifindex(nh);
			iface = rtnl_link_get(link_cache, ifindex);
			if_name = rtnl_link_get_name(iface);
			route_next_hop_set_simple(&tmp_route.next_hop, ifindex, if_name, rtnl_route_nh_get_gateway(nh));
		} else {
			rtnl_route_foreach_nexthop(route, foreach_nexthop, &tmp_route.next_hop);
		}

		// route-metadata/source-protocol
		if (rtnl_route_get_protocol(route) == RTPROT_STATIC) {
			route_set_source_protocol(&tmp_route, "ietf-routing:static");
		} else {
			route_set_source_protocol(&tmp_route, "ietf-routing:direct");
		}

		// add the created route to the hash by a destination address
		route_list_hash_add(&tmp_rib->routes, rtnl_route_get_dst(route), &tmp_route);

		// last-updated -> TODO: implement later
		route_free(&tmp_route);
		route = (struct rtnl_route *) nl_cache_get_next((struct nl_object *) route);
	}

	for (int i = 0; i < ribs->size; i++) {
		const struct route_list_hash *routes_hash = &ribs->list[i].routes;
		if (routes_hash->size) {
			// iterate every "hash" and set the active value for the preferred route
			for (int j = 0; j < routes_hash->size; j++) {
				struct route_list *ls = &routes_hash->list_route[j];
				if (ls->size > 0) {
					struct route *pref = &ls->list[0];
					for (int k = 1; k < ls->size; k++) {
						struct route *ptr = &ls->list[k];
						if (ptr->preference < pref->preference) {
							pref = ptr;
						}
					}
					pref->metadata.active = 1;
				}
			}
		}
	}

error_out:
	return error;
}

static int routing_load_control_plane_protocols(sr_session_ctx_t *session, struct lyd_node *routing_container_node)
{
	// error handling
	int error = 0;
	int nl_err = 0;
	LY_ERR ly_err = LY_SUCCESS;

	// libyang
	const struct lys_module *ly_uv4mod = NULL, *ly_uv6mod = NULL;
	const struct ly_ctx *ly_ctx = NULL;
	struct lyd_node *cpp_container_node = NULL;
	struct lyd_node *cpp_list_node = NULL;
	struct lyd_node *static_routes_container_node = NULL;
	struct lyd_node *tmp_node = NULL;
	struct lyd_node *ipv4_container_node = NULL, *ipv6_container_node = NULL;
	struct lyd_node *route_node = NULL;
	struct lyd_node *nh_node = NULL, *nh_list_node = NULL;

	// temp buffers
	char list_buffer[PATH_MAX] = {0};
	char ip_buffer[INET6_ADDRSTRLEN] = {0};
	char prefix_buffer[INET6_ADDRSTRLEN + 1 + 3] = {0};
	char route_path_buffer[PATH_MAX] = {0};

	// control-plane-protocol structs
	struct control_plane_protocol cpp_map[ROUTING_PROTOS_COUNT] = {0};
	struct control_plane_protocol *STATIC_PROTO = &cpp_map[RTPROT_STATIC];
	struct route tmp_route = {0};

	ly_ctx = sr_get_context(sr_session_get_connection(session));
	if (ly_ctx) {
		ly_uv4mod = ly_ctx_get_module(ly_ctx, "ietf-ipv4-unicast-routing", "2018-03-13");
		ly_uv6mod = ly_ctx_get_module(ly_ctx, "ietf-ipv6-unicast-routing", "2018-03-13");
	} else {
		SRP_LOG_ERR("unable to load external modules... exiting");
		error = -1;
		goto error_out;
	}

	nl_err = rtnl_route_read_table_names("/etc/iproute2/rt_tables");
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_read_table_names failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	nl_err = rtnl_route_read_protocol_names("/etc/iproute2/rt_protos");
	if (nl_err != 0) {
		SRP_LOG_ERR("rtnl_route_read_table_names failed (%d): %s", nl_err, nl_geterror(nl_err));
		goto error_out;
	}

	// build protocols map array
	error = routing_build_protos_map(cpp_map);
	if (error) {
		SRP_LOG_ERR("unable to build protocols mapping array: %d", error);
		goto error_out;
	}

	ly_err = lyd_new_path(routing_container_node, ly_ctx, ROUTING_CONTROL_PLANE_PROTOCOLS_CONTAINER_YANG_PATH, NULL, 0, &cpp_container_node);
	if (ly_err != LY_SUCCESS) {
		SRP_LOG_ERR("unable to create control plane protocols container...");
		goto error_out;
	}

	// control plane protocols container created - add all protocols to the inner list

	// add the data to the datastore
	for (int i = 0; i < ROUTING_PROTOS_COUNT; i++) {
		const struct control_plane_protocol *proto = &cpp_map[i];
		if (proto->initialized) {
			// write proto path - type + name are added automatically when creating the list node
			snprintf(list_buffer, sizeof(list_buffer), "%s[type=\"%s\"][name=\"%s\"]", ROUTING_CONTROL_PLANE_PROTOCOL_LIST_YANG_PATH, proto->type, proto->name);
			ly_err = lyd_new_path(cpp_container_node, ly_ctx, list_buffer, NULL, 0, &cpp_list_node);
			if (ly_err != LY_SUCCESS) {
				SRP_LOG_ERR("unable to add new control plane protocol %s", proto->name);
				goto error_out;
			}

			// description
			ly_err = lyd_new_path(cpp_list_node, ly_ctx, "description", proto->description, 0, &tmp_node);
			if (ly_err != LY_SUCCESS) {
				SRP_LOG_ERR("unable to add 'description' node for the control plane protocol %s...", proto->name);
				goto error_out;
			}

			// static protocol -> static-routes
			if (strncmp(proto->name, "static", sizeof("static") - 1) == 0) {
				ly_err = lyd_new_path(cpp_list_node, ly_ctx, "static-routes", NULL, 0, &static_routes_container_node);
				if (ly_err != LY_SUCCESS) {
					SRP_LOG_ERR("unable to add static-routes container node... exiting");
					goto error_out;
				}

				// for the static protocol add ipv4 and ipv6 static routes - each destination prefix => one route => one nexthop + description
				ly_err = lyd_new_inner(static_routes_container_node, ly_uv4mod, "ipv4", false, &ipv4_container_node);
				if (ly_err != LY_SUCCESS) {
					SRP_LOG_ERR("unable to add ipv4 container node... exiting");
					goto error_out;
				}
				ly_err = lyd_new_inner(static_routes_container_node, ly_uv6mod, "ipv6", false, &ipv6_container_node);
				if (ly_err != LY_SUCCESS) {
					SRP_LOG_ERR("unable to add ipv6 container node... exiting");
					goto error_out;
				}

				// ipv4
				for (int j = 0; j < ipv4_static_routes->size; j++) {
					const struct nl_addr *DST_PREFIX = ipv4_static_routes->list_addr[j];
					const struct route *ROUTE = &ipv4_static_routes->list_route[j].list[0];
					const union route_next_hop_value *NEXTHOP = &ROUTE->next_hop.value;

					// configure prefix
					nl_addr2str(DST_PREFIX, ip_buffer, sizeof(ip_buffer));
					if (strchr(ip_buffer, '/') == NULL) {
						snprintf(prefix_buffer, sizeof(prefix_buffer), "%s/%d", ip_buffer, nl_addr_get_prefixlen(DST_PREFIX));
					} else {
						snprintf(prefix_buffer, sizeof(prefix_buffer), "%s", ip_buffer);
					}

					// create new list node
					snprintf(route_path_buffer, sizeof(route_path_buffer), "route[destination-prefix=\"%s\"]", prefix_buffer);
					ly_err = lyd_new_path(ipv4_container_node, ly_ctx, route_path_buffer, NULL, 0, &route_node);
					if (ly_err != LY_SUCCESS) {
						SRP_LOG_ERR("unable to create a new route node for the list %s", route_path_buffer);
						goto error_out;
					}

					// description
					if (ROUTE->metadata.description != NULL) {
						ly_err = lyd_new_term(route_node, ly_uv4mod, "description", ROUTE->metadata.description, false, &tmp_node);
						if (ly_err != LY_SUCCESS) {
							SRP_LOG_ERR("unable to add description leaf to the %s node", route_path_buffer);
							goto error_out;
						}
					}

					// next-hop container
					ly_err = lyd_new_inner(route_node, ly_uv4mod, "next-hop", false, &nh_node);
					if (ly_err != LY_SUCCESS) {
						SRP_LOG_ERR("unable to create new next-hop container for the node %s", route_path_buffer);
						goto error_out;
					}
					switch (ROUTE->next_hop.kind) {
						case route_next_hop_kind_none:
							break;
						case route_next_hop_kind_simple: {
							// next-hop-address
							if (NEXTHOP->simple.addr) {
								nl_addr2str(NEXTHOP->simple.addr, ip_buffer, sizeof(ip_buffer));
								ly_err = lyd_new_term(nh_node, ly_uv4mod, "next-hop-address", ip_buffer, false, &tmp_node);
								if (ly_err != LY_SUCCESS) {
									SRP_LOG_ERR("unable to create next-hop-address leaf for the node %s", route_path_buffer);
									goto error_out;
								}

								ly_err = lyd_new_term(nh_node, ly_uv4mod, "outgoing-interface", NEXTHOP->simple.if_name, false, &tmp_node);
								if (ly_err != LY_SUCCESS) {
									SRP_LOG_ERR("unable to create outgoing-interface leaf for the node %s", route_path_buffer);
									goto error_out;
								}
							}
							break;
						}
						case route_next_hop_kind_special:
							break;
						case route_next_hop_kind_list: {
							const struct route_next_hop_list *NEXTHOP_LIST = &ROUTE->next_hop.value.list;
							ly_err = lyd_new_any(nh_node, ly_uv4mod, "next-hop-list/next-hop", NULL, true, LYD_ANYDATA_STRING, false, &nh_list_node);
							if (ly_err != LY_SUCCESS) {
								SRP_LOG_ERR("unable to create new next-hop-list/next-hop list for the node %s", route_path_buffer);
								goto error_out;
							}
							for (int k = 0; k < NEXTHOP_LIST->size; k++) {
								// next-hop-address
								if (NEXTHOP_LIST->list[k].addr) {
									nl_addr2str(NEXTHOP_LIST->list[k].addr, ip_buffer, sizeof(ip_buffer));
									ly_err = lyd_new_term(nh_list_node, ly_uv4mod, "next-hop-address", ip_buffer, false, &tmp_node);
									if (ly_err != LY_SUCCESS) {
										SRP_LOG_ERR("unable to create next-hop-address leaf in the list for route %s", route_path_buffer);
										goto error_out;
									}

									ly_err = lyd_new_term(nh_list_node, ly_uv4mod, "outgoing-interface", NEXTHOP_LIST->list[k].if_name, false, &tmp_node);
									if (ly_err != LY_SUCCESS) {
										SRP_LOG_ERR("unable to create outgoing-interface leaf in the list for route %s", route_path_buffer);
										goto error_out;
									}
								}
							}
							break;
						}
					}
				}

				// ipv6
				for (int j = 0; j < ipv6_static_routes->size; j++) {
					const struct nl_addr *DST_PREFIX = ipv6_static_routes->list_addr[j];
					const struct route *ROUTE = &ipv6_static_routes->list_route[j].list[0];
					const union route_next_hop_value *NEXTHOP = &ROUTE->next_hop.value;

					// configure prefix
					nl_addr2str(DST_PREFIX, ip_buffer, sizeof(ip_buffer));
					if (strchr(ip_buffer, '/') == NULL) {
						snprintf(prefix_buffer, sizeof(prefix_buffer), "%s/%d", ip_buffer, nl_addr_get_prefixlen(DST_PREFIX));
					} else {
						snprintf(prefix_buffer, sizeof(prefix_buffer), "%s", ip_buffer);
					}

					// create new list node
					snprintf(route_path_buffer, sizeof(route_path_buffer), "route[destination-prefix=\"%s\"]", prefix_buffer);
					ly_err = lyd_new_path(ipv6_container_node, ly_ctx, route_path_buffer, NULL, 0, &route_node);
					if (ly_err != LY_SUCCESS) {
						SRP_LOG_ERR("unable to create a new route node for the list %s", route_path_buffer);
						goto error_out;
					}

					// description
					if (ROUTE->metadata.description != NULL) {
						ly_err = lyd_new_term(route_node, ly_uv6mod, "description", ROUTE->metadata.description, false, &tmp_node);
						if (ly_err != LY_SUCCESS) {
							SRP_LOG_ERR("unable to add description leaf to the %s node", route_path_buffer);
							goto error_out;
						}
					}

					// next-hop container
					ly_err = lyd_new_inner(route_node, ly_uv6mod, "next-hop", false, &nh_node);
					if (ly_err != LY_SUCCESS) {
						SRP_LOG_ERR("unable to create new next-hop container for the node %s", route_path_buffer);
						goto error_out;
					}
					switch (ROUTE->next_hop.kind) {
						case route_next_hop_kind_none:
							break;
						case route_next_hop_kind_simple: {
							// next-hop-address
							if (NEXTHOP->simple.addr) {
								nl_addr2str(NEXTHOP->simple.addr, ip_buffer, sizeof(ip_buffer));
								ly_err = lyd_new_term(nh_node, ly_uv6mod, "next-hop-address", ip_buffer, false, &tmp_node);
								if (ly_err != LY_SUCCESS) {
									SRP_LOG_ERR("unable to create next-hop-address leaf for the node %s", route_path_buffer);
									goto error_out;
								}

								// TODO JURAJ ADD OUTGOING_INTERFACE
							}
							break;
						}
						case route_next_hop_kind_special:
							break;
						case route_next_hop_kind_list: {
							const struct route_next_hop_list *NEXTHOP_LIST = &ROUTE->next_hop.value.list;
							ly_err = lyd_new_any(nh_node, ly_uv6mod, "next-hop-list/next-hop", NULL, true, LYD_ANYDATA_STRING, false, &nh_list_node);
							if (ly_err != LY_SUCCESS) {
								SRP_LOG_ERR("unable to create new next-hop-list/next-hop list for the node %s", route_path_buffer);
								goto error_out;
							}
							for (int k = 0; k < NEXTHOP_LIST->size; k++) {
								// next-hop-address
								if (NEXTHOP_LIST->list[k].addr) {
									nl_addr2str(NEXTHOP_LIST->list[k].addr, ip_buffer, sizeof(ip_buffer));
									ly_err = lyd_new_term(nh_list_node, ly_uv6mod, "next-hop-address", ip_buffer, false, &tmp_node);
									if (ly_err != LY_SUCCESS) {
										SRP_LOG_ERR("unable to create next-hop-address leaf in the list for route %s", route_path_buffer);
										goto error_out;
									}

									// TODO JURAJ ADD OUTGOING_INTERFACE
								}
							}
							break;
						}
					}
				}
			}
		}
	}

	goto out;

error_out:
	SRP_LOG_ERR("error loading initial data for control-plane-procotols container");
	error = 1;
out:
	// free all control plane protocol structs
	for (int i = 0; i < ROUTING_PROTOS_COUNT; i++) {
		control_plane_protocol_free(&cpp_map[i]);
	}

	return error;
}

static int routing_build_rib_descriptions(struct rib_list *ribs)
{
	int error = 0;

	const char *data_dir = NULL;
	struct rib_description_pair default_descriptions[] = {
		{"ipv4-main", "main routing table - normal routing table containing all non-policy routes (ipv4 only)"},
		{"ipv6-main", "main routing table - normal routing table containing all non-policy routes (ipv6 only)"},
		{"ipv4-default", "default routing table - empty and reserved for post-processing if previous default rules did not select the packet (ipv4 only)"},
		{"ipv6-default", "default routing table - empty and reserved for post-processing if previous default rules did not select the packet (ipv6 only)"},
		{"ipv4-local", "local routing table - maintained by the kernel, containing high priority control routes for local and broadcast addresses (ipv4 only)"},
		{"ipv6-local", "local routing table - maintained by the kernel, containing high priority control routes for local and broadcast addresses (ipv6 only)"},
	};
	struct {
		struct rib_description_pair *list;
		int size;
	} rib_descriptions = {0};

	// file stream
	FILE *fptr = NULL;

	// buffers and temporary values
	char path_buffer[PATH_MAX] = {0};
	char line_buffer[PATH_MAX] = {0};
	char name_buffer[32 + 5] = {0};
	struct rib_description_pair tmp_description = {0};

	// get the data_dir variable using getenv
	data_dir = getenv(ROUTING_PLUGIN_DATA_DIR);
	if (data_dir == NULL) {
		SRP_LOG_ERR("unable to use environment variable for the plugin data dir: %s", ROUTING_PLUGIN_DATA_DIR);
		goto error_out;
	}

	// create file path and see if it exists
	snprintf(path_buffer, sizeof(path_buffer), "%s%s%s", data_dir, (data_dir[strlen(data_dir) - 1] == '/') ? "" : "/", ROUTING_RIBS_DESCRIPTIONS_MAP_FNAME);
	SRP_LOG_DBG("RIBs description map file path: %s", path_buffer);

	if (access(path_buffer, F_OK) != 0) {
		// file doesn't exist - use default values and create the file for future use
		fptr = fopen(path_buffer, "w");
		if (fptr == NULL) {
			SRP_LOG_ERR("unable to open %s file for writing", path_buffer);
			goto error_out;
		}

		for (unsigned i = 0; i < sizeof(default_descriptions) / sizeof(default_descriptions[0]); i++) {
			rib_descriptions.list = xrealloc(rib_descriptions.list, sizeof(struct rib_description_pair) * (unsigned) (rib_descriptions.size + 1));
			memcpy(&rib_descriptions.list[rib_descriptions.size], &default_descriptions[i], sizeof(struct rib_description_pair));
			rib_descriptions.size += 1;

			fprintf(fptr, "%s\t\"%s\"\n", default_descriptions[i].name, default_descriptions[i].description);
		}
	} else {
		// file exists - use those values
		fptr = fopen(path_buffer, "r");
		if (fptr == NULL) {
			SRP_LOG_ERR("unable to open file %s", path_buffer);
			goto error_out;
		}

		while (fgets(line_buffer, sizeof(line_buffer), fptr) != NULL) {
			const int read_n = sscanf(line_buffer, "%s \"%256[^\"]\"", tmp_description.name, tmp_description.description);
			if (read_n == 2) {
				// add the description to the list
				rib_descriptions.list = xrealloc(rib_descriptions.list, sizeof(struct rib_description_pair) * (unsigned) (rib_descriptions.size + 1));
				memcpy(&rib_descriptions.list[rib_descriptions.size], &tmp_description, sizeof(struct rib_description_pair));
				rib_descriptions.size += 1;
			} else {
				SRP_LOG_ERR("unable to correctly read 2 values from the RIBs map file");
				goto error_out;
			}
		}
	}

	// now iterate over each rib and set its description
	for (int i = 0; i < ribs->size; i++) {
		const struct rib *RIB = &ribs->list[i];
		const int TABLE_ID = rtnl_route_str2table(RIB->name);

		// for default, local and main add prefixes, for other use given names
		if (routing_is_rib_known(TABLE_ID)) {
			snprintf(name_buffer, sizeof(name_buffer), "%s-%s", RIB->address_family == AF_INET ? "ipv4" : "ipv6", RIB->name);
		} else {
			snprintf(name_buffer, sizeof(name_buffer), "%s", RIB->name);
		}

		const size_t NAME_LEN = strlen(name_buffer);

		// set the description for each AF
		for (int j = 0; j < rib_descriptions.size; j++) {
			const struct rib_description_pair *PAIR = &rib_descriptions.list[j];
			if (strncmp(name_buffer, PAIR->name, NAME_LEN) == 0) {
				memcpy(((struct rib *) RIB)->description, PAIR->description, sizeof(PAIR->description));
				break;
			}
		}
	}

	goto out;

error_out:
	SRP_LOG_ERR("unable to build RIB descriptions");
	error = -1;

out:
	if (fptr != NULL) {
		fclose(fptr);
	}
	FREE_SAFE(rib_descriptions.list);

	return error;
}

static inline int routing_is_rib_known(int table)
{
	return table == RT_TABLE_DEFAULT || table == RT_TABLE_LOCAL || table == RT_TABLE_MAIN;
}

static int routing_build_protos_map(struct control_plane_protocol map[ROUTING_PROTOS_COUNT])
{
	int error = 0;

	// temp variables and buffers
	char *data_dir = NULL;
	char path_buffer[PATH_MAX] = {0};
	char line_buffer[PATH_MAX] = {0};
	int tmp_type = 0;
	char type_buffer[100] = {0};
	char desc_buffer[256] = {0};
	FILE *fptr = NULL;

	data_dir = getenv(ROUTING_PLUGIN_DATA_DIR);
	if (data_dir == NULL) {
		SRP_LOG_ERR("unable to use environment variable for the plugin data dir: %s", ROUTING_PLUGIN_DATA_DIR);
		goto error_out;
	}
	snprintf(path_buffer, sizeof(path_buffer), "%s%s%s", data_dir, (data_dir[strlen(data_dir) - 1] == '/' ? "" : "/"), ROUTING_PROTOS_MAP_FNAME);
	fptr = fopen(path_buffer, "r");
	if (fptr == NULL) {
		SRP_LOG_DBG("protocols map file doesnt exist - using only already known proto types and descriptions");
		// file doesn't exist -> build the initial map and write it to the file
		const char *known_types_map[ROUTING_PROTOS_COUNT] = {
			[RTPROT_UNSPEC] = "ietf-routing:direct",
			[RTPROT_REDIRECT] = "ietf-routing:direct",
			[RTPROT_KERNEL] = "ietf-routing:direct",
			[RTPROT_BOOT] = "ietf-routing:direct",
			[RTPROT_STATIC] = "ietf-routing:static",
			[RTPROT_GATED] = "ietf-routing:direct",
			[RTPROT_RA] = "ietf-routing:direct",
			[RTPROT_MRT] = "ietf-routing:direct",
			[RTPROT_ZEBRA] = "ietf-routing:direct",
			[RTPROT_BIRD] = "ietf-routing:direct",
			[RTPROT_DNROUTED] = "ietf-routing:direct",
			[RTPROT_XORP] = "ietf-routing:direct",
			[RTPROT_NTK] = "ietf-routing:direct",
			[RTPROT_DHCP] = "ietf-routing:direct",
			[RTPROT_MROUTED] = "ietf-routing:direct",
			[RTPROT_BABEL] = "ietf-routing:direct",
			[RTPROT_BGP] = "ietf-routing:direct",
			[RTPROT_ISIS] = "ietf-routing:direct",
			[RTPROT_OSPF] = "ietf-routing:direct",
			[RTPROT_RIP] = "ietf-routing:direct",
			[RTPROT_EIGRP] = "ietf-routing:direct",
		};

		const char *known_descr_map[ROUTING_PROTOS_COUNT] = {
			[RTPROT_UNSPEC] = "unspecified protocol",
			[RTPROT_REDIRECT] = "redirect protocol",
			[RTPROT_KERNEL] = "kernel protocol",
			[RTPROT_BOOT] = "boot protocol",
			[RTPROT_STATIC] = "static protocol",
			[RTPROT_GATED] = "gated protocol",
			[RTPROT_RA] = "ra protocol",
			[RTPROT_MRT] = "mrt protocol",
			[RTPROT_ZEBRA] = "zebra protocol",
			[RTPROT_BIRD] = "bird protocol",
			[RTPROT_DNROUTED] = "dnrouted protocol",
			[RTPROT_XORP] = "xorp protocol",
			[RTPROT_NTK] = "ntk protocol",
			[RTPROT_DHCP] = "dhcp protocol",
			[RTPROT_MROUTED] = "mrouted protocol",
			[RTPROT_BABEL] = "babel protocol",
			[RTPROT_BGP] = "bgp protocol",
			[RTPROT_ISIS] = "isis protocol",
			[RTPROT_OSPF] = "ospf protocol",
			[RTPROT_RIP] = "rip protocol",
			[RTPROT_EIGRP] = "eigrp protocol",
		};

		fptr = fopen(path_buffer, "w");
		if (fptr == NULL) {
			SRP_LOG_ERR("unable to open %s file for writing", ROUTING_PROTOS_MAP_FNAME);
			goto error_out;
		}

		// file opened - write protocol types into the file
		for (int i = 0; i < ROUTING_PROTOS_COUNT; i++) {
			if (routing_is_proto_type_known(i)) {
				rtnl_route_proto2str(i, map[i].name, sizeof(map[i].name));
				map[i].type = xstrdup(known_types_map[i]);
				map[i].description = xstrdup(known_descr_map[i]);
				map[i].initialized = 1;
				fprintf(fptr, "%d\t%s\t\"%s\"\n", i, map[i].type, map[i].description);
			}
		}
	} else {
		SRP_LOG_DBG("protocols map file exists - using map values");
		// file exists -> use map file values
		while (fgets(line_buffer, sizeof(line_buffer), fptr) != NULL) {
			const int read_n = sscanf(line_buffer, "%d %s \"%256[^\"]\"", &tmp_type, type_buffer, desc_buffer);
			if (read_n == 3) {
				if (tmp_type >= 0 && tmp_type <= ROUTING_PROTOS_COUNT) {
					rtnl_route_proto2str(tmp_type, map[tmp_type].name, sizeof(map[tmp_type].name));
					map[tmp_type].type = xstrdup(type_buffer);
					map[tmp_type].description = xstrdup(desc_buffer);
					map[tmp_type].initialized = 1;
				} else {
					SRP_LOG_ERR("invalid protocol type found in the protocol types map file: %d", tmp_type);
					goto error_out;
				}
			} else {
				SRP_LOG_ERR("unable to properly read the protocol types map file format; read %d values", read_n);
				goto error_out;
			}
		}
	}
	goto out;

error_out:
	error = -1;
out:
	if (fptr) {
		fclose(fptr);
	}
	return error;
}

static inline int routing_is_proto_type_known(int type)
{
	return type == RTPROT_UNSPEC ||
		   type == RTPROT_REDIRECT ||
		   type == RTPROT_KERNEL ||
		   type == RTPROT_BOOT ||
		   type == RTPROT_STATIC ||
		   type == RTPROT_GATED ||
		   type == RTPROT_RA ||
		   type == RTPROT_MRT ||
		   type == RTPROT_ZEBRA ||
		   type == RTPROT_BIRD ||
		   type == RTPROT_DNROUTED ||
		   type == RTPROT_XORP ||
		   type == RTPROT_NTK ||
		   type == RTPROT_DHCP ||
		   type == RTPROT_MROUTED ||
		   type == RTPROT_BABEL ||
		   type == RTPROT_BGP ||
		   type == RTPROT_ISIS ||
		   type == RTPROT_OSPF ||
		   type == RTPROT_RIP ||
		   type == RTPROT_EIGRP;
}

static bool routing_running_datastore_is_empty(void)
{
	FILE *sysrepocfg_DS_empty_check = NULL;
	bool is_empty = false;

	sysrepocfg_DS_empty_check = popen(SYSREPOCFG_EMPTY_CHECK_COMMAND, "r");
	if (sysrepocfg_DS_empty_check == NULL) {
		SRP_LOG_WRN("could not execute %s", SYSREPOCFG_EMPTY_CHECK_COMMAND);
		is_empty = true;
		goto out;
	}

	if (fgetc(sysrepocfg_DS_empty_check) == EOF) {
		is_empty = true;
	}

out:
	if (sysrepocfg_DS_empty_check) {
		pclose(sysrepocfg_DS_empty_check);
	}

	return is_empty;
}
