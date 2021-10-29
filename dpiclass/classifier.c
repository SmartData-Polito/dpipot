#include "classifier.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif

// #define VERBOSE 1

#define MAX_FLOW_ROOTS_PER_THREAD 32
#define MAX_IDLE_FLOWS_PER_THREAD 8
#define IDLE_SCAN_PERIOD 1000  /* msec */
#define MAX_IDLE_TIME_UDP 1000 /* msec */
#define MAX_IDLE_TIME_TCP 5000 /* msec */

#include <time.h>

static uint32_t flow_id = 0;

enum nDPI_l3_type {
    L3_IP, L3_IP6
};

struct nDPI_flow_info {
    uint32_t flow_id;
    unsigned long long int packets_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;

    enum nDPI_l3_type l3_type;
    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } v4;
        struct {
            uint64_t src[2];
            uint64_t dst[2];
        } v6;
    } ip_tuple;

    unsigned long long int total_l4_data_len;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t is_midstream_flow:1;
    uint8_t flow_fin_ack_seen:1;
    uint8_t flow_ack_seen:1;
    uint8_t detection_completed:1;
    uint8_t tls_client_hello_seen:1;
    uint8_t tls_server_hello_seen:1;
    uint8_t reserved_00:2;
    uint8_t l4_protocol;

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_protocol;

    struct ndpi_flow_struct * ndpi_flow;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;
};


static void ndpi_flow_info_freer(void * const node)
{
    struct nDPI_flow_info * const flow = (struct nDPI_flow_info *)node;

    ndpi_free(flow->ndpi_dst);
    ndpi_free(flow->ndpi_src);
    ndpi_flow_free(flow->ndpi_flow);
    ndpi_free(flow);
}

struct nDPI_workflow * init_workflow()
{
    struct nDPI_workflow * workflow = (struct nDPI_workflow *)ndpi_calloc(1, sizeof(*workflow));

    if (workflow == NULL) {
        return NULL;
    }

    workflow->pcap_handle = NULL;

    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (workflow->ndpi_struct == NULL) {
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_active_flows = 0;
    workflow->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL) {
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL) {
        free_workflow(&workflow);
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    ndpi_finalize_initalization(workflow->ndpi_struct);

    return workflow;
}


static int ip_tuple_to_string(struct nDPI_flow_info const * const flow,
                              char * const src_addr_str, socklen_t src_addr_len,
                              char * const dst_addr_str, socklen_t dst_addr_len)
{
    switch (flow->l3_type) {
        case L3_IP:
            return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src,
                             src_addr_str, src_addr_len) != NULL &&
                   inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst,
                             dst_addr_str, dst_addr_len) != NULL;
        case L3_IP6:
            return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
                             src_addr_str, src_addr_len) != NULL &&
                   inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
                             dst_addr_str, dst_addr_len) != NULL;
    }

    return 0;
}

#ifdef VERBOSE
static void print_packet_info(struct nDPI_workflow const * const workflow,
                              struct pcap_pkthdr const * const header,
                              uint32_t l4_data_len,
                              struct nDPI_flow_info const * const flow)
{
    char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char buf[256];
    int used = 0, ret;

    ret = snprintf(buf, sizeof(buf), "[%8llu, %4u] %4u bytes: ",
                   workflow->packets_captured, flow->flow_id, header->len);
    if (ret > 0) {
        used += ret;
    }

    if (ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) != 0) {
        ret = snprintf(buf + used, sizeof(buf) - used, "IP[%s -> %s]", src_addr_str, dst_addr_str);
    } else {
        ret = snprintf(buf + used, sizeof(buf) - used, "IP[ERROR]");
    }
    if (ret > 0) {
        used += ret;
    }

    switch (flow->l4_protocol) {
        case IPPROTO_UDP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> UDP[%u -> %u, %u bytes]",
                           flow->src_port, flow->dst_port, l4_data_len);
            break;
        case IPPROTO_TCP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> TCP[%u -> %u, %u bytes]",
                           flow->src_port, flow->dst_port, l4_data_len);
            break;
        case IPPROTO_ICMP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP");
            break;
        case IPPROTO_ICMPV6:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP6");
            break;
        case IPPROTO_HOPOPTS:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP6 Hop-By-Hop");
            break;
        default:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> Unknown[0x%X]", flow->l4_protocol);
            break;
    }
    if (ret > 0) {
        used += ret;
    }

    fprintf(stdout, "%.*s\n", used, buf);
}
#endif

static int ip_tuples_equal(struct nDPI_flow_info const * const A,
                           struct nDPI_flow_info const * const B)
{
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
        return A->ip_tuple.v4.src == B->ip_tuple.v4.src &&
               A->ip_tuple.v4.dst == B->ip_tuple.v4.dst;
    } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        return A->ip_tuple.v6.src[0] == B->ip_tuple.v6.src[0] &&
               A->ip_tuple.v6.src[1] == B->ip_tuple.v6.src[1] &&
               A->ip_tuple.v6.dst[0] == B->ip_tuple.v6.dst[0] &&
               A->ip_tuple.v6.dst[1] == B->ip_tuple.v6.dst[1];
    }
    return 0;
}

static int ip_tuples_compare(struct nDPI_flow_info const * const A,
                             struct nDPI_flow_info const * const B)
{
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
        if (A->ip_tuple.v4.src < B->ip_tuple.v4.src ||
            A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
        {
            return -1;
        }
        if (A->ip_tuple.v4.src > B->ip_tuple.v4.src ||
            A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
        {
            return 1;
        }
    } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        if ((A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] &&
             A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] &&
             A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1]))
        {
            return -1;
        }
        if ((A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] &&
             A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] &&
             A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1]))
        {
            return 1;
        }
    }
    if (A->src_port < B->src_port ||
        A->dst_port < B->dst_port)
    {
        return -1;
    } else if (A->src_port > B->src_port ||
               A->dst_port > B->dst_port)
    {
        return 1;
    }
    return 0;
}

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPI_workflow * const workflow = (struct nDPI_workflow *)user_data;
    struct nDPI_flow_info * const flow = *(struct nDPI_flow_info **)A;

    (void)depth;

    if (workflow == NULL || flow == NULL) {
        return;
    }

    if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf) {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            (flow->l4_protocol == IPPROTO_TCP && flow->last_seen + MAX_IDLE_TIME_TCP < workflow->last_time) ||
            (flow->l4_protocol != IPPROTO_TCP && flow->last_seen + MAX_IDLE_TIME_UDP < workflow->last_time)) {

            if((which == ndpi_preorder) || (which == ndpi_leaf)) {
                if((!flow->detection_completed) && flow->ndpi_flow) {

                    u_int8_t proto_guessed;
                    flow->detected_l7_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow, 1, &proto_guessed);
                }
            }

            char src_addr_str[INET6_ADDRSTRLEN+1];
            char dst_addr_str[INET6_ADDRSTRLEN+1];
            ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
            workflow->total_idle_flows++;
        }
    }
}

static int ndpi_workflow_node_cmp(void const * const A, void const * const B) {
    struct nDPI_flow_info const * const flow_info_a = (struct nDPI_flow_info *)A;
    struct nDPI_flow_info const * const flow_info_b = (struct nDPI_flow_info *)B;

    if (flow_info_a->hashval < flow_info_b->hashval) {
        return(-1);
    } else if (flow_info_a->hashval > flow_info_b->hashval) {
        return(1);
    }

    /* Flows have the same hash */
    if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
        return(-1);
    } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
        return(1);
    }

    if (ip_tuples_equal(flow_info_a, flow_info_b) != 0 &&
        flow_info_a->src_port == flow_info_b->src_port &&
        flow_info_a->dst_port == flow_info_b->dst_port)
    {
        return(0);
    }

    return ip_tuples_compare(flow_info_a, flow_info_b);
}

void print_idle_flow(struct nDPI_workflow * const workflow, struct nDPI_flow_info * const flow) {
    // ['first_seen','protocol','src_ip','src_port','dst_ip','dst_port','ndpi_proto']
    char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char buf[256];

    struct timeval ts;
    gettimeofday(&ts, 0);
    uint64_t time_ms = ((uint64_t)ts.tv_sec) * TICK_RESOLUTION + (uint64_t) ts.tv_usec / (1000000 / TICK_RESOLUTION);

    if (ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) != 0) {
        fprintf(stdout, "%lu %lu %d %s %d %s %d %lld %s expired\n",
               time_ms,
               flow->first_seen/1000,
               flow->l4_protocol,
               src_addr_str,
               flow->src_port,
               dst_addr_str,
               flow->dst_port,
               flow->total_l4_data_len,
               ndpi_protocol2name(workflow->ndpi_struct, flow->detected_l7_protocol, buf, sizeof(buf)));
    }

}

void check_for_idle_flows(int dump_all, struct nDPI_workflow * const workflow)
{
    if (dump_all) {
      workflow->last_time = UINT_MAX;
    }

    if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
        for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index) {
            ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

            while (workflow->cur_idle_flows > 0) {
                struct nDPI_flow_info * const f =
                    (struct nDPI_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
                print_idle_flow(workflow, f);
                ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index],
                             ndpi_workflow_node_cmp);
                ndpi_flow_info_freer(f);
                workflow->cur_active_flows--;
            }
        }

        workflow->last_idle_scan_time = workflow->last_time;
    }
}

void free_workflow(struct nDPI_workflow ** const workflow)
{
    struct nDPI_workflow * const w = *workflow;

    if (w == NULL) {
        return;
    }
    check_for_idle_flows(1, w);

    if (w->pcap_handle != NULL) {
        pcap_close(w->pcap_handle);
        w->pcap_handle = NULL;
    }

    if (w->ndpi_struct != NULL) {
        ndpi_exit_detection_module(w->ndpi_struct);
    }
    for(size_t i = 0; i < w->max_active_flows; i++) {
        ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
    }
    ndpi_free(w->ndpi_flows_active);
    ndpi_free(w->ndpi_flows_idle);
    ndpi_free(w);
    *workflow = NULL;
}


char* ndpi_process_packet(struct nDPI_workflow *workflow,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet)
{

    struct nDPI_flow_info flow = {};
    char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};

    void *tree_result;
    struct nDPI_flow_info *flow_to_process;

    int direction_changed = 0;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    size_t hashed_index;

    uint64_t time_ms;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t ip_size;

    const uint8_t * l4_ptr = NULL;
    uint16_t l4_len = 0;

    uint16_t type;

    workflow->packets_captured++;
    time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + (uint64_t)(header->ts.tv_usec / (1000000 / TICK_RESOLUTION));
    workflow->last_time = time_ms;


    /* process datalink layer - always DLT_EN10MB */
    if (header->len < sizeof(struct ndpi_ethhdr)) {
        fprintf(stderr, "%lu [%8llu] Ethernet packet too short - skipping\n", time_ms,
                workflow->packets_captured);
        return NULL;
    }
    ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    type = ntohs(ethernet->h_proto);
    switch (type) {
        case ETH_P_IP: /* IPv4 */
            if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                fprintf(stderr, "%lu [%8llu] IP packet too short - skipping\n", time_ms,
                        workflow->packets_captured);
                return NULL;
            }
            break;
        case ETH_P_IPV6: /* IPV6 */
            if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                fprintf(stderr, "%lu [%8llu] IP6 packet too short - skipping\n", time_ms,
                        workflow->packets_captured);
                return NULL;
            }
            break;
        case ETH_P_ARP: /* ARP */
            return NULL;
        default:
            fprintf(stderr, "%lu [%8llu] Unknown Ethernet packet with type 0x%X - skipping\n", time_ms,
                    workflow->packets_captured, type);
            return NULL;
    }

    if (type == ETH_P_IP) {
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = NULL;
    } else if (type == ETH_P_IPV6) {
        ip = NULL;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    } else {
        fprintf(stderr, "%lu [%8llu] Captured non IPv4/IPv6 packet with type 0x%X - skipping\n", time_ms,
                workflow->packets_captured, type);
        return NULL;
    }
    ip_size = (uint16_t)(header->len - ip_offset);

    if (type == ETH_P_IP && header->len >= ip_offset) {
        if (header->caplen < header->len) {
            fprintf(stderr, "%lu [%8llu] Captured packet size is smaller than packet size: %u < %u\n", time_ms,
                    workflow->packets_captured, header->caplen, header->len);
        }
    }

    /* process layer3 e.g. IPv4 / IPv6 */
    if (ip != NULL && ip->version == 4) {
        if (ip_size < sizeof(*ip)) {
            fprintf(stderr, "%lu [%8llu] Packet smaller than IP4 header length: %u < %zu\n", time_ms,
                    workflow->packets_captured, ip_size, sizeof(*ip));
            return NULL;
        }

        flow.l3_type = L3_IP;
        if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            fprintf(stderr, "%lu [%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n", time_ms,
                    workflow->packets_captured, ip_size - sizeof(*ip));
            return NULL;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;
    } else if (ip6 != NULL) {
        if (ip_size < sizeof(ip6->ip6_hdr)) {
            fprintf(stderr, "%lu [%8llu] Packet smaller than IP6 header length: %u < %zu\n", time_ms,
                    workflow->packets_captured, ip_size, sizeof(ip6->ip6_hdr));
            return NULL;
        }

        flow.l3_type = L3_IP6;
        if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            fprintf(stderr, "%lu [%8llu] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n", time_ms,
                    workflow->packets_captured, ip_size - sizeof(*ip6));
            return NULL;
        }

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
    } else {
        fprintf(stderr, "%lu [%8llu] Non IP/IPv6 protocol detected: 0x%X\n", time_ms,
                workflow->packets_captured, type);
        return NULL;
    }

    /* process layer4 e.g. TCP / UDP */
    if (flow.l4_protocol == IPPROTO_TCP) {
        const struct ndpi_tcphdr * tcp;

        if (header->len < (uint64_t)(l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
            fprintf(stderr, "%lu [%8llu] Malformed TCP packet, packet size smaller than expected\n",
                    time_ms, workflow->packets_captured);
            return NULL;
        }
        tcp = (struct ndpi_tcphdr *)l4_ptr;
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);
    } else if (flow.l4_protocol == IPPROTO_UDP) {
        const struct ndpi_udphdr * udp;

        if (header->len < (uint64_t)(l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
            fprintf(stderr, "%lu [%8llu] Malformed UDP packet, packet size smaller than expected\n",
                    time_ms, workflow->packets_captured);
            return NULL;
        }
        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);
    }

    workflow->packets_processed++;
    workflow->total_l4_data_len += l4_len;

#ifdef VERBOSE
    print_packet_info(workflow, header, l4_len, &flow);
#endif

    check_for_idle_flows(0, workflow);

    /* calculate flow hash for btree find, search(insert) */
    if (flow.l3_type == L3_IP) {
        if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback
        }
    } else if (flow.l3_type == L3_IP6) {
        if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src, &ip6->ip6_dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
            flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
        }
    }
    flow.hashval += (uint64_t)(flow.l4_protocol + flow.src_port + flow.dst_port);

    hashed_index = flow.hashval % workflow->max_active_flows;
    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
    if (tree_result == NULL) {
        /* flow not found in btree: switch src <-> dst and try to find it again */
        uint64_t orig_src_ip[2] = { flow.ip_tuple.v6.src[0], flow.ip_tuple.v6.src[1] };
        uint64_t orig_dst_ip[2] = { flow.ip_tuple.v6.dst[0], flow.ip_tuple.v6.dst[1] };
        uint16_t orig_src_port = flow.src_port;
        uint16_t orig_dst_port = flow.dst_port;

        flow.ip_tuple.v6.src[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.src[1] = orig_dst_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_src_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_src_ip[1];
        flow.src_port = orig_dst_port;
        flow.dst_port = orig_src_port;

        tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
        if (tree_result != NULL) {
            direction_changed = 1;
        }

        flow.ip_tuple.v6.src[0] = orig_src_ip[0];
        flow.ip_tuple.v6.src[1] = orig_src_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_dst_ip[1];
        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if (tree_result == NULL) {
        /* flow still not found, must be new */
        if (workflow->cur_active_flows == workflow->max_active_flows) {
            fprintf(stderr, "%lu [%8llu] max flows to track reached: %llu, idle: %llu\n", time_ms,
                    workflow->packets_captured, workflow->max_active_flows, workflow->cur_idle_flows);
            return NULL;
        }

        flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (flow_to_process == NULL) {
            fprintf(stderr, "%lu [%8llu] Not enough memory for flow info\n", time_ms,
                    workflow->packets_captured);
            return NULL;
        }

        workflow->cur_active_flows++;
        workflow->total_active_flows++;
        memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
        flow_to_process->flow_id = flow_id++;

        flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (flow_to_process->ndpi_flow == NULL) {
            fprintf(stderr, "%lu [%8llu, %4u] Not enough memory for flow struct\n", time_ms,
                    workflow->packets_captured, flow_to_process->flow_id);
            return NULL;
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_src == NULL) {
            fprintf(stderr, "%lu [%8llu, %4u] Not enough memory for src id struct\n", time_ms,
                    workflow->packets_captured, flow_to_process->flow_id);
            return NULL;
        }

        flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_dst == NULL) {
            fprintf(stderr, "%lu [%8llu, %4u] Not enough memory for dst id struct\n", time_ms,
                    workflow->packets_captured, flow_to_process->flow_id);
            return NULL;
        }

        if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL) {
            /* Possible Leak, but should not happen as we'd abort earlier. */
            return NULL;
        }

        ndpi_src = flow_to_process->ndpi_src;
        ndpi_dst = flow_to_process->ndpi_dst;
    } else {
        flow_to_process = *(struct nDPI_flow_info **)tree_result;

        if (direction_changed != 0) {
            ndpi_src = flow_to_process->ndpi_dst;
            ndpi_dst = flow_to_process->ndpi_src;
        } else {
            ndpi_src = flow_to_process->ndpi_src;
            ndpi_dst = flow_to_process->ndpi_dst;
        }
    }

    flow_to_process->packets_processed++;
    flow_to_process->total_l4_data_len += l4_len;
    /* update timestamps, important for timeout handling */
    if (flow_to_process->first_seen == 0) {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
        flow_to_process->flow_fin_ack_seen = 1;
        //printf("[%8llu, %4u] end of flow\n",  workflow->packets_captured, flow_to_process->flow_id);
        return NULL;
    }

    flow_to_process->detected_l7_protocol =
        ndpi_detection_process_packet(workflow->ndpi_struct, flow_to_process->ndpi_flow,
                                      ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
                                      ip_size, time_ms, ndpi_src, ndpi_dst);

    if((!flow_to_process->detection_completed) && flow_to_process->ndpi_flow) {
        u_int8_t proto_guessed;
        flow_to_process->detected_l7_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow_to_process->ndpi_flow, 1, &proto_guessed);
    }

    if (ip_tuple_to_string(flow_to_process, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) != 0) {

        fprintf(stdout, "%lu %lu %d %s %d %s %d %lld prot %s app %s cat %s\n",
              time_ms,
              flow_to_process->first_seen/1000,
              flow_to_process->l4_protocol,
              src_addr_str,
              flow_to_process->src_port,
              dst_addr_str,
              flow_to_process->dst_port,
              flow_to_process->total_l4_data_len,
              ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol),
              ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol),
              ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.category));
        fflush(stdout);
    }
    if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN)
        return ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol);
    else
        return ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol);
}
