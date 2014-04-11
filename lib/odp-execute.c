/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 * Copyright (c) 2013 Simon Horman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "odp-execute.h"
#include <linux/openvswitch.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>

#include "dpif.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "odp-util.h"
#include "packets.h"
#include "unaligned.h"
#include "util.h"

/* Masked copy of an ethernet address. 'src' is already properly masked. */
static void
ether_addr_copy_masked(uint8_t *dst, const uint8_t *src,
                       const uint8_t *mask)
{
    int i;

    for (i=0; i < ETH_ADDR_LEN; i++) {
        dst[i] = src[i] | (dst[i] & ~mask[i]);
    }
}

static void
odp_eth_set_addrs(struct ofpbuf *packet, const struct ovs_key_ethernet *key,
                  const struct ovs_key_ethernet *mask)
{
    struct eth_header *eh = ofpbuf_l2(packet);

    if (eh) {
        if (!mask) {
            memcpy(eh->eth_src, key->eth_src, sizeof eh->eth_src);
            memcpy(eh->eth_dst, key->eth_dst, sizeof eh->eth_dst);
        } else {
            ether_addr_copy_masked(eh->eth_src, key->eth_src, mask->eth_src);
            ether_addr_copy_masked(eh->eth_dst, key->eth_dst, mask->eth_dst);
        }
    }
}

static void
odp_set_ipv4(struct ofpbuf *packet, const struct ovs_key_ipv4 *key,
             const struct ovs_key_ipv4 *mask)
{
    struct ip_header *nh = ofpbuf_l3(packet);

    packet_set_ipv4(packet,
                    key->ipv4_src
                    | (get_16aligned_be32(&nh->ip_src) & ~mask->ipv4_src),
                    key->ipv4_dst
                    | (get_16aligned_be32(&nh->ip_dst) & ~mask->ipv4_dst),
                    key->ipv4_tos | (nh->ip_tos & ~mask->ipv4_tos),
                    key->ipv4_ttl | (nh->ip_ttl & ~mask->ipv4_ttl));
}

static const ovs_be32 *
mask_ipv6_addr(const ovs_be16 *old, const ovs_be32 *addr_,
               const ovs_be32 *mask_, ovs_be32 *masked_)
{
    const ovs_be16 *addr = (const ovs_be16 *)addr_;
    const ovs_be16 *mask = (const ovs_be16 *)mask_;
    ovs_be16 *masked = (ovs_be16 *)masked_;

    masked[0] = addr[0] | (old[0] & ~mask[0]);
    masked[1] = addr[1] | (old[1] & ~mask[1]);
    masked[2] = addr[2] | (old[2] & ~mask[2]);
    masked[3] = addr[3] | (old[3] & ~mask[3]);
    masked[4] = addr[4] | (old[4] & ~mask[4]);
    masked[5] = addr[5] | (old[5] & ~mask[5]);
    masked[6] = addr[6] | (old[6] & ~mask[6]);
    masked[7] = addr[7] | (old[7] & ~mask[7]);

    return masked_;
}

static void
odp_set_ipv6(struct ofpbuf *packet, const struct ovs_key_ipv6 *key,
             const struct ovs_key_ipv6 *mask)
{
    struct ovs_16aligned_ip6_hdr *nh = ofpbuf_l3(packet);
    ovs_be32 sbuf[4], dbuf[4];
    uint8_t old_tc = ntohl(get_16aligned_be32(&nh->ip6_flow)) >> 20;
    ovs_be32 old_fl = get_16aligned_be32(&nh->ip6_flow) & htonl(0xfffff);

    packet_set_ipv6(packet, key->ipv6_proto,
                    mask_ipv6_addr((const ovs_be16 *)nh->ip6_src.be32,
                                   key->ipv6_src, mask->ipv6_src, sbuf),
                    mask_ipv6_addr((const ovs_be16 *)nh->ip6_dst.be32,
                                   key->ipv6_dst, mask->ipv6_dst, dbuf),
                    key->ipv6_tclass | (old_tc & ~mask->ipv6_tclass),
                    key->ipv6_label | (old_fl & ~mask->ipv6_label),
                    key->ipv6_hlimit | (nh->ip6_hlim & ~mask->ipv6_hlimit));
}

static void
odp_set_tcp(struct ofpbuf *packet, const struct ovs_key_tcp *key,
             const struct ovs_key_tcp *mask)
{
    struct tcp_header *th = ofpbuf_l4(packet);

    packet_set_tcp_port(packet, key->tcp_src | (th->tcp_src & ~mask->tcp_src),
                        key->tcp_dst | (th->tcp_dst & ~mask->tcp_dst));
}

static void
odp_set_udp(struct ofpbuf *packet, const struct ovs_key_udp *key,
             const struct ovs_key_udp *mask)
{
    struct udp_header *uh = ofpbuf_l4(packet);

    packet_set_udp_port(packet, key->udp_src | (uh->udp_src & ~mask->udp_src),
                        key->udp_dst | (uh->udp_dst & ~mask->udp_dst));
}

static void
odp_set_sctp(struct ofpbuf *packet, const struct ovs_key_sctp *key,
             const struct ovs_key_sctp *mask)
{
    struct sctp_header *sh = ofpbuf_l4(packet);

    packet_set_sctp_port(packet,
                         key->sctp_src | (sh->sctp_src & ~mask->sctp_src),
                         key->sctp_dst | (sh->sctp_dst & ~mask->sctp_dst));
}

static void
odp_set_tunnel_action(const struct nlattr *a, struct flow_tnl *tun_key)
{
    enum odp_key_fitness fitness;

    fitness = odp_tun_key_from_attr(a, tun_key);
    ovs_assert(fitness != ODP_FIT_ERROR);
}

static void
set_arp(struct ofpbuf *packet, const struct ovs_key_arp *key,
        const struct ovs_key_arp *mask)
{
    struct arp_eth_header *arp = ofpbuf_l3(packet);

    if (!mask) {
        arp->ar_op = key->arp_op;
        memcpy(arp->ar_sha, key->arp_sha, ETH_ADDR_LEN);
        put_16aligned_be32(&arp->ar_spa, key->arp_sip);
        memcpy(arp->ar_tha, key->arp_tha, ETH_ADDR_LEN);
        put_16aligned_be32(&arp->ar_tpa, key->arp_tip);
    } else {
        ovs_be32 ar_spa = get_16aligned_be32(&arp->ar_spa);
        ovs_be32 ar_tpa = get_16aligned_be32(&arp->ar_tpa);

        arp->ar_op = key->arp_op | (arp->ar_op & ~mask->arp_op);
        ether_addr_copy_masked(arp->ar_sha, key->arp_sha, mask->arp_sha);
        put_16aligned_be32(&arp->ar_spa,
                           key->arp_sip | (ar_spa & ~mask->arp_sip));
        ether_addr_copy_masked(arp->ar_tha, key->arp_tha, mask->arp_tha);
        put_16aligned_be32(&arp->ar_tpa,
                           key->arp_tip | (ar_tpa & ~mask->arp_tip));
    }
}

#define get_value(a) (const void *)(a + 1)

static void
odp_execute_set_action(struct pkt_metadata *md, struct ofpbuf *packet,
                       const struct nlattr *a)
{
    enum ovs_key_attr type = nl_attr_type(a);
    const struct ovs_key_ipv4 *ipv4_key;
    const struct ovs_key_ipv6 *ipv6_key;
    const struct ovs_key_tcp *tcp_key;
    const struct ovs_key_udp *udp_key;
    const struct ovs_key_sctp *sctp_key;

    switch (type) {
    case OVS_KEY_ATTR_PRIORITY:
        md->skb_priority = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_TUNNEL:
        odp_set_tunnel_action(a, &md->tunnel);
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        md->pkt_mark = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_ETHERNET:
        odp_eth_set_addrs(packet, get_value(a), NULL);
        break;

    case OVS_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
        packet_set_ipv4(packet, ipv4_key->ipv4_src, ipv4_key->ipv4_dst,
                        ipv4_key->ipv4_tos, ipv4_key->ipv4_ttl);
        break;

    case OVS_KEY_ATTR_IPV6:
        ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
        packet_set_ipv6(packet, ipv6_key->ipv6_proto, ipv6_key->ipv6_src,
                        ipv6_key->ipv6_dst, ipv6_key->ipv6_tclass,
                        ipv6_key->ipv6_label, ipv6_key->ipv6_hlimit);
        break;

    case OVS_KEY_ATTR_TCP:
        tcp_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_tcp));
        packet_set_tcp_port(packet, tcp_key->tcp_src, tcp_key->tcp_dst);
        break;

    case OVS_KEY_ATTR_UDP:
        udp_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_udp));
        packet_set_udp_port(packet, udp_key->udp_src, udp_key->udp_dst);
        break;

    case OVS_KEY_ATTR_SCTP:
        sctp_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_sctp));
        packet_set_sctp_port(packet, sctp_key->sctp_src, sctp_key->sctp_dst);
        break;

    case OVS_KEY_ATTR_MPLS:
        set_mpls_lse(packet, nl_attr_get_be32(a));
        break;

    case OVS_KEY_ATTR_ARP:
        set_arp(packet, get_value(a), NULL);
        break;

    case OVS_KEY_ATTR_DP_HASH:
        md->dp_hash = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_RECIRC_ID:
        md->recirc_id = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_ND:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case __OVS_KEY_ATTR_MAX:
    default:
        OVS_NOT_REACHED();
    }
}

#define get_mask(a, type) ((const type *)(const void *)(a + 1) + 1)

static void
odp_execute_masked_set_action(struct pkt_metadata *md, struct ofpbuf *packet,
                              const struct nlattr *a)
{
    enum ovs_key_attr type = nl_attr_type(a);
    struct mpls_hdr *mh;

    switch (type) {
    case OVS_KEY_ATTR_PRIORITY:
        md->skb_priority = nl_attr_get_u32(a)
            | (md->skb_priority & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        md->pkt_mark = nl_attr_get_u32(a)
            | (md->pkt_mark & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_ETHERNET:
        odp_eth_set_addrs(packet, get_value(a),
                          get_mask(a, struct ovs_key_ethernet));
        break;

    case OVS_KEY_ATTR_IPV4:
        odp_set_ipv4(packet, get_value(a), get_mask(a, struct ovs_key_ipv4));
        break;

    case OVS_KEY_ATTR_IPV6:
        odp_set_ipv6(packet, get_value(a), get_mask(a, struct ovs_key_ipv6));
        break;

    case OVS_KEY_ATTR_TCP:
        odp_set_tcp(packet, get_value(a), get_mask(a, struct ovs_key_tcp));
        break;

    case OVS_KEY_ATTR_UDP:
        odp_set_udp(packet, get_value(a), get_mask(a, struct ovs_key_udp));
        break;

    case OVS_KEY_ATTR_SCTP:
        odp_set_sctp(packet, get_value(a), get_mask(a, struct ovs_key_sctp));
        break;

    case OVS_KEY_ATTR_MPLS:
        mh = ofpbuf_l2_5(packet);
        if (mh) {
            put_16aligned_be32(&mh->mpls_lse, nl_attr_get_be32(a)
                               | (get_16aligned_be32(&mh->mpls_lse)
                                  & ~*get_mask(a, ovs_be32)));
        }
        break;

    case OVS_KEY_ATTR_ARP:
        set_arp(packet, get_value(a), get_mask(a, struct ovs_key_arp));
        break;

    case OVS_KEY_ATTR_DP_HASH:
        md->dp_hash = nl_attr_get_u32(a)
            | (md->dp_hash & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_RECIRC_ID:
        md->recirc_id = nl_attr_get_u32(a)
            | (md->recirc_id & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_TUNNEL:    /* Masked data not supported for tunnel. */
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_ND:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case __OVS_KEY_ATTR_MAX:
    default:
        OVS_NOT_REACHED();
    }
}

static void
odp_execute_actions__(void *dp, struct ofpbuf *packet, bool steal,
                      struct pkt_metadata *,
                      const struct nlattr *actions, size_t actions_len,
                      odp_execute_cb dp_execute_action, bool more_actions);

static void
odp_execute_sample(void *dp, struct ofpbuf *packet, bool steal,
                   struct pkt_metadata *md, const struct nlattr *action,
                   odp_execute_cb dp_execute_action, bool more_actions)
{
    const struct nlattr *subactions = NULL;
    const struct nlattr *a;
    size_t left;

    NL_NESTED_FOR_EACH_UNSAFE (a, left, action) {
        int type = nl_attr_type(a);

        switch ((enum ovs_sample_attr) type) {
        case OVS_SAMPLE_ATTR_PROBABILITY:
            if (random_uint32() >= nl_attr_get_u32(a)) {
                return;
            }
            break;

        case OVS_SAMPLE_ATTR_ACTIONS:
            subactions = a;
            break;

        case OVS_SAMPLE_ATTR_UNSPEC:
        case __OVS_SAMPLE_ATTR_MAX:
        default:
            OVS_NOT_REACHED();
        }
    }

    odp_execute_actions__(dp, packet, steal, md, nl_attr_get(subactions),
                          nl_attr_get_size(subactions), dp_execute_action,
                          more_actions);
}

static void
odp_execute_actions__(void *dp, struct ofpbuf *packet, bool steal,
                      struct pkt_metadata *md,
                      const struct nlattr *actions, size_t actions_len,
                      odp_execute_cb dp_execute_action, bool more_actions)
{
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);

        switch ((enum ovs_action_attr) type) {
            /* These only make sense in the context of a datapath. */
        case OVS_ACTION_ATTR_OUTPUT:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_RECIRC:
            if (dp_execute_action) {
                /* Allow 'dp_execute_action' to steal the packet data if we do
                 * not need it any more. */
                bool may_steal = steal && (!more_actions
                                           && left <= NLA_ALIGN(a->nla_len)
                                           && type != OVS_ACTION_ATTR_RECIRC);
                dp_execute_action(dp, packet, md, a, may_steal);
            }
            break;

        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
            eth_push_vlan(packet, htons(ETH_TYPE_VLAN), vlan->vlan_tci);
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
            eth_pop_vlan(packet);
            break;

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);
            push_mpls(packet, mpls->mpls_ethertype, mpls->mpls_lse);
            break;
         }

        case OVS_ACTION_ATTR_POP_MPLS:
            pop_mpls(packet, nl_attr_get_be16(a));
            break;

        case OVS_ACTION_ATTR_SET:
            odp_execute_set_action(md, packet, nl_attr_get(a));
            break;

        case OVS_ACTION_ATTR_SET_MASKED:
            odp_execute_masked_set_action(md, packet, nl_attr_get(a));
            break;

        case OVS_ACTION_ATTR_SAMPLE:
            odp_execute_sample(dp, packet, steal, md, a, dp_execute_action,
                               more_actions || left > NLA_ALIGN(a->nla_len));
            break;

        case OVS_ACTION_ATTR_UNSPEC:
        case __OVS_ACTION_ATTR_MAX:
            OVS_NOT_REACHED();
        }
    }
}

void
odp_execute_actions(void *dp, struct ofpbuf *packet, bool steal,
                    struct pkt_metadata *md,
                    const struct nlattr *actions, size_t actions_len,
                    odp_execute_cb dp_execute_action)
{
    odp_execute_actions__(dp, packet, steal, md, actions, actions_len,
                          dp_execute_action, false);

    if (!actions_len && steal) {
        /* Drop action. */
        ofpbuf_delete(packet);
    }
}
