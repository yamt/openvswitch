/*
 * Copyright (c) 2007-2013 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/sctp/checksum.h>

#include "datapath.h"
#include "vlan.h"
#include "vport.h"

static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      const struct nlattr *attr, int len, bool keep_skb);

static int make_writable(struct sk_buff *skb, int write_len)
{
	if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))
		return 0;

	return pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}

/* remove VLAN header from packet and update csum accordingly. */
static int __pop_vlan_tci(struct sk_buff *skb, __be16 *current_tci)
{
	struct vlan_hdr *vhdr;
	int err;

	err = make_writable(skb, VLAN_ETH_HLEN);
	if (unlikely(err))
		return err;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));

	vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	*current_tci = vhdr->h_vlan_TCI;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);

	vlan_set_encap_proto(skb, vhdr);
	skb->mac_header += VLAN_HLEN;
	skb_reset_mac_len(skb);

	return 0;
}

static int pop_vlan(struct sk_buff *skb)
{
	__be16 tci;
	int err;

	if (likely(vlan_tx_tag_present(skb))) {
		vlan_set_tci(skb, 0);
	} else {
		if (unlikely(skb->protocol != htons(ETH_P_8021Q) ||
			     skb->len < VLAN_ETH_HLEN))
			return 0;

		err = __pop_vlan_tci(skb, &tci);
		if (err)
			return err;
	}
	/* move next vlan tag to hw accel tag */
	if (likely(skb->protocol != htons(ETH_P_8021Q) ||
		   skb->len < VLAN_ETH_HLEN))
		return 0;

	err = __pop_vlan_tci(skb, &tci);
	if (unlikely(err))
		return err;

	__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), ntohs(tci));
	return 0;
}

static int push_vlan(struct sk_buff *skb, const struct ovs_action_push_vlan *vlan)
{
	if (unlikely(vlan_tx_tag_present(skb))) {
		u16 current_tag;

		/* push down current VLAN tag */
		current_tag = vlan_tx_tag_get(skb);

		if (!__vlan_put_tag(skb, skb->vlan_proto, current_tag))
			return -ENOMEM;

		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->csum = csum_add(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));

	}
	__vlan_hwaccel_put_tag(skb, vlan->vlan_tpid, ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT);
	return 0;
}

/* 'src' is already properly masked. */
static void ether_addr_copy_masked(u8 *dst_, const u8 *src_, const u8 *mask_)
{
	u16 *dst = (u16 *)dst_;
	const u16 *src = (const u16 *)src_;
	const u16 *mask = (const u16 *)mask_;

	dst[0] = src[0] | (dst[0] & ~mask[0]);
	dst[1] = src[1] | (dst[1] & ~mask[1]);
	dst[2] = src[2] | (dst[2] & ~mask[2]);
}

static int set_eth_addr(struct sk_buff *skb,
			const struct ovs_key_ethernet *key)
{
	int err;
	err = make_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);

	ether_addr_copy(eth_hdr(skb)->h_source, key->eth_src);
	ether_addr_copy(eth_hdr(skb)->h_dest, key->eth_dst);

	ovs_skb_postpush_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);
	return 0;
}

static int set_eth_addr_masked(struct sk_buff *skb,
			       const struct ovs_key_ethernet *key,
			       const struct ovs_key_ethernet *mask)
{
	int err;
	err = make_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);

	ether_addr_copy_masked(eth_hdr(skb)->h_source, key->eth_src,
			       mask->eth_src);
	ether_addr_copy_masked(eth_hdr(skb)->h_dest, key->eth_dst,
			       mask->eth_dst);

	ovs_skb_postpush_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);
	return 0;
}

static void set_ip_addr(struct sk_buff *skb, struct iphdr *nh,
			__be32 *addr, __be32 new_addr)
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (nh->protocol == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
						 *addr, new_addr, 1);
	} else if (nh->protocol == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace4(&uh->check, skb,
							 *addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}

	csum_replace4(&nh->check, *addr, new_addr);
	skb_clear_rxhash(skb);
	*addr = new_addr;
}

static void update_ipv6_checksum(struct sk_buff *skb, u8 l4_proto,
				 __be32 addr[4], const __be32 new_addr[4])
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (l4_proto == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace16(&tcp_hdr(skb)->check, skb,
						  addr, new_addr, 1);
	} else if (l4_proto == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace16(&uh->check, skb,
							  addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}
}

static void set_ipv6_addr(struct sk_buff *skb, u8 l4_proto,
			  __be32 addr[4], const __be32 new_addr[4],
			  bool recalculate_csum)
{
	if (likely(recalculate_csum))
		update_ipv6_checksum(skb, l4_proto, addr, new_addr);

	skb_clear_rxhash(skb);
	memcpy(addr, new_addr, sizeof(__be32[4]));
}

static void set_ipv6_tc(struct ipv6hdr *nh, u8 tc, u8 mask)
{
	/* Keep the unmasked bits, if any. */
	if (unlikely(~mask))
		tc |= (nh->priority << 4 | (nh->flow_lbl[0] & 0xF0) >> 4) & ~mask;
	nh->priority = tc >> 4;
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0x0F) | ((tc & 0x0F) << 4);
}

static void set_ipv6_fl(struct ipv6hdr *nh, u32 fl, u32 mask)
{
	/* Keep the unmasked bits, if any. */
	if (unlikely(~mask))
		fl |= ((u32)(nh->flow_lbl[0] & 0x0F) << 16
		       | nh->flow_lbl[1] << 8 | nh->flow_lbl[2]) & ~mask;
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0xF0) | (fl & 0x000F0000) >> 16;
	nh->flow_lbl[1] = (fl & 0x0000FF00) >> 8;
	nh->flow_lbl[2] = fl & 0x000000FF;
}

static void set_ip_ttl(struct sk_buff *skb, struct iphdr *nh, u8 new_ttl)
{
	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

static int set_ipv4(struct sk_buff *skb, const struct ovs_key_ipv4 *key)
{
	struct iphdr *nh;
	int err;

	err = make_writable(skb, skb_network_offset(skb) +
				 sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);

	if (unlikely(key->ipv4_src != nh->saddr))
		set_ip_addr(skb, nh, &nh->saddr, key->ipv4_src);

	if (unlikely(key->ipv4_dst != nh->daddr))
		set_ip_addr(skb, nh, &nh->daddr, key->ipv4_dst);

	if (key->ipv4_tos != nh->tos)
		ipv4_change_dsfield(nh, 0, key->ipv4_tos);

	if (key->ipv4_ttl != nh->ttl)
		set_ip_ttl(skb, nh, key->ipv4_ttl);

	return 0;
}

static int set_ipv4_masked(struct sk_buff *skb, const struct ovs_key_ipv4 *key,
			   const struct ovs_key_ipv4 *mask)
{
	struct iphdr *nh;
	int err;

	err = make_writable(skb, skb_network_offset(skb) +
				 sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);

	if (unlikely(mask->ipv4_src))
		set_ip_addr(skb, nh, &nh->saddr,
			    key->ipv4_src | (nh->saddr & ~mask->ipv4_src));

	if (unlikely(mask->ipv4_dst))
		set_ip_addr(skb, nh, &nh->daddr,
			    key->ipv4_dst | (nh->daddr & ~mask->ipv4_dst));

	if (mask->ipv4_tos)
		ipv4_change_dsfield(nh, 0,
				    key->ipv4_tos | (nh->tos & ~mask->ipv4_tos));

	if (mask->ipv4_ttl)
		set_ip_ttl(skb, nh,
			   key->ipv4_ttl | (nh->ttl & ~mask->ipv4_ttl));

	return 0;
}

static int set_ipv6(struct sk_buff *skb, const struct ovs_key_ipv6 *key)
{
	struct ipv6hdr *nh;
	int err;
	__be32 *saddr;
	__be32 *daddr;

	err = make_writable(skb, skb_network_offset(skb) +
			    sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);
	saddr = (__be32 *)&nh->saddr;
	daddr = (__be32 *)&nh->daddr;

	if (unlikely(memcmp(key->ipv6_src, saddr, sizeof(key->ipv6_src))))
		set_ipv6_addr(skb, key->ipv6_proto, saddr, key->ipv6_src, true);

	if (unlikely(memcmp(key->ipv6_dst, daddr, sizeof(key->ipv6_dst)))) {
		unsigned int offset = 0;
		int flags = OVS_IP6T_FH_F_SKIP_RH;
		bool recalc_csum = true;

		if (ipv6_ext_hdr(nh->nexthdr))
			recalc_csum = ipv6_find_hdr(skb, &offset,
						    NEXTHDR_ROUTING, NULL,
						    &flags) != NEXTHDR_ROUTING;

		set_ipv6_addr(skb, key->ipv6_proto, daddr, key->ipv6_dst,
			      recalc_csum);
	}

	set_ipv6_tc(nh, key->ipv6_tclass, 0xff);
	set_ipv6_fl(nh, ntohl(key->ipv6_label), UINT_MAX);
	nh->hop_limit = key->ipv6_hlimit;

	return 0;
}

static void mask_ipv6_addr(const __be32 old[4], const __be32 addr[4],
			   const __be32 mask[4], __be32 masked[4])
{
	masked[0] = addr[0] | (old[0] & ~mask[0]);
	masked[1] = addr[1] | (old[1] & ~mask[1]);
	masked[2] = addr[2] | (old[2] & ~mask[2]);
	masked[3] = addr[3] | (old[3] & ~mask[3]);
}

static bool is_ipv6_addr_any(const __be32 addr[4])
{
	return !(addr[0] | addr[1] | addr[2] | addr[3]);
}

static int set_ipv6_masked(struct sk_buff *skb, const struct ovs_key_ipv6 *key,
			   const struct ovs_key_ipv6 *mask)
{
	struct ipv6hdr *nh;
	int err;

	err = make_writable(skb, skb_network_offset(skb) +
			    sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);

	if (unlikely(is_ipv6_addr_any(mask->ipv6_src))) {
		__be32 masked[4];
		__be32 *saddr = (__be32 *)&nh->saddr;

		mask_ipv6_addr(saddr, key->ipv6_src, mask->ipv6_src, masked);
		set_ipv6_addr(skb, key->ipv6_proto, saddr, masked, true);
	}
	if (unlikely(is_ipv6_addr_any(mask->ipv6_dst))) {
		__be32 masked[4];
		__be32 *daddr = (__be32 *)&nh->daddr;
		unsigned int offset = 0;
		int flags = OVS_IP6T_FH_F_SKIP_RH;
		bool recalc_csum = true;

		if (ipv6_ext_hdr(nh->nexthdr))
			recalc_csum = ipv6_find_hdr(skb, &offset,
						    NEXTHDR_ROUTING, NULL,
						    &flags) != NEXTHDR_ROUTING;

		mask_ipv6_addr(daddr, key->ipv6_dst, mask->ipv6_dst, masked);
		set_ipv6_addr(skb, key->ipv6_proto, daddr, masked, recalc_csum);
	}
	if (mask->ipv6_tclass)
		set_ipv6_tc(nh, key->ipv6_tclass, mask->ipv6_tclass);
	if (mask->ipv6_label)
		set_ipv6_fl(nh, ntohl(key->ipv6_label), ntohl(mask->ipv6_label));
	nh->hop_limit = key->ipv6_hlimit | (nh->hop_limit & ~mask->ipv6_hlimit);

	return 0;
}

/* Must follow make_writable() since that can move the skb data. */
static void set_tp_port(struct sk_buff *skb, __be16 *port,
			 __be16 new_port, __sum16 *check)
{
	inet_proto_csum_replace2(check, skb, *port, new_port, 0);
	*port = new_port;
	skb_clear_rxhash(skb);
}

static void set_udp_port(struct sk_buff *skb, __be16 *port, __be16 new_port)
{
	struct udphdr *uh = udp_hdr(skb);

	if (uh->check && skb->ip_summed != CHECKSUM_PARTIAL) {
		set_tp_port(skb, port, new_port, &uh->check);

		if (!uh->check)
			uh->check = CSUM_MANGLED_0;
	} else {
		*port = new_port;
		skb_clear_rxhash(skb);
	}
}

static int set_udp(struct sk_buff *skb, const struct ovs_key_udp *key)
{
	struct udphdr *uh;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct udphdr));
	if (unlikely(err))
		return err;

	uh = udp_hdr(skb);

	if (likely(key->udp_src != uh->source))
		set_udp_port(skb, &uh->source, key->udp_src);

	if (likely(key->udp_dst != uh->dest))
		set_udp_port(skb, &uh->dest, key->udp_dst);

	return 0;
}

static int set_udp_masked(struct sk_buff *skb, const struct ovs_key_udp *key,
			  const struct ovs_key_udp *mask)
{
	struct udphdr *uh;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct udphdr));
	if (unlikely(err))
		return err;

	uh = udp_hdr(skb);

	if (likely(mask->udp_src))
		set_udp_port(skb, &uh->source,
			     key->udp_src | (uh->source & ~mask->udp_src));

	if (likely(mask->udp_dst))
		set_udp_port(skb, &uh->dest,
			     key->udp_dst | (uh->dest & ~mask->udp_dst));

	return 0;
}

static int set_tcp(struct sk_buff *skb, const struct ovs_key_tcp *key)
{
	struct tcphdr *th;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);

	if (likely(key->tcp_src != th->source))
		set_tp_port(skb, &th->source, key->tcp_src, &th->check);

	if (likely(key->tcp_dst != th->dest))
		set_tp_port(skb, &th->dest, key->tcp_dst, &th->check);

	return 0;
}

static int set_tcp_masked(struct sk_buff *skb, const struct ovs_key_tcp *key,
			  const struct ovs_key_tcp *mask)
{
	struct tcphdr *th;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);

	if (likely(mask->tcp_src))
		set_tp_port(skb, &th->source,
			    key->tcp_src | (th->source & ~mask->tcp_src),
			    &th->check);

	if (likely(mask->tcp_dst))
		set_tp_port(skb, &th->dest,
			    key->tcp_dst | (th->dest & ~mask->tcp_dst),
			    &th->check);

	return 0;
}

static int set_sctp_ports(struct sk_buff *skb, __be16 src, __be16 dst)
{
	struct sctphdr *sh;
	int err;
	unsigned int sctphoff = skb_transport_offset(skb);
	__le32 old_correct_csum, new_csum, old_csum;

	err = make_writable(skb, sctphoff + sizeof(struct sctphdr));
	if (unlikely(err))
		return err;

	sh = sctp_hdr(skb);

	old_csum = sh->checksum;
	old_correct_csum = sctp_compute_cksum(skb, sctphoff);

	sh->source = src;
	sh->dest = dst;

	new_csum = sctp_compute_cksum(skb, sctphoff);

	/* Carry any checksum errors through. */
	sh->checksum = old_csum ^ old_correct_csum ^ new_csum;

	skb_clear_rxhash(skb);

	return 0;
}

static int set_sctp(struct sk_buff *skb,
		    const struct ovs_key_sctp *key)
{
	return set_sctp_ports(skb, key->sctp_src, key->sctp_dst);
}

static int set_sctp_masked(struct sk_buff *skb,
			   const struct ovs_key_sctp *key,
			   const struct ovs_key_sctp *mask)
{
	struct sctphdr *sh = sctp_hdr(skb);
	return set_sctp_ports(skb,
			      key->sctp_src | (sh->source & ~mask->sctp_src),
			      key->sctp_dst | (sh->dest & ~mask->sctp_dst));
}

static int do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *vport;

	if (unlikely(!skb))
		return -ENOMEM;

	vport = ovs_vport_rcu(dp, out_port);
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return -ENODEV;
	}

	ovs_vport_send(vport, skb);
	return 0;
}

static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    const struct nlattr *attr)
{
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	BUG_ON(!OVS_CB(skb)->pkt_key);

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.key = OVS_CB(skb)->pkt_key;
	upcall.userdata = NULL;
	upcall.portid = 0;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			upcall.portid = nla_get_u32(a);
			break;
		}
	}

	return ovs_dp_upcall(dp, skb, &upcall);
}

static int sample(struct datapath *dp, struct sk_buff *skb,
		  const struct nlattr *attr)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			if (net_random() >= nla_get_u32(a))
				return 0;
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;
			break;
		}
	}

	return do_execute_actions(dp, skb, nla_data(acts_list),
				  nla_len(acts_list), true);
}

static int execute_set_action(struct sk_buff *skb, const struct nlattr *a)
{
	int err = 0;

	switch (nla_type(a)) {
	case OVS_KEY_ATTR_PRIORITY:
		skb->priority = nla_get_u32(a);
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		skb->mark = nla_get_u32(a);
		break;

	case OVS_KEY_ATTR_IPV4_TUNNEL:
		OVS_CB(skb)->tun_key = nla_data(a);
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr(skb, nla_data(a));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4(skb, nla_data(a));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6(skb, nla_data(a));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, nla_data(a));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp(skb, nla_data(a));
		break;

	case OVS_KEY_ATTR_SCTP:
		err = set_sctp(skb, nla_data(a));
		break;
	}

	return err;
}

#define get_mask(a, type) ((const type *)nla_data(a) + 1)

static int execute_masked_set_action(struct sk_buff *skb,
				     const struct nlattr *a)
{
	int err = 0;

	switch (nla_type(a)) {
	case OVS_KEY_ATTR_PRIORITY:
		skb->priority = nla_get_u32(a)
			| (skb->priority & ~*get_mask(a, u32));
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		skb->mark = nla_get_u32(a) | (skb->mark & ~*get_mask(a, u32));
		break;

	case OVS_KEY_ATTR_IPV4_TUNNEL:
		/* Masked data not supported for tunnel. */
		err = -EINVAL;
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr_masked(skb, nla_data(a),
					  get_mask(a, struct ovs_key_ethernet));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4_masked(skb, nla_data(a),
				      get_mask(a, struct ovs_key_ipv4));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6_masked(skb, nla_data(a),
				      get_mask(a, struct ovs_key_ipv6));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp_masked(skb, nla_data(a),
				     get_mask(a, struct ovs_key_tcp));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp_masked(skb, nla_data(a),
				     get_mask(a, struct ovs_key_udp));
		break;

	case OVS_KEY_ATTR_SCTP:
		err = set_sctp_masked(skb, nla_data(a),
				      get_mask(a, struct ovs_key_sctp));
		break;
	}

	return err;
}

/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct nlattr *attr, int len, bool keep_skb)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port = -1;
	const struct nlattr *a;
	int rem;

	for (a = attr, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;

		if (prev_port != -1) {
			do_output(dp, skb_clone(skb, GFP_ATOMIC), prev_port);
			prev_port = -1;
		}

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			output_userspace(dp, skb, a);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, nla_data(a));
			if (unlikely(err)) /* skb already freed. */
				return err;
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb);
			break;

		case OVS_ACTION_ATTR_SET:
			err = execute_set_action(skb, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
			err = execute_masked_set_action(skb, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample(dp, skb, a);
			break;
		}

		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	if (prev_port != -1) {
		if (keep_skb)
			skb = skb_clone(skb, GFP_ATOMIC);

		do_output(dp, skb, prev_port);
	} else if (!keep_skb)
		consume_skb(skb);

	return 0;
}

/* We limit the number of times that we pass into execute_actions()
 * to avoid blowing out the stack in the event that we have a loop. */
#define MAX_LOOPS 4

struct loop_counter {
	u8 count;		/* Count. */
	bool looping;		/* Loop detected? */
};

static DEFINE_PER_CPU(struct loop_counter, loop_counters);

static int loop_suppress(struct datapath *dp, struct sw_flow_actions *actions)
{
	if (net_ratelimit())
		pr_warn("%s: flow looped %d times, dropping\n",
				ovs_dp_name(dp), MAX_LOOPS);
	actions->actions_len = 0;
	return -ELOOP;
}

/* Execute a list of actions against 'skb'. */
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb)
{
	struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
	struct loop_counter *loop;
	int error;

	/* Check whether we've looped too much. */
	loop = &__get_cpu_var(loop_counters);
	if (unlikely(++loop->count > MAX_LOOPS))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		error = loop_suppress(dp, acts);
		kfree_skb(skb);
		goto out_loop;
	}

	OVS_CB(skb)->tun_key = NULL;
	error = do_execute_actions(dp, skb, acts->actions,
					 acts->actions_len, false);

	/* Check whether sub-actions looped too much. */
	if (unlikely(loop->looping))
		error = loop_suppress(dp, acts);

out_loop:
	/* Decrement loop counter. */
	if (!--loop->count)
		loop->looping = false;

	return error;
}
