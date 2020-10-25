/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

static __always_inline int proto_is_vlan(__u16 h_proto) {
  return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
      h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
  int i;
  __u16 h_proto;
  struct vlan_hdr *vlh;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
  vlh = nh->pos;
  h_proto = eth->h_proto;

  #pragma unroll
  for (i = 0; i < VLAN_MAX_DEPTH; i++) {
    if (!proto_is_vlan(h_proto))
      break;

    if (vlh + 1 > data_end)
      break;
    h_proto = vlh->h_vlan_encapsulated_proto;
    vlh++;
  }

  nh->pos = vlh;

	return h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
  struct ipv6hdr *ipv6 = nh->pos;

  if (ipv6 + 1 > data_end)
    return -1;

  nh->pos = ipv6 + 1;
  *ip6hdr = ipv6;

  return ipv6->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
    void *data_end,
    struct iphdr **iphdr) {
  struct iphdr *iph = nh->pos;
  int hdsize;

  if (iph + 1 > data_end)
    return -1;

  hdsize = iph->ihl * 4;
  if (hdsize < sizeof(iph))
    return -1;

  nh->pos += hdsize;
  *iphdr = iph;

  return iph->protocol;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
  struct icmp6hdr *icmp6 =  nh->pos;

  if (icmp6 + 1 > data_end)
    return -1;

  nh->pos = icmp6 + 1;
  *icmp6hdr = icmp6;

  return icmp6->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
    void *data_end,
    struct icmphdr **icmphdr) {
 struct icmphdr *icmp = nh->pos;
 if (icmp + 1 > data_end)
   return -1;

 nh->pos = icmp + 1;
 *icmphdr = icmp;

 return icmp->type;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */
  
  /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6)) {
    /* Assignment additions go below here */
    struct ipv6hdr *ip6;
    nh_type = parse_ip6hdr(&nh, data_end, &ip6);
    if (nh_type != IPPROTO_ICMPV6)
      goto out;

    struct icmp6hdr *icmp6;
    nh_type = parse_icmp6hdr(&nh, data_end, &icmp6);
    // necessary to check
    if (&(icmp6->icmp6_sequence) + sizeof(icmp6->icmp6_sequence) > data_end)
      goto out;
    if (bpf_htons(icmp6->icmp6_sequence) & 1)
      goto out;
  } else if (nh_type == bpf_htons(ETH_P_IP)) {
    struct iphdr *ip;
    nh_type = parse_iphdr(&nh, data_end, &ip);
    if (nh_type != IPPROTO_ICMP)
      goto out;

    struct icmphdr *icmp;
    nh_type = parse_icmphdr(&nh, data_end, &icmp);
    __be16 *sequence = &((icmp->un).echo.sequence);
    
    if (sequence + sizeof(*sequence) > data_end)
      goto out;
    if (bpf_htons(*sequence) & 1)
      goto out;
  }

	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
