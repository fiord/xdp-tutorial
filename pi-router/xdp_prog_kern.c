/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpu
#define memcpy(dst, src, n) __builtin_memcpy((dest), (src), (n))

SEC("xdp_icmp")
int  xdp_icmp_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
  struct hdr_cursor nh;
	struct ethhdr *eth;
  int eth_type;
  int ip_type;
  int icmp_type;
  struct iphdr *iphdr;
  struct ipv6hdr *ipv6hdr;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */
  
	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
  eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6)) {
    ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
    if (ip_type != IPPROTO_ICMPV6)
      goto out;
  } else if (nh_type == bpf_htons(ETH_P_IP)) {
    ip_type = parse_iphdr(&nh, data_end, &iphdr);
    if (ip_type != IPPROTO_ICMP)
      goto out;
  }

	action = XDP_DROP;
out:
	return action;
}

char _license[] SEC("license") = "GPL";
