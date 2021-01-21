/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpu
#define memcpy(dst, src, n) __builtin_memcpy((dest), (src), (n))
#endif

SEC("xdp_target")
int  xdp_target_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
  struct hdr_cursor nh;
	struct ethhdr *eth;
  int eth_type;
  int ip_type;
  struct iphdr *iphdr;
  // struct ipv6hdr *ipv6hdr;
  const uint32_t ignore_addr = (203u << 24) | (178u << 16) | (135u << 8) | 112u;

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
	if (eth_type == bpf_htons(ETH_P_IPV6)) {
    goto out;
  } else if (eth_type == bpf_htons(ETH_P_IP)) {
    ip_type = parse_iphdr(&nh, data_end, &iphdr);
    if (iphdr->saddr != ignore_addr && iphdr->daddr != ignore_addr)
      goto out;
  }

	action = XDP_DROP;
out:
	return action;
}

char _license[] SEC("license") = "GPL";
