// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>

#include <bpf/bpf_helpers.h>
#include <string.h>

struct
{
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  __uint(max_entries, 64); /* Assume netdev has no more than 64 queues */
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
  int index = ctx->rx_queue_index;

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  int pkt_sz = data_end - data;

  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) <= data_end)
  {
    if (eth->h_proto != htons(ETH_P_IP))
    {
      return XDP_PASS;
    }

    void *ip_ptr = (void *)(long)(data + sizeof(struct ethhdr));
    if (ip_ptr + sizeof(struct iphdr) <= data_end)
    {
      struct iphdr *ip = ip_ptr;
      if (ip->protocol != IPPROTO_UDP)
      {
        return XDP_PASS;
      }
      void *udp_ptr = (void *)(long)(ip_ptr + sizeof(struct iphdr));
      if (udp_ptr + sizeof(struct udphdr) <= data_end)
      {
        struct udphdr *udp = udp_ptr;
        if (ntohs(udp->dest) == 7777)
        {
          void *res = bpf_map_lookup_elem(&xsks_map, &index);
//          bpf_printk("udp packet dest: %d, queue: %d, map: %d", ntohs(udp->dest), index, res);
          if (res)
          {
            return bpf_redirect_map(&xsks_map, index, 0);
          }
        }
      }
    }
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual BSD/GPL";