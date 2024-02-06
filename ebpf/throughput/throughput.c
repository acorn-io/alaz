#include "../headers/bpf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <arpa/inet.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct throughput_event
{
	__u64 timestamp;
	__u32 size;
	__u16 sport;
	__u16 dport;
	__u8  saddr[16];
	__u8  daddr[16];
	__u8  is_ingress;
};

// used for sending throughput events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} throughput_events SEC(".maps");

SEC("classifier")
int packet_classifier(struct __sk_buff *skb) {
	void *data = (void*)(long)skb->data;
	void *data_end = (void*)(long)skb->data_end;

	__u8 is_ingress = 0;
	if (skb->ifindex == skb->ingress_ifindex) {
		is_ingress = 1;
	}

	if (data + sizeof(struct ethhdr) > data_end) {
    	return TC_ACT_UNSPEC;
    }

	// Get the Ethernet header
	struct ethhdr *eth = data;

	if (eth->h_proto == htons(ETH_P_IP)) {
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
			return TC_ACT_UNSPEC;
		}
		struct iphdr *ip = data + sizeof(struct ethhdr);

		struct throughput_event *e = bpf_ringbuf_reserve(&throughput_events, sizeof(struct throughput_event), 0);
		if (!e) {
			return TC_ACT_UNSPEC;
		}

		e->timestamp = bpf_ktime_get_ns();
		e->size = skb->len;
		e->sport = 0;
		e->dport = 0;
		e->is_ingress = is_ingress;
		__builtin_memcpy(&e->saddr, &ip->saddr, sizeof(ip->saddr));
		__builtin_memcpy(&e->daddr, &ip->daddr, sizeof(ip->daddr));

		if (ip->protocol == IPPROTO_TCP) {
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
				bpf_ringbuf_submit(e, 0);
				return TC_ACT_UNSPEC;
			}
			struct tcphdr *tcp = (struct tcphdr*)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));

			e->sport = ntohs(tcp->source);
			e->dport = ntohs(tcp->dest);
		} else if (ip->protocol == IPPROTO_TCP) {
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
				bpf_ringbuf_submit(e, 0);
				return TC_ACT_UNSPEC;
			}
			struct udphdr *udp = (struct udphdr*)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));

			e->sport = ntohs(udp->source);
			e->dport = ntohs(udp->dest);
		}

		bpf_ringbuf_submit(e, 0);
	}

	return TC_ACT_UNSPEC;
}
