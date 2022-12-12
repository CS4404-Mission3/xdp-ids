#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <stdatomic.h>
#include <bpf_helpers.h>

#define bpf_printk(fmt, ...)						   \
({								                       \
	       char ____fmt[] = fmt;					   \
	       bpf_trace_printk(____fmt, sizeof(____fmt),  \
				##__VA_ARGS__);			               \
})

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifdef __BPF__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif
#endif

SEC("prog")
int xdp_prog_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end) {
        return XDP_DROP;
    }
    if (unlikely(eth->h_proto != htons(ETH_P_IP))) {
        return XDP_PASS;
    }

    struct iphdr *iph = NULL;
    if (eth->h_proto == htons(ETH_P_IP)) {
        iph = (data + sizeof(struct ethhdr));
        if (unlikely(iph + 1 > (struct iphdr *)data_end)) {
            return XDP_DROP;
        }
    } else { // Skip non-IP
        return XDP_PASS;
    }

    // Skip non-UDP
    if (!iph || iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // Parse UDP
    struct udphdr *udph = NULL;
    udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
    if (udph + 1 > (struct udphdr *)data_end) {
        return XDP_DROP;
    }

    // Filters
    if (udph->source == htons(5350) || udph->source == htons(5351) || udph->source == htons(5352) || udph->source == htons(5353) || udph->source == htons(5354) || udph->source == htons(5355) || udph->source == htons(5356) || udph->source == htons(5357)) {
        bpf_printk("Detected C2 packet from %d:%d\n", iph->saddr, ntohs(udph->source));
	return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
