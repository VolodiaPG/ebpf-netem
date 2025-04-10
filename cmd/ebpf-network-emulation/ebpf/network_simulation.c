#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/stddef.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "helpers.h"
#include "maps.h"

/* Adapted from: https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/progs/test_tc_edt.c */

/* the maximum delay we are willing to add (drop packets beyond that) */
#define TIME_HORIZON_NS (2000 * 1000 * 1000)
#define NS_PER_SEC 1000000000
#define ECN_HORIZON_NS 500000000
#define NS_PER_MS 1000000
#define MAX_PERCENTAGE 100

/* flow_key => last_tstamp timestamp used */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 65535);
} flow_map SEC(".maps");

/* Map to store packet counters for loss simulation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 65535);
} packet_counter_map SEC(".maps");

static inline int inject_delay(struct __sk_buff *skb, uint32_t *delay_ms) {
    uint64_t delay_ns;
    uint64_t now = bpf_ktime_get_ns();
    delay_ns = (*delay_ms) * NS_PER_MS;
    uint64_t ts = skb->tstamp;
    uint64_t new_ts = ((uint64_t)skb->tstamp) + delay_ns;

    // sometimes skb-tstamp is reset to 0
    // https://patchwork.kernel.org/project/netdevbpf/patch/20220301053637.930759-1-kafai@fb.com/
    // check if skb->tstamp == 0
    if (ts == 0) {
        skb->tstamp = now + delay_ns;
        return TC_ACT_OK;
    }
    // otherwise add additional delay to packets
    skb->tstamp = new_ts;

    return TC_ACT_OK;
}

/* Simulate packet loss based on loss percentage */
static inline int simulate_packet_loss(struct __sk_buff *skb, __u32 ip_address, uint32_t *loss_percent) {
    // If loss percentage is 0, don't drop any packets
    if (*loss_percent == 0) {
        return TC_ACT_OK;
    }

    // If loss percentage is 100, drop all packets
    if (*loss_percent >= MAX_PERCENTAGE) {
        return TC_ACT_SHOT;
    }

    // Get the packet counter for this IP
    uint64_t *counter = bpf_map_lookup_elem(&packet_counter_map, &ip_address);
    uint64_t pkt_count = 0;

    // If counter exists, increment it, otherwise create it
    if (counter) {
        pkt_count = *counter + 1;
    }

    // Update the counter
    if (bpf_map_update_elem(&packet_counter_map, &ip_address, &pkt_count, BPF_ANY)) {
        // If update fails, default to not dropping
        return TC_ACT_OK;
    }

    // Calculate if we should drop this packet
    // We use modulo to distribute drops evenly
    // For example, if loss_percent is 20, we drop every 5th packet (100/20 = 5)
    if (*loss_percent > 0 && (pkt_count % (MAX_PERCENTAGE / *loss_percent)) == 0) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

/*
 * For some reason section names need to start with "tc"
 * TODO: Remove duplicate header parsing code
 */
SEC("tc2")
int set_delay(struct __sk_buff *skb)
{
    // data_end is a void* to the end of the packet. Needs weird casting due to kernel weirdness.
    void *data_end = (void *)(unsigned long long)skb->data_end;
    // data is a void* to the beginning of the packet. Also needs weird casting.
    void *data = (void *)(unsigned long long)skb->data;

    // nh keeps track of the beginning of the next header to parse
    struct hdr_cursor nh;

    struct ethhdr *eth;
    struct iphdr *iphdr;

    int eth_type;
    int ip_type;

    // start parsing at beginning of data
    nh.pos = data;

    // parse ethernet
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_TCP || ip_type == IPPROTO_UDP) {
            __u32 ip_address = iphdr->daddr; // destination IP, to be used as map lookup key
            __u32 *delay_ms;
            __u32 *loss_percent;
            struct handle_bps_delay *val_struct;
            // Map lookup
            val_struct = bpf_map_lookup_elem(&IP_HANDLE_BPS_DELAY, &ip_address);

            // Safety check, go on if no handle could be retrieved
            if (!val_struct) {
                return TC_ACT_OK;
            }

            delay_ms = &val_struct->delay_ms;
            loss_percent = &val_struct->loss_percent;

            // First check if we should drop this packet due to simulated loss
            if (loss_percent) {
                int loss_result = simulate_packet_loss(skb, ip_address, loss_percent);
                if (loss_result != TC_ACT_OK) {
                    return loss_result;
                }
            }

            // If not dropped, apply delay if configured
            if (delay_ms) {
                return inject_delay(skb, delay_ms);
            }
        }
    }
    return TC_ACT_OK;
}


struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME); // pin map by name (accessible under /sys/fs/bpf/<name>)
	__array(values, int ());
} progs SEC(".maps");

static inline int throttle_flow(struct __sk_buff *skb, __u32 ip_address, uint32_t *throttle_rate_bps)
{
    // use ip as key in map
    int key = ip_address;

    // when was the last packet sent?
    uint64_t *last_tstamp = bpf_map_lookup_elem(&flow_map, &key);
    // calculate delay between packets based on bandwidth and packet size (bps = byte/second)
    uint64_t delay_ns = ((uint64_t)skb->len) * NS_PER_SEC / *throttle_rate_bps;

    uint64_t now = bpf_ktime_get_ns();
    uint64_t tstamp, next_tstamp = 0;

    // calculate the next timestamp
    if (last_tstamp)
        next_tstamp = *last_tstamp + delay_ns;

    // if the current timestamp of the packet is in the past, use the current time
    tstamp = skb->tstamp;
    if (tstamp < now)
        tstamp = now;

    // if the delayed timestamp is already in the past, send the packet
    if (next_tstamp <= tstamp) {
        if (bpf_map_update_elem(&flow_map, &key, &tstamp, BPF_ANY))
            return TC_ACT_SHOT;
        //set additional delay for packet
        bpf_tail_call(skb, &progs, 0);
        return TC_ACT_OK;
    }

    // do not queue for more than 2s, just drop packet instead
    if (next_tstamp - now >= TIME_HORIZON_NS)
        return TC_ACT_SHOT;

    /* set ecn bit, if needed */
    if (next_tstamp - now >= ECN_HORIZON_NS)
        bpf_skb_ecn_set_ce(skb);

    // update last timestamp in map
    if (bpf_map_update_elem(&flow_map, &key, &next_tstamp, BPF_EXIST))
        return TC_ACT_SHOT;

    // set delayed timestamp for packet
    skb->tstamp = next_tstamp;

    //set additional delay for packet
    bpf_tail_call(skb, &progs, 0);

    return TC_ACT_OK;
}

SEC("tc")
int tc_main(struct __sk_buff *skb)
{
    // data_end is a void* to the end of the packet. Needs weird casting due to kernel weirdness.
    void *data_end = (void *)(unsigned long long)skb->data_end;
    // data is a void* to the beginning of the packet. Also needs weird casting.
    void *data = (void *)(unsigned long long)skb->data;

    // nh keeps track of the beginning of the next header to parse
    struct hdr_cursor nh;

    struct ethhdr *eth;
    struct iphdr *iphdr;

    int eth_type;
    int ip_type;

    // start parsing at beginning of data
    nh.pos = data;

    // parse ethernet
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_TCP || ip_type == IPPROTO_UDP) {
            __u32 ip_address = iphdr->daddr; // destination IP, to be used as map lookup key
            __u32 *throttle_rate_bps;
            __u32 *loss_percent;
            struct handle_bps_delay *val_struct;

            // Map lookup
            val_struct = bpf_map_lookup_elem(&IP_HANDLE_BPS_DELAY, &ip_address);

            // Safety check, go on if no handle could be retrieved
            if (!val_struct) {
                return TC_ACT_OK;
            }

            throttle_rate_bps = &val_struct->throttle_rate_bps;
            loss_percent = &val_struct->loss_percent;

            // First check if we should drop this packet due to simulated loss
            if (loss_percent) {
                int loss_result = simulate_packet_loss(skb, ip_address, loss_percent);
                if (loss_result != TC_ACT_OK) {
                    return loss_result;
                }
            }

            // If not dropped and throttling is configured, apply throttling
            if (throttle_rate_bps && *throttle_rate_bps > 0) {
                return throttle_flow(skb, ip_address, throttle_rate_bps);
            }
        }
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
