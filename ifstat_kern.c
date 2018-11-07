#define KBUILD_MODNAME "ifstat"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct pkt_info {
  u16 src_port, dst_port;
  u32 src_ip, dst_ip;
  u8 ipproto;
  u16 pkt_size;
};

enum filter_data_bucket {
  BUCKET_64_BYTES = 0,
  BUCKET_65_127_BYTES,
  BUCKET_128_255_BYTES,
  BUCKET_256_511_BYTES,
  BUCKET_512_1023_BYTES,
  BUCKET_1024_1512_BYTES,
  BUCKET_1513_BYTES,
  BUCKET_BYTES,
  BUCKET_PACKETS,
  BUCKET_LAST
};

static inline void print_ip(u32 ip) {
  // HACK: warning: cannot use more than 3 conversion specifiers
  bpf_trace_printk("  %d.%d.\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF);
  bpf_trace_printk("  %d.%d\n", (ip >> 8) & 0xFF, (ip & 0xFF));
}

static inline void print_filter_result(int num, int result) {
#ifdef DEBUG
  if(!result)
    bpf_trace_printk("FILTER%d_CHECK ok\n", num);
  else
    bpf_trace_printk("FILTER%d_CHECK fail\n", num);
#endif
}

static inline enum filter_data_bucket determine_bucket(u32 pkt_size) {
  if (pkt_size <= 64)
    return BUCKET_64_BYTES;
  else if(pkt_size >= 65 && pkt_size < 127)
    return BUCKET_65_127_BYTES;
  else if(pkt_size >= 128 && pkt_size <= 255)
    return BUCKET_128_255_BYTES;
  else if(pkt_size >= 256 && pkt_size <= 511)
    return BUCKET_256_511_BYTES;
  else if(pkt_size >= 512 && pkt_size <= 1023)
    return BUCKET_512_1023_BYTES;
  else if(pkt_size >= 1024 && pkt_size <= 1512)
    return BUCKET_1024_1512_BYTES;
  else
    return BUCKET_1513_BYTES;
}

static inline ptrdiff_t calc_packet_size(void *start, void *end) {
  // HACK: Валидатор ругается, если получить отрицательное значение в
  // данной функции, поэтому добавляем проверку
  if(end > start)
    return (end - start);
  else
    return (start - end);
}

#define FILTER_BUCKET_VALUE_ADD_FUNC(NUM) \
static inline void filter ## NUM ##_bucket_value_add(int bkt_num, int value) { \
  u64 *ptr = filter ## NUM ##_lookup(bkt_num); \
  if (ptr) \
    (*ptr) += value; \
}

#define FILTER_CHECK_FUNC(NUM, SRC_PORT, DST_PORT, SRC_IP, DST_IP, IPPROTO) \
static inline int filter ## NUM ## _check(struct pkt_info *pkt) { \
  if ((IPPROTO == ANY && pkt->ipproto != IPPROTO_TCP && pkt->ipproto != IPPROTO_UDP) || \
      (IPPROTO != ANY && pkt->ipproto != IPPROTO)) \
    return 1; \
  if ((SRC_IP != ANY && pkt->src_ip != htonl(SRC_IP)) || \
      (DST_IP != ANY && pkt->dst_ip != htonl(DST_IP))) \
    return 1; \
  if ((SRC_PORT != ANY && pkt->src_port != htons(SRC_PORT)) || \
      (DST_PORT != ANY && pkt->dst_port != htons(DST_PORT))) \
    return 1; \
  return 0; \
}

#define FILTER_INIT(NUM) \
  static inline u64 * filter ## NUM ##_lookup(u32 bkt_num); \
  BPF_PERCPU_ARRAY(filter ## NUM, u64, BUCKET_LAST); \
  FILTER_CHECK_FUNC(NUM, FILTER ## NUM ## _SRC_PORT, \
                         FILTER ## NUM ## _DST_PORT, \
			 FILTER ## NUM ## _SRC_IP, \
			 FILTER ## NUM ## _DST_IP, \
			 FILTER ## NUM ## _IPPROTO); \
  FILTER_BUCKET_VALUE_ADD_FUNC(NUM);

// HACK: libbcc не позволяет вызывать <ARRAYNAME>.lookup внутри
// макроса, поэтому приходится писать функции-обёртки а-ля
// filter0_lookup; в противном случае LLVM выдаёт ошибку
//   error: cannot use map function inside a macro

#if FILTER0_ENABLED == 1
  FILTER_INIT(0);

  static inline u64 * filter0_lookup(u32 bkt_num) {
    return filter0.lookup(&bkt_num);
  }
#endif

#if FILTER1_ENABLED == 1
  FILTER_INIT(1);

  static inline u64 * filter1_lookup(u32 bkt_num) {
    return filter1.lookup(&bkt_num);
  }
#endif

#if FILTER2_ENABLED == 1
  FILTER_INIT(2);

  static inline u64 * filter2_lookup(u32 bkt_num) {
    return filter2.lookup(&bkt_num);
  }
#endif

#if FILTER3_ENABLED == 1
  FILTER_INIT(3);

  static inline u64 * filter3_lookup(u32 bkt_num) {
    return filter3.lookup(&bkt_num);
  }
#endif

#if FILTER4_ENABLED == 1
  FILTER_INIT(4);

  static inline u64 * filter4_lookup(u32 bkt_num) {
    return filter4.lookup(&bkt_num);
  }
#endif


#define FILTER_BUCKET_UPDATE(NUM, PKT_INFO) \
  do { \
    filter ## NUM ## _bucket_value_add(determine_bucket(PKT_INFO->pkt_size), 1); \
    filter ## NUM ## _bucket_value_add(BUCKET_PACKETS, 1); \
    filter ## NUM ## _bucket_value_add(BUCKET_BYTES, PKT_INFO->pkt_size); \
  } while(0);

#define FILTER_PROCESS(NUM, PKT_INFO) \
  do { \
    int result = filter ## NUM ## _check(PKT_INFO); \
    print_filter_result(NUM, result); \
    if(!result) \
      FILTER_BUCKET_UPDATE(NUM, PKT_INFO); \
  } while(0);

static inline void parse_ipv4(void *packet, void *packet_end) {
#ifdef DEBUG
  bpf_trace_printk("parse_ipv4 called!\n");
#endif

  const struct iphdr *iph = packet + sizeof(struct ethhdr);
  const struct tcphdr *tcph = packet + sizeof(struct ethhdr) + sizeof(struct iphdr);
  const struct udphdr *udph = packet + sizeof(struct ethhdr) + sizeof(struct iphdr);

  struct pkt_info info;
  struct pkt_info *pkt = &info;

  if (((void *)&iph[1] > packet_end) ||
      ((void *)&udph[1] > packet_end) ||
      ((void *)&tcph[1] > packet_end))
    return;

  pkt->ipproto = iph->protocol;
  if (pkt->ipproto != IPPROTO_TCP && pkt->ipproto != IPPROTO_UDP)
    return;

#ifdef DEBUG
  bpf_trace_printk("ipproto ok!\n");
#endif

  pkt->pkt_size = calc_packet_size(packet, packet_end);
  pkt->src_ip = iph->saddr;
  pkt->dst_ip = iph->daddr;

  if(pkt->ipproto == IPPROTO_TCP) {
    pkt->src_port = tcph->source;
    pkt->dst_port = tcph->dest;
  } else if(pkt->ipproto == IPPROTO_UDP) {
    pkt->src_port = udph->source;
    pkt->dst_port = udph->dest;
  }

#ifdef DEBUG
  bpf_trace_printk("pkt->src_ip = \n");
  print_ip(ntohl(pkt->src_ip));
  bpf_trace_printk("\n");

  bpf_trace_printk("pkt->dst_ip = \n");
  print_ip(ntohl(pkt->dst_ip));
  bpf_trace_printk("\n");

  bpf_trace_printk("pkt->src_port = %u\n", ntohs(pkt->src_port));
  bpf_trace_printk("pkt->dst_port = %u\n", ntohs(pkt->dst_port));
  bpf_trace_printk("pkt->pkt_size = %u\n", pkt->pkt_size);
  bpf_trace_printk("iph->id = %u\n", ntohs(iph->id));
#endif

// Если FILTERx_ENABLED будет равен 0, то FILTER_PROCESS(X, ...)
// выпилится ещё на этапе компиляции. Таким образом, выключенные
// фильтры не будут запущены, что должно положительно влиять на
// производительность

#if FILTER0_ENABLED == 1
  FILTER_PROCESS(0, pkt);
#endif

#if FILTER1_ENABLED == 1
  FILTER_PROCESS(1, pkt);
#endif

#if FILTER2_ENABLED == 1
  FILTER_PROCESS(2, pkt);
#endif

#if FILTER3_ENABLED == 1
  FILTER_PROCESS(3, pkt);
#endif

#if FILTER4_ENABLED == 1
  FILTER_PROCESS(4, pkt);
#endif
}

int packet_handler(struct xdp_md *ctx) {
// HACK: К сожалению, нельзя, чтобы bpf_trace_printk использовался в
// макросах, из-за чего нет возможности избавиться от дублирования
// проверки #ifdef DEBUG ... #endif везде
// __FUNCTION__ тоже нельзя использовать :(

#ifdef DEBUG
  bpf_trace_printk("packet_handler called!\n");
#endif

  void* packet_end = (void*)(long)ctx->data_end;
  void* packet = (void*)(long)ctx->data;

  struct ethhdr *eth = packet;
  if (packet + sizeof(*eth) > packet_end)
    goto out;

  if (eth->h_proto != htons(ETH_P_IP))
    goto out;

  parse_ipv4(packet, packet_end);

out:
  return XDP_PASS;
}
