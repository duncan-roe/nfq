/* N F Q 6 */

/* pragmas */

#pragma GCC diagnostic ignored "-Wpointer-sign"

/* Headers */

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <libmnl/libmnl.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>

/* Macros */

#define NUM_TESTS 5

/* If bool is a macro, get rid of it */

#ifdef bool
#undef bool
#undef true
#undef false
#endif

/* Headers */

#include "prototypes.h"
#include "typedefs.h"
#include "logger.h"

/* Typedefs */

struct dnshdr
{
  uint16_t ID;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint8_t RD:1, TC:1, AA:1, Opcode:4, QR:1;
  uint8_t RCODE:4, CD:1, AD:1, Z:1, RA:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
  uint8_t QR:1, Opcode:4, AA:1, TC:1, RD:1;
  uint8_t RA:1, Z:1, AD:1, CD:1, RCODE:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
  uint16_t QDCOUNT;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
};                                 /* struct dnshdr */

/* Static Variables */

static struct mnl_socket *nl;
/* Largest possible packet payload, plus netlink data overhead: */
static char buf[0xffff + 4096];
static char txbuf[sizeof buf];
static struct pkt_buff *pktb;
static bool tests[NUM_TESTS] = { false };
static uint32_t packet_mark;

/* Static prototypes */

static void usage(void);
static int queue_cb(const struct nlmsghdr *nlh, void *data);
static void nfq_send_verdict(int queue_num, uint32_t id, bool accept);
static struct nlmsghdr *nfq_hdr_put(int type, uint32_t queue_num);

/* ********************************** main ********************************** */

int
main(int argc, char *argv[])
{
  struct nlmsghdr *nlh;
  int ret;
  unsigned int portid, queue_num;
  int i;

  while ((i = getopt(argc, argv, "TUht:")) != -1)
  {
    switch (i)
    {
      case 'h':
        usage();
        return 0;

      case 't':
        ret = atoi(optarg);
        if (ret < 0 || ret > NUM_TESTS)
        {
          fprintf(stderr, "Test %d is out of range\n", ret);
          exit(EXIT_FAILURE);
        }                          /* if (ret < 0 || ret > NUM_TESTS) */
        tests[ret] = true;
        break;
    }                              /* switch (i) */
  }                                /* while () */

  if (argc == optind)
  {
    fputs("Missing queue number\n", stderr);
    exit(EXIT_FAILURE);
  }
  queue_num = atoi(argv[optind]);

  setlinebuf(stdout);

/* Initialise current time. If no error now, there never will be */
  if (!get_time_now())
    exit(1);

  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL)
  {
    perror("mnl_socket_open");
    exit(EXIT_FAILURE);
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
  {
    perror("mnl_socket_bind");
    exit(EXIT_FAILURE);
  }
  portid = mnl_socket_get_portid(nl);

  nlh = nfq_hdr_put(NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  nlh = nfq_hdr_put(NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

  if (tests[4])
  {
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS,
      htonl(NFQA_CFG_F_GSO | (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK,
      htonl(NFQA_CFG_F_GSO | (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_send");
      exit(EXIT_FAILURE);
    }
  }                                /* if (tests[4]) */
  else
  {
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (tests[3])
    {
      mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
      mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_FAIL_OPEN));
    }                              /* if (tests[3]) */

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
      perror("mnl_socket_send");
      exit(EXIT_FAILURE);
    }
  }                                /* if (tests[4]) else */

/* ENOBUFS is signalled to userspace when packets were lost
 * on kernel side.  In most cases, userspace isn't interested
 * in this information, so turn it off.
 */
  if (!tests[2])
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

  for (;;)
  {
    ret = mnl_socket_recvfrom(nl, buf, sizeof buf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
      if (errno == ENOBUFS)
        continue;
      exit(EXIT_FAILURE);
    }

    ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
    if (ret < 0)
    {
      perror("mnl_cb_run");
      exit(EXIT_FAILURE);
    }
  }

  mnl_socket_close(nl);

  return 0;
}

/* ******************************* nfq_hdr_put ****************************** */

static struct nlmsghdr *
nfq_hdr_put(int type, uint32_t queue_num)
{
  struct nlmsghdr *nlh = mnl_nlmsg_put_header(txbuf);
  nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
  nlh->nlmsg_flags = NLM_F_REQUEST;

  struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
  nfg->nfgen_family = AF_UNSPEC;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = htons(queue_num);

  return nlh;
}

/* **************************** nfq_send_verdict **************************** */

static void
nfq_send_verdict(int queue_num, uint32_t id, bool accept)
{
  struct nlmsghdr *nlh;
  bool done = false;

  nlh = nfq_hdr_put(NFQNL_MSG_VERDICT, queue_num);

  if (!accept)
  {
    nfq_nlmsg_verdict_put(nlh, id, NF_DROP);
    goto send_verdict;
  }                                /* if (!accept) */

  if (pktb_mangled(pktb))
    nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));

  if (tests[0] && !packet_mark)
  {
    nfq_nlmsg_verdict_put_mark(nlh, 0xbeef);
    nfq_nlmsg_verdict_put(nlh, id, NF_REPEAT);
    done = true;
  }                                /* if (tests[0] */

  if (tests[1] && !done)
  {
    if (packet_mark == 0xfaceb00c)
      nfq_nlmsg_verdict_put(nlh, id, NF_STOP);
    else
    {
      nfq_nlmsg_verdict_put_mark(nlh, 0xfaceb00c);
      nfq_nlmsg_verdict_put(nlh, id, NF_REPEAT);
    }                              /* if (packet_mark == 0xfaceb00c) else */
    done = true;
  }                                /* if (tests[1] && !done) */

  if (!done)
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

send_verdict:
  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }
}

/* ******************************** queue_cb ******************************** */

#ifdef GIVE_UP
#undef GIVE_UP
#endif
#define GIVE_UP(x)\
do {fputs(x, stderr); accept = false; goto send_verdict;} while (0)

static int
queue_cb(const struct nlmsghdr *nlh, void *data)
{
  struct nfqnl_msg_packet_hdr *ph = NULL;
  struct nlattr *attr[NFQA_MAX + 1] = { };
  uint32_t id = 0, skbinfo;
  struct nfgenmsg *nfg;
  uint16_t ulen;
  uint8_t *payload;
  uint8_t *udp_payload;
  bool accept = true;
  struct udphdr *udph;
  struct ip6_hdr *iph;
  char erbuf[4096];
  bool normal = true;              /* Don't print record structure */
  char record_buf[160];
  int nc = 0;
  unsigned int match_offset, match_len, rep_len;
  uint16_t plen;

  if (nfq_nlmsg_parse(nlh, attr) < 0)
  {
    perror("problems parsing");
    return MNL_CB_ERROR;
  }

  nfg = mnl_nlmsg_get_payload(nlh);

  if (attr[NFQA_PACKET_HDR] == NULL)
  {
    fputs("metaheader not set\n", stderr);
    return MNL_CB_ERROR;
  }

  ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

  plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

  payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

  packet_mark = attr[NFQA_MARK] ? ntohl(mnl_attr_get_u32(attr[NFQA_MARK])) : 0;

  skbinfo =
    attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

  if (attr[NFQA_CAP_LEN])
  {
    uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
    if (orig_len != plen)
    {
      nc += snprintf(record_buf, sizeof record_buf, "%s", "truncated ");
      normal = false;
    }                              /* if (orig_len != plen) */
  }

  if (skbinfo & NFQA_SKB_GSO)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc, "%s", "GSO ");
    normal = false;
  }                                /* if (skbinfo & NFQA_SKB_GSO) */

  id = ntohl(ph->packet_id);
  nc += snprintf(record_buf + nc, sizeof record_buf - nc,
    "packet received (id=%u hw=0x%04x hook=%u, payload len %u", id,
    ntohs(ph->hw_protocol), ph->hook, plen);

/*
 * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
 * The application should behave as if the checksums are correct.
 *
 * If these packets are later forwarded/sent out, the checksums will
 * be corrected by kernel/hardware.
 */
  if (skbinfo & NFQA_SKB_CSUMNOTREADY)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc,
      ", checksum not ready");
    if (ntohs(ph->hw_protocol) != ETH_P_IPV6)
      normal = false;
  }                                /* if (skbinfo & NFQA_SKB_CSUMNOTREADY) */
  if (!normal)
  {
    snprintf(record_buf + nc, sizeof record_buf - nc, ")\n");
    LOG("%s", record_buf);
  }                                /* if (!normal) */

/* Copy data to a packet buffer. Allow 255 bytes extra room */
  pktb = pktb_alloc(AF_INET6, payload, plen, 255);
  if (!pktb)
  {
    snprintf(erbuf, sizeof erbuf, "%s. (pktb_alloc)\n", strerror(errno));
    GIVE_UP(erbuf);
  }                                /* if (!pktb) */
  if (!(iph = nfq_ip6_get_hdr(pktb)))
    GIVE_UP("Malformed IPv6\n");
  if (!nfq_ip6_set_transport_header(pktb, iph, IPPROTO_UDP))
    GIVE_UP("No UDP payload found\n");
  if (!(udph = nfq_udp_get_hdr(pktb)))
    GIVE_UP("Packet too short to get UDP header\n");
  if (!(udp_payload = nfq_udp_get_payload(udph, pktb)))
    GIVE_UP("Packet too short to get UDP payload\n");
  ulen = nfq_udp_get_payload_len(udph, pktb);

send_verdict:
  nfq_send_verdict(ntohs(nfg->res_id), id, accept);

  pktb_free(pktb);

  return MNL_CB_OK;
}

/* ********************************** usage ********************************* */

static void
usage(void)
{
/* N.B. Trailing empty comments are there to stop gnu indent joining lines */
  puts("\nUsage: nfq6 [-TUh] [-t <test #>] queue_number\n" /*  */
    "  -T: use TCP (not implemented yet)\n" /*  */
    "  -U: use UDP (default\n"     /*  */
    "  -h: give this help\n"       /*  */
    "  -t <n>: Do test <n>. Tests are:\n" /*  */
    "    0: If packet mark is zero, set it to 0xbeef and give verdict " /*  */
    "NF_REPEAT\n"                  /*  */
    "    1: If packet mark is not 0xfaceb00c, set it to that and give " /*  */
    "verdict NF_REPEAT\n"          /*  */
    "       If packet mark *is* 0xfaceb00c, give verdict NF_STOP\n" /*  */
    "    2: Allow ENOBUFS to happen; treat as harmless when it does\n" /*  */
    "    3: Configure NFQA_CFG_F_FAIL_OPEN\n" /*  */
    "    4: Try OR together attribute values, i.e.\n" /*  */
    "       NFQA_CFG_F_GSO | (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)\n" /*  */
    "   !4: Put 1 or 2 attribute msgs, do 1 send\n" /*  */
    );
}                                  /* static void usage(void) */
