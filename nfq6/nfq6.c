/* N F Q 6 */

/* pragmas */

#pragma GCC diagnostic ignored "-Wpointer-sign"

/* System headers */

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/ip.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <sys/resource.h>
#include <libmnl/libmnl.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>

/* Macros */

#define NUM_TESTS 20

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

/* Static Variables */

static struct mnl_socket *nl;
/* Largest possible packet payload, plus netlink data overhead: */
static char buf[0xffff + 4096];
static char pktbuf[sizeof buf];
static struct pkt_buff *pktb;
static bool tests[NUM_TESTS] = { false };
static uint32_t packet_mark;
static int alternate_queue = 0;
static bool quit = false;
static int passes = 0;

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

  while ((i = getopt(argc, argv, "a:hp:t:")) != -1)
  {
    switch (i)
    {
      case 'a':
        alternate_queue = atoi(optarg);
        if (alternate_queue <= 0 || alternate_queue > 0xffff)
        {
          fprintf(stderr, "Alternate queue number %d is out of range\n",
            alternate_queue);
          exit(EXIT_FAILURE);
        }            /* if (alternate_queue <= 0 || alternate_queue > 0xffff) */
        break;

      case 'h':
        usage();
        return 0;

      case 'p':
        passes = atoi(optarg);
        if (passes < 0)
          passes = 0;              /* Finger trouble */
        if (passes)
          tests[6] = true;
        break;

      case 't':
        ret = atoi(optarg);
        if (ret < 0 || ret >= NUM_TESTS)
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

  if (tests[5])
    tests[4] = true;

  if (tests[4] && !alternate_queue)
  {
    fputs("Missing alternate queue number for test 4\n", stderr);
    exit(EXIT_FAILURE);
  }                                /* if (tests[4] && !alternate_queue) */

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

  mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS,
    htonl(NFQA_CFG_F_GSO | (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)));
  mnl_attr_put_u32(nlh, NFQA_CFG_MASK,
    htonl(NFQA_CFG_F_GSO | (tests[3] ? NFQA_CFG_F_FAIL_OPEN : 0)));

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

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
    if (ret < 0 && !(errno == EINTR || tests[14]))
    {
      perror("mnl_cb_run");
      if (errno != EINTR)
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
  struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
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

  if (tests[4] && !done)
  {
    nfq_nlmsg_verdict_put(nlh, id,
      NF_QUEUE_NR(alternate_queue) | (tests[5] ? NF_VERDICT_FLAG_QUEUE_BYPASS :
      0));
    done = true;
  }                                /* if (tests[4] && !done) */

  if (!done)
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

send_verdict:
  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }
  if (quit)
    exit(0);
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
  uint8_t *payload;
  uint8_t *xxp_payload;
  bool accept = true;
  struct udphdr *udph;
  struct tcphdr *tcph;
  struct ip6_hdr *iph;
  char erbuf[4096];
  bool normal = !tests[16];        /* Don't print record structure */
  char record_buf[160];
  int nc = 0;
  uint16_t plen;
  uint8_t *p;
  int (*mangler) (struct pkt_buff *, unsigned int, unsigned int, const char *,
    unsigned int);

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
 * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO or IPv6.
 * The application should behave as if the checksums are correct.
 *
 * If these packets are later forwarded/sent out, the checksums will
 * be corrected by kernel/hardware.
 */
  if (skbinfo & NFQA_SKB_CSUMNOTREADY)
  {
    nc += snprintf(record_buf + nc, sizeof record_buf - nc,
      ", checksum not ready");
    if (ntohs(ph->hw_protocol) != ETH_P_IPV6 || tests[15])
      normal = false;
  }                                /* if (skbinfo & NFQA_SKB_CSUMNOTREADY) */
  if (!normal)
  {
    snprintf(record_buf + nc, sizeof record_buf - nc, ")\n");
    get_time_now();                /* Put here while only 1 LOG call */
    LOG("%s", record_buf);
  }                                /* if (!normal) */

/* Copy data to a packet buffer. Allow 255 bytes extra room */
  if (tests[7])
  {
    if (tests[19])
      pktb = pktb_make_data(AF_INET6, payload, plen, pktbuf + tests[8],
        sizeof pktbuf);
    else
      pktb = pktb_make(AF_INET6, payload, plen, 255, pktbuf + tests[8],
        sizeof pktbuf);
    if (!pktb)
    {
      snprintf(erbuf, sizeof erbuf, "%s. (pktb_make)\n", strerror(errno));
      GIVE_UP(erbuf);
    }                              /* if (!pktb) */
  }                                /* if (tests[7]) */
  else
  {
    if (tests[19])
      pktb = pktb_alloc_data(AF_INET6, payload, plen);
    else
      pktb = pktb_alloc(AF_INET6, payload, plen, 255);
    if (!pktb)
    {
      snprintf(erbuf, sizeof erbuf, "%s. (pktb_alloc)\n", strerror(errno));
      GIVE_UP(erbuf);
    }                              /* if (!pktb) */
  }                                /* if (tests[7]) else */

/* Get timings for pktb_make vs. pktb _alloc if requested */
  if (passes)
  {
    struct rusage usage[2];
    int i;

    i = getrusage(RUSAGE_SELF, usage);
    if (i)
      perror("getrusage");
    if (tests[7])
      if (tests[19])
      {
        for (i = passes; i; i--)
        {
          pktb = pktb_make_data(AF_INET6, payload, plen, pktbuf + tests[8],
            sizeof pktbuf);
          if (!pktb)
          {
            perror("pktb_make");   /* Not expected ever */
            break;
          }                        /* if (!pktb) */
        }                          /* for (i = passes; i; i--) */
      }                            /* if (tests[19]) */
      else
      {
        for (i = passes; i; i--)
        {
          {
            pktb = pktb_make(AF_INET6, payload, plen, 255, pktbuf + tests[8],
              sizeof pktbuf);
            if (!pktb)
            {
              perror("pktb_make"); /* Not expected ever */
              break;
            }                      /* if (!pktb) */
          }                        /* for (i = passes; i; i--) */
        }                          /* if (tests[19]) else */
      }                            /* if (tests[7]) */
    else
    {
      if (tests[19])
      {
        for (i = passes; i; i--)
        {
          pktb_free(pktb);
          pktb = pktb_alloc_data(AF_INET6, payload, plen);
          if (!pktb)
          {
            perror("pktb_alloc");
            break;
          }                        /* if (!pktb) */
        }                          /* for (i = passes; i; i--) */
      }                            /* if (tests[19]) */
      else
      {
        for (i = passes; i; i--)
        {
          pktb_free(pktb);
          pktb = pktb_alloc(AF_INET6, payload, plen, 255);
          if (!pktb)
          {
            perror("pktb_alloc");
            break;
          }                        /* if (!pktb) */
        }                          /* for (i = passes; i; i--) */
      }                            /* if (tests[19]) else */
    }                              /* if (tests[7]) else */
    i = getrusage(RUSAGE_SELF, usage + 1);
    if (i)
      perror("getrusage");
    else
      printf("passes: %d\n   sys: %lg\n  user: %lg\n", passes,
        usage[1].ru_stime.tv_sec + usage[1].ru_stime.tv_usec / 1000000.0 -
        usage[0].ru_stime.tv_sec - usage[0].ru_stime.tv_usec / 1000000.0,
        usage[1].ru_utime.tv_sec + usage[1].ru_utime.tv_usec / 1000000.0 -
        usage[0].ru_utime.tv_sec - usage[0].ru_utime.tv_usec / 1000000.0);
    passes = 0;
  }                                /* if (passes) */

  if (!(iph = nfq_ip6_get_hdr(pktb)))
    GIVE_UP("Malformed IPv6\n");

  if (tests[13])
  {
    mangler = nfq_tcp_mangle_ipv6;
    if (!nfq_ip6_set_transport_header(pktb, iph, IPPROTO_TCP))
      GIVE_UP("No TCP payload found\n");
    if (!(tcph = nfq_tcp_get_hdr(pktb)))
      GIVE_UP("Packet too short to get TCP header\n");
    if (!(xxp_payload = nfq_tcp_get_payload(tcph, pktb)))
      GIVE_UP("Packet too short to get TCP payload\n");
  }                                /* if (tests[13]) */
  else
  {
    mangler = nfq_udp_mangle_ipv6;
    if (!nfq_ip6_set_transport_header(pktb, iph, IPPROTO_UDP))
      GIVE_UP("No UDP payload found\n");
    if (!(udph = nfq_udp_get_hdr(pktb)))
      GIVE_UP("Packet too short to get UDP header\n");
    if (!(xxp_payload = nfq_udp_get_payload(udph, pktb)))
      GIVE_UP("Packet too short to get UDP payload\n");
  }                                /* if (tests[13]) else */

  if (tests[6] && strchr(xxp_payload, 'q'))
  {
    accept = false;                /* Drop this packet */
    quit = true;                   /* Exit after giving verdict */
  }                              /* if (tests[6] && strchr(xxp_payload, 'q')) */

  if (tests[9] && (p = strstr(xxp_payload, "ASD")))
    mangler(pktb, p - xxp_payload, 3, "F", 1);

  if (tests[10] && (p = strstr(xxp_payload, "QWE")))
    mangler(pktb, p - xxp_payload, 3, "RTYUIOP", 7);

  if (tests[11] && (p = strstr(xxp_payload, "ASD")))
    mangler(pktb, p - xxp_payload, 3, "G", 1);

  if (tests[12] && (p = strstr(xxp_payload, "QWE")))
    mangler(pktb, p - xxp_payload, 3, "MNBVCXZ", 7);

  if (tests[17] && (p = strstr(xxp_payload, "ZXC")))
    mangler(pktb, p - xxp_payload, 3, "VBN", 3);

  if (tests[18] && (p = strstr(xxp_payload, "ZXC")))
    mangler(pktb, p - xxp_payload, 3, "VBN", 3);

send_verdict:
  nfq_send_verdict(ntohs(nfg->res_id), id, accept);

  if (!tests[7])
    pktb_free(pktb);

  return MNL_CB_OK;
}

/* ********************************** usage ********************************* */

static void
usage(void)
{
/* N.B. Trailing empty comments are there to stop gnu indent joining lines */
  puts("\nUsage: nfq6 [-a <alt q #>] [-p passes] " /*  */
    "[-t <test #>],... queue_number\n" /*  */
    "       nfq6 -h\n"             /*  */
    "  -a <n>: Alternate queue for test 4\n" /*  */
    "  -h: give this Help and exit\n" /*  */
    "  -p <n>: Time <n> passes of pktb_make() or whatever on the first" /*  */
    " packet.\n"                   /*  */
    "          Forces on t6. It's expected the 2nd packet will be" /*  */
    " \"q\"\n"                     /*  */
    "  -t <n>: do Test <n>. Tests are:\n" /*  */
    "    0: If packet mark is zero, set it to 0xbeef and give verdict " /*  */
    "NF_REPEAT\n"                  /*  */
    "    1: If packet mark is not 0xfaceb00c, set it to that and give " /*  */
    "verdict NF_REPEAT\n"          /*  */
    "       If packet mark *is* 0xfaceb00c, give verdict NF_STOP\n" /*  */
    "    2: Allow ENOBUFS to happen; treat as harmless when it does\n" /*  */
    "    3: Configure NFQA_CFG_F_FAIL_OPEN\n" /*  */
    "    4: Send packets to alternate -a queue\n" /*  */
    "    5: Force on test 4 and specify BYPASS\n" /*  */
    "    6: Exit nfq6 if incoming packet contains 'q'\n" /*  */
    "    7: Use pktb_make()\n"     /*  */
    "    8: Give pktb_make() an odd address\n" /*  */
    "    9: Replace 1st ASD by F\n" /*  */
    "   10: Replace 1st QWE by RTYUIOP\n" /*  */
    "   11: Replace 2nd ASD by G\n" /*  */
    "   12: Replace 2nd QWE by MNBVCXZ\n" /*  */
    "   13: Use TCP\n"             /*  */
    "   14: Report EINTR if we get it\n" /*  */
    "   15: Log netlink packets with no checksum\n" /*  */
    "   16: Log all netlink packets\n" /*  */
    "   17: Replace 1st ZXC by VBN\n" /*  */
    "   18: Replace 2nd ZXC by VBN\n" /*  */
    "   19: Use _data variants of pktb_alloc & pktb_make\n" /*  */
    );
}                                  /* static void usage(void) */
