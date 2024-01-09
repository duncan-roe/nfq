/* N F Q */

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
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>

/* If bool is a macro, get rid of it */

#ifdef bool
#undef bool
#undef true
#undef false
#endif

#include "prototypes.h"
#include "typedefs.h"
#include "chains.h"
#include "uthash.h"
#include "logger.h"

/* Macros */

#define OLD 5                      /* Seconds */

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

struct advert
{
  char *name;
  char *repname;
  UT_hash_handle hh;
};                                 /* struct advert */

/* Static Variables */

static struct mnl_socket *nl;
#include "static_qtypes.h"
/* Largest possible packet payload, plus netlink data overhead: */
static char buf[0xffff + 4096];
static char txbuf[sizeof buf];
static struct pkt_buff *pktb;
static chainbase saved_queries = { &saved_queries, &saved_queries };
static chainbase free_blocks = { &free_blocks, &free_blocks };
static struct advert *ads = NULL;
static struct advert *aa;          /* Temp */

/* Static prototypes */

static void putblk(savedq * sq);
static savedq *getblk(void);
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
  FILE *stream;
  struct advert *a;
  char *p;
  char *q;
  int pos;
  const char *const rcfile = "/etc/nfq.conf";

  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <queue_num>\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  queue_num = atoi(argv[1]);

  setlinebuf(stdout);

/* Initialise current time. If no error now, there never will be */
  if (!get_time_now())
    exit(1);

/* Open and read the list of sites to be diverted */

  if (!(stream = fopen(rcfile, "r")))
  {
    fprintf(stderr, "%s. %s (fopen)\n", strerror(errno), rcfile);
    exit(EXIT_FAILURE);
  }                                /* if (!(stream = fopen(argv[2], "r"))) */
  for (;;)
  {
    if (!fgets(buf, sizeof buf, stream))
      break;                       /* Assume EOF */

    buf[strlen(buf) - 1] = 0;      /* Remove trlg newline */

    if (!(p = strtok(buf, ", ")))
      continue;                    /* Blank line */

    if (*p == '#')
      continue;                    /* Comment */

    HASH_FIND_STR(ads, p, aa);
    if (aa)
    {
      fprintf(stderr, "Ignoring duplicate entry for %s\n", p);
      continue;
    }                              /* if (HASH_FIND_PTR(ads, name, a->name) */

    if (!(a = malloc(sizeof *a)))
    {
      perror("malloc");
      exit(EXIT_FAILURE);
    }                              /* if (!(a = malloc(sizeof *a))) */

    if (!(a->name = malloc(strlen(p) + 1)))
    {
      perror("malloc");
      exit(EXIT_FAILURE);
    }                              /* if (!(a->name = malloc(strlen(p) + 1))) */
    strcpy(a->name, p);

    if (!(p = strtok(NULL, ", ")))
    {
      fprintf(stderr, "No replacement host for %s\n", a->name);
      free(a->name);
      free(a);
      continue;
    }                              /* if (!(p = strtok(buf, ", "))) */

/* 1 char for trlg NUL, 1 char for leading length below */
    ret = strlen(p) + 2;

    if (!(q = strtok(p, ".")))     /* Host simple name - stays in p */
    {
      fprintf(stderr, "No components (?) in hostname \"%s\"\n", p);
      free(a->name);
      free(a);
      continue;
    }                              /* if (!(q = strtok(p, "."))) */

    if (!(q = strtok(NULL, ".")))  /* 1st domain component */
    {
      fprintf(stderr, "only one component in hostname \"%s\"\n", p);
      free(a->name);
      free(a);
      continue;
    }                              /* if (!(q = strtok(p, "."))) */

    if (!(a->repname = malloc(ret)))
    {
      perror("malloc");
      exit(EXIT_FAILURE);
    }                              /* if (!(a->name = malloc(strlen(p) + 1))) */

/* Insert simple host name */

    pos = 0;                      /* Tracks where to put next count or string */
    ret = strlen(p);
    a->repname[pos++] = ret;
    strcpy(&a->repname[pos], p);
    pos += ret;

/* Insert all the domain parts */

    do
    {
      ret = strlen(q);
      a->repname[pos++] = ret;
      strcpy(&a->repname[pos], q);
      pos += ret;
    }
    while ((q = strtok(NULL, ".")));

    HASH_ADD_STR(ads, name, a);
  }                                /* for (;;) */

/* Config file read - continue with netfilter code */

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
  nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  nlh = nfq_hdr_put(NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

  mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
  mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

/* ENOBUFS is signalled to userspace when packets were lost
 * on kernel side.  In most cases, userspace isn't interested
 * in this information, so turn it off.
 */
  mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

  for (;;)
  {
    ret = mnl_socket_recvfrom(nl, buf, sizeof buf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
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

  nlh = nfq_hdr_put(NFQNL_MSG_VERDICT, queue_num);

  if (accept && pktb_mangled(pktb))
    nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
  nfq_nlmsg_verdict_put(nlh, id, accept ? NF_ACCEPT : NF_DROP);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }
}

/* ********************************* putblk ********************************* */

static void
putblk(savedq * sq)
{
  gfechain(sq, &free_blocks);
}                                  /* static void putblk(savedq *sq) */

/* ********************************* getblk ********************************* */

static savedq *
getblk()
{
  savedq *result;
  void *chunk;
  int i;

  if (free_blocks.next != &free_blocks)
  {
    result = gfeunchn(free_blocks.next);
    return result;
  }                                /* if (free_blocks.next != &free_blocks) */

/* Free chain is empty, so may need to malloc more space. */
/* first though, look for old saved queries and return the first we find */

  FOREACHBACK(result, saved_queries) if (time_now - result->stamp > OLD)
    return gfeunchn(result);

  if (free_blocks.next != &free_blocks)
  {
    result = gfeunchn(free_blocks.next);
    return result;
  }                                /* if (free_blocks.next != &free_blocks) */

  if (!(chunk = malloc(8 * sizeof *result)))
  {
    perror("malloc");
    exit(EXIT_FAILURE);
  }                             /* if (!(chunk = malloc(8 * sizeof *result))) */

  for (result = chunk, i = 7; i; ++result, --i)
    putblk(result);

  return result;                   /* (the 8th 1/8th of chunk) */
}                                  /* static savedq *getblk() */

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
  uint16_t qdcount;
  uint16_t dnsid;
  uint16_t qtype;
  uint8_t *payload;
  uint8_t *udp_payload;
  bool accept = true;
  struct udphdr *udph;
  struct iphdr *iph;
  char erbuf[4096];
  int erlen;
  bool normal = true;              /* Don't print record structure */
  char record_buf[160];
  int nc = 0;
  char nambuf[256];
  int namlen;
  uint8_t *label;
  const char *qmsg;                /* Pointer to description of query type */
  char qbuf[16];                   /* Custom query type description */
  char *action = "AC";
  unsigned int match_offset, match_len, rep_len;
  struct dnshdr *dnsh;
  bool response;                   /* Msg is a response */
  struct savedq *sq;
  char *component[128];            /* Enough for a.b.c.d... */
  int num_components;
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
    if (ntohs(ph->hw_protocol) != ETH_P_IP)
      normal = false;
  }                                /* if (skbinfo & NFQA_SKB_CSUMNOTREADY) */
  if (!normal)
  {
    snprintf(record_buf + nc, sizeof record_buf - nc, ")\n");
    LOG("%s", record_buf);
  }                                /* if (!normal) */

/* Copy data to a packet buffer and assemble host name from it */
/* Allow max name length extra room */
  pktb = pktb_alloc(AF_INET, payload, plen, 255);
  if (!pktb)
  {
    snprintf(erbuf, sizeof erbuf, "%s. (pktb_alloc)\n", strerror(errno));
    GIVE_UP(erbuf);
  }                                /* if (!pktb) */
  if (!(iph = nfq_ip_get_hdr(pktb)))
    GIVE_UP("Malformed IPv4\n");
  if (iph->protocol != IPPROTO_UDP)
  {
    snprintf(erbuf, sizeof erbuf, "Protocol %02x is not UDP!\n", iph->protocol);
    GIVE_UP(erbuf);
  }                                /* if (iph->protocol != IPPROTO_UDP) */
  if (nfq_ip_set_transport_header(pktb, iph))
    GIVE_UP("Wrong offset to IPv4 payload\n");
  if (!(udph = nfq_udp_get_hdr(pktb)))
    GIVE_UP("Packet too short to get UDP header\n");
  if (!(udp_payload = nfq_udp_get_payload(udph, pktb)))
    GIVE_UP("Packet too short to get UDP payload\n");
  ulen = nfq_udp_get_payload_len(udph, pktb);
  if (ulen < 19)
    GIVE_UP("UDP payload too short to contain a query\n");
  dnsh = (void *)udp_payload;
  qdcount = ntohs(dnsh->QDCOUNT);
  dnsid = ntohs(dnsh->ID);
  if (qdcount != 1)
  {
    snprintf(erbuf, sizeof erbuf, "ID 0x%04hx: QDCOUNT = %hd\n",
      dnsid, qdcount);
    fputs(erbuf, stderr);
  }                                /* if (qdcount != 1) */
  response = dnsh->QR;
  if (!response && dnsh->AD)
  {
    snprintf(erbuf, sizeof erbuf,
      "AC ID 0x%04hx (Asssumed DIG request)\n", dnsid);
    LOG("%s", erbuf);
    goto send_verdict;
  }                                /* if (!response && dnsh->AD) */
  if (!qdcount)
    GIVE_UP("Zero queries\n");

/* Get first queried name. TODO - cater for > 1 query */
/*                                (but only if we ever see it happen) */

  num_components = erlen = namlen = 0;
  if (qdcount > 1)
    erlen = snprintf(erbuf, sizeof erbuf, "Query 1 of %d: ", qdcount);
  match_offset = sizeof *dnsh;
  label = udp_payload + match_offset;
  for (;;)
  {
    if ((label[0] & 0xc0) == 0xc0)
      label = ((label[0] & 3) << 8) + label[1] + udp_payload;
    else if (label[0] & 0xc0)
    {
      sprintf(erbuf, "Unexpected label length top bits %02x\n",
        label[0] & 0xc0);
      GIVE_UP(erbuf);
    }                              /* else if (label[0] & 0xc0) */
    if (namlen + label[0] + 3 > sizeof nambuf)
      GIVE_UP("Name too long\n");

/* 1st component? */
    if (!num_components)
      component[num_components++] = nambuf;

    memcpy(nambuf + namlen, label + 1, label[0]);
    namlen += label[0];
    label += label[0] + 1;
    if (label[0])
    {
      nambuf[namlen++] = '.';
      component[num_components++] = nambuf + namlen;
    }                              /* if (label[0]) */
    else
    {
      nambuf[namlen] = 0;
      match_len = namlen + 1;      /* +1 for initial count byte */
      break;
    }                              /* if (label[0]) else */
  }                                /* for (::) */

/* Determine query type */

  ++label;
  qtype = (label[0] << 8) + label[1];
  label += 2;
  if (qtype > sizeof qtypes / sizeof *qtypes)
  {
    if (qtype == 32768)
      qmsg = "TA";
    else if (qtype == 32769)
      qmsg = "DLV";
    else
    {
      snprintf(qbuf, sizeof qbuf, "UNREC=%d", qtype);
      qmsg = qbuf;
    }                              /* else */
  }                            /* if (qtype > sizeof qtypes / sizeof *qtypes) */
  else
    qmsg = qtypes[qtype];

  if (qtype != 1 && qtype != 28)   /* Not an A or AAAA request */
/* TODO Logging of non-A pkts is configurable */
    goto send_verdict;

  get_time_now();

/* Examine A queries / responses for possible diversion / reinstatement */

  if (response)
  {
    FOREACH(sq, saved_queries)
    {
      if (dnsid == sq->ID)
      {
        strcpy(nambuf, sq->pname);
        nc = nfq_udp_mangle_ipv4(pktb, match_offset, match_len, sq->NAME,
          rep_len = strlen(sq->NAME));
        if (!nc)
        {
          erlen += snprintf(erbuf + erlen, sizeof erbuf - erlen,
            "nfq_udp_mangle_ipv4 FAIL: ");
          goto log_packet;
        }                          /* if (!nc) */
        action = "RI";
        putblk(sq = gfeunchn(sq));
        break;
      }                            /* if (dnsid == sq->ID) */
    }                              /* FOREACH(sq, saved_queries) */
    if (!strcmp(action, "AC"))
        goto send_verdict;         /* Don't log response to acepted pkt */
  }                                /* if (response) */
  else
  {
    HASH_FIND_STR(ads, nambuf, aa);
    if (!aa)
    {
/* Check for match on last 2 components only */
      if (num_components > 2)
        HASH_FIND_STR(ads, component[num_components - 2], aa);
    }                              /* if (!aa) */
    if (aa)
    {
      sq = getblk();
      strcpy(sq->NAME, udp_payload + match_offset);
      sq->ID = dnsid;
      strcpy(sq->pname, nambuf);
      sq->stamp = time_now;
      nc = nfq_udp_mangle_ipv4(pktb, match_offset, match_len, aa->repname,
        rep_len = strlen(aa->repname));
      if (!nc)
      {
        erlen += snprintf(erbuf + erlen, sizeof erbuf - erlen,
          "nfq_udp_mangle_ipv4 FAIL: ");
        putblk(sq);
        goto log_packet;
      }                            /* if (!nc) */
      action = "DV";
      gfechain(sq, &saved_queries);
    }                              /* (aa) */
  }                                /* if (response) else */

log_packet:
  erlen += snprintf(erbuf + erlen, sizeof erbuf - erlen,
    "%s %02hhx%02hhx %s", action, udp_payload[0], udp_payload[1], nambuf);
  erlen += snprintf(erbuf + erlen, sizeof erbuf - erlen, " %s", qmsg);
  erlen += snprintf(erbuf + erlen, sizeof erbuf - erlen, "%s", "\n");
  LOG("%s", erbuf);

send_verdict:
  nfq_send_verdict(ntohs(nfg->res_id), id, accept);

  pktb_free(pktb);

  return MNL_CB_OK;
}
