

/*
 * nameresolver.c — mDNS + LLMNR responder module
 *
 * Self-contained module that responds to mDNS and LLMNR queries
 * for a configurable hostname, resolving to the active adapter IP.
 *
 * Requires: mdns.h from https://github.com/mjansson/mdns
 *
 * Note: Disable systemd-resolved LLMNR if it's running:
 *         Set LLMNR=no in /etc/systemd/resolved.conf
 *         sudo systemctl restart systemd-resolved
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>

#include "mdns.h"
#include "nameresolver.h"

/* ── constants ────────────────────────────────────────────────── */

#define LLMNR_PORT      5355
#define LLMNR_GROUP_V4  "224.0.0.252"

#define DNS_FLAG_QR     0x8000
#define DNS_FLAG_AA     0x0400
#define DNS_TYPE_A      1
#define DNS_TYPE_AAAA   28

#define NR_MAX_SOCKETS  8

/* ── module state ─────────────────────────────────────────────── */

static char nr_mdns_name[270];      /* "hostname.local." */
static char nr_llmnr_name[256];     /* "hostname" */

static char nr_namebuf[256];
static char nr_sendbuf[1024];

static struct sockaddr_in  nr_addr_ipv4;
static struct sockaddr_in6 nr_addr_ipv6;
static int nr_has_ipv4;
static int nr_has_ipv6;

static int  nr_mdns_socks[2];
static int  nr_num_mdns;

static int  nr_llmnr_socks[2];
static int  nr_num_llmnr;

static void *nr_mdns_buffer;
static size_t nr_mdns_capacity = 2048;

/* ── helpers ──────────────────────────────────────────────────── */

static mdns_string_t
nr_ipv4_str(char *buf, size_t cap, const struct sockaddr_in *a, size_t alen)
{
    char host[NI_MAXHOST] = {0};
    getnameinfo((const struct sockaddr *)a, (socklen_t)alen,
                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    int len = snprintf(buf, cap, "%s", host);
    if (len >= (int)cap) len = (int)cap - 1;
    return (mdns_string_t){ buf, (size_t)len };
}

/* nr_ipv6_str intentionally omitted — add back if IPv6 logging is needed */

/* ── address detection ────────────────────────────────────────── */

static void
nr_detect_addresses(void)
{
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) < 0) return;

    int f4 = 1, f6 = 1;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST)) continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT)) continue;

        if (ifa->ifa_addr->sa_family == AF_INET && f4) {
            struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
            if (s->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                nr_addr_ipv4 = *s;
                nr_has_ipv4 = 1;
                f4 = 0;
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6 && f6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)ifa->ifa_addr;
            if (s->sin6_scope_id) continue;
            static const unsigned char lo1[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
            if (memcmp(s->sin6_addr.s6_addr, lo1, 16) == 0) continue;
            nr_addr_ipv6 = *s;
            nr_has_ipv6 = 1;
            f6 = 0;
        }
    }
    freeifaddrs(ifaddr);
}

/* ── mDNS sockets ─────────────────────────────────────────────── */

static int
nr_open_mdns(int *socks, int max)
{
    int n = 0;
    if (n < max) {
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = htons(MDNS_PORT);
        int s = mdns_socket_open_ipv4(&sa);
        if (s >= 0) socks[n++] = s;
    }
    if (n < max) {
        struct sockaddr_in6 sa = {0};
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = in6addr_any;
        sa.sin6_port = htons(MDNS_PORT);
        int s = mdns_socket_open_ipv6(&sa);
        if (s >= 0) socks[n++] = s;
    }
    return n;
}

/* ── mDNS callback ────────────────────────────────────────────── */

static int
nr_mdns_cb(int sock, const struct sockaddr *from, size_t addrlen,
           mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
           uint16_t rclass, uint32_t ttl, const void *data, size_t size,
           size_t name_offset, size_t name_length,
           size_t record_offset, size_t record_length, void *user_data)
{
    (void)ttl; (void)record_offset; (void)record_length;
    (void)user_data; (void)name_length;

    if (entry != MDNS_ENTRYTYPE_QUESTION) return 0;

    size_t off = name_offset;
    mdns_string_t name = mdns_string_extract(data, size, &off,
                                             nr_namebuf, sizeof(nr_namebuf));

    size_t expected = strlen(nr_mdns_name);
    if (name.length != expected) return 0;
    if (strncasecmp(name.str, nr_mdns_name, name.length) != 0) return 0;

    char src[NI_MAXHOST] = {0};
    getnameinfo(from, (socklen_t)addrlen, src, sizeof(src), NULL, 0, NI_NUMERICHOST);
    char ip[64] = "?";
    if (nr_has_ipv4)
        nr_ipv4_str(ip, sizeof(ip), &nr_addr_ipv4, sizeof(nr_addr_ipv4));
    printf("  [mDNS]  %s -> %s  (from %s)\n", nr_mdns_name, ip, src);
    fflush(stdout);

    uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);

    if ((rtype == MDNS_RECORDTYPE_A || rtype == MDNS_RECORDTYPE_ANY) && nr_has_ipv4) {
        mdns_record_t ans = {
            .name = name, .type = MDNS_RECORDTYPE_A,
            .data.a.addr = nr_addr_ipv4, .rclass = 0, .ttl = 0
        };
        if (unicast)
            mdns_query_answer_unicast(sock, from, addrlen,
                                      nr_sendbuf, sizeof(nr_sendbuf),
                                      query_id, rtype, name.str, name.length,
                                      ans, 0, 0, 0, 0);
        else
            mdns_query_answer_multicast(sock, nr_sendbuf, sizeof(nr_sendbuf),
                                        ans, 0, 0, 0, 0);
    }

    if ((rtype == MDNS_RECORDTYPE_AAAA || rtype == MDNS_RECORDTYPE_ANY) && nr_has_ipv6) {
        mdns_record_t ans = {
            .name = name, .type = MDNS_RECORDTYPE_AAAA,
            .data.aaaa.addr = nr_addr_ipv6, .rclass = 0, .ttl = 0
        };
        if (unicast)
            mdns_query_answer_unicast(sock, from, addrlen,
                                      nr_sendbuf, sizeof(nr_sendbuf),
                                      query_id, rtype, name.str, name.length,
                                      ans, 0, 0, 0, 0);
        else
            mdns_query_answer_multicast(sock, nr_sendbuf, sizeof(nr_sendbuf),
                                        ans, 0, 0, 0, 0);
    }

    return 0;
}

/* ── LLMNR sockets ────────────────────────────────────────────── */

static int
nr_open_llmnr(int *socks, int max)
{
    int n = 0;

    /* multicast socket */
    if (n < max) {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s >= 0) {
            unsigned int reuse = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
            setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
            struct ip_mreq mreq = {0};
            inet_pton(AF_INET, LLMNR_GROUP_V4, &mreq.imr_multiaddr);
            mreq.imr_interface.s_addr = INADDR_ANY;
            if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                close(s);
            } else {
                unsigned char ttl = 1, loop = 1;
                setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
                setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

                struct sockaddr_in sa = {0};
                sa.sin_family = AF_INET;
                inet_pton(AF_INET, LLMNR_GROUP_V4, &sa.sin_addr);
                sa.sin_port = htons(LLMNR_PORT);
                if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                    sa.sin_addr.s_addr = INADDR_ANY;
                    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                        close(s); s = -1;
                    }
                }
                if (s >= 0) {
                    int fl = fcntl(s, F_GETFL, 0);
                    fcntl(s, F_SETFL, fl | O_NONBLOCK);
                    socks[n++] = s;
                }
            }
        }
    }

    /* unicast socket */
    if (n < max && nr_has_ipv4) {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s >= 0) {
            unsigned int reuse = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
            setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
            struct sockaddr_in sa = nr_addr_ipv4;
            sa.sin_port = htons(LLMNR_PORT);
            if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                close(s);
            } else {
                int fl = fcntl(s, F_GETFL, 0);
                fcntl(s, F_SETFL, fl | O_NONBLOCK);
                socks[n++] = s;
            }
        }
    }

    return n;
}

/* ── LLMNR wire format helpers ────────────────────────────────── */

static int
nr_dns_decode(const uint8_t *pkt, size_t len, size_t *off, char *out, size_t cap)
{
    size_t pos = *off, op = 0;
    int jumped = 0; size_t end = 0; int maxj = 10;

    while (pos < len && maxj > 0) {
        uint8_t l = pkt[pos];
        if (l == 0) { if (!jumped) end = pos + 1; break; }
        if ((l & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            if (!jumped) end = pos + 2;
            pos = ((l & 0x3F) << 8) | pkt[pos + 1];
            jumped = 1; maxj--; continue;
        }
        pos++;
        if (pos + l > len) return -1;
        if (op > 0 && op < cap) out[op++] = '.';
        for (uint8_t i = 0; i < l && op < cap - 1; i++) out[op++] = pkt[pos + i];
        pos += l;
    }
    if (op < cap) out[op] = '\0';
    if (!jumped) end = pos + 1;
    *off = end;
    return (int)op;
}

static size_t
nr_dns_encode(const char *name, uint8_t *buf, size_t cap)
{
    size_t pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll == 0 || ll > 63 || pos + 1 + ll >= cap) return 0;
        buf[pos++] = (uint8_t)ll;
        memcpy(buf + pos, p, ll);
        pos += ll;
        p += ll;
        if (*p == '.') p++;
    }
    if (pos < cap) buf[pos++] = 0;
    return pos;
}

static void
nr_llmnr_respond(int sock, const struct sockaddr *from, socklen_t flen,
                 uint16_t id, const char *qname, uint16_t qtype, uint16_t qclass)
{
    uint8_t r[512];
    size_t p = 0;

    r[p++] = (id >> 8); r[p++] = id & 0xFF;
    uint16_t fl = DNS_FLAG_QR | DNS_FLAG_AA;
    r[p++] = (fl >> 8); r[p++] = fl & 0xFF;
    r[p++] = 0; r[p++] = 1;
    size_t ac_off = p;
    r[p++] = 0; r[p++] = 0;
    r[p++] = 0; r[p++] = 0;
    r[p++] = 0; r[p++] = 0;

    size_t qn_off = p;
    size_t nl = nr_dns_encode(qname, r + p, sizeof(r) - p);
    if (nl == 0) return;
    p += nl;
    /* need: QTYPE(2) + QCLASS(2) + A answer(16) + AAAA answer(28) = 48 */
    if (p + 48 > sizeof(r)) return;
    r[p++] = (qtype >> 8); r[p++] = qtype & 0xFF;
    r[p++] = (qclass >> 8); r[p++] = qclass & 0xFF;

    uint16_t ac = 0;

    if ((qtype == DNS_TYPE_A || qtype == 255) && nr_has_ipv4) {
        r[p++] = 0xC0 | ((qn_off >> 8) & 0x3F); r[p++] = qn_off & 0xFF;
        r[p++] = 0; r[p++] = DNS_TYPE_A;
        r[p++] = 0; r[p++] = 1;
        r[p++] = 0; r[p++] = 0; r[p++] = 0; r[p++] = 30;
        r[p++] = 0; r[p++] = 4;
        memcpy(r + p, &nr_addr_ipv4.sin_addr, 4); p += 4;
        ac++;
    }
    if ((qtype == DNS_TYPE_AAAA || qtype == 255) && nr_has_ipv6) {
        r[p++] = 0xC0 | ((qn_off >> 8) & 0x3F); r[p++] = qn_off & 0xFF;
        r[p++] = 0; r[p++] = DNS_TYPE_AAAA;
        r[p++] = 0; r[p++] = 1;
        r[p++] = 0; r[p++] = 0; r[p++] = 0; r[p++] = 30;
        r[p++] = 0; r[p++] = 16;
        memcpy(r + p, &nr_addr_ipv6.sin6_addr, 16); p += 16;
        ac++;
    }

    if (ac == 0) return;
    r[ac_off] = (ac >> 8); r[ac_off + 1] = ac & 0xFF;
    sendto(sock, r, p, 0, from, flen);
}

static void
nr_llmnr_handle(int sock, const uint8_t *pkt, size_t len,
                const struct sockaddr *from, socklen_t flen)
{
    if (len < 12) return;

    uint16_t id  = (pkt[0] << 8) | pkt[1];
    uint16_t fl  = (pkt[2] << 8) | pkt[3];
    uint16_t qdc = (pkt[4] << 8) | pkt[5];
    uint16_t anc = (pkt[6] << 8) | pkt[7];
    uint16_t nsc = (pkt[8] << 8) | pkt[9];

    if (fl & DNS_FLAG_QR) return;
    if ((fl >> 11) & 0xF) return;
    if (qdc != 1 || anc != 0 || nsc != 0) return;
    if (fl & 0x0400) return;

    char qname[256] = {0};
    size_t off = 12;
    if (nr_dns_decode(pkt, len, &off, qname, sizeof(qname)) <= 0) return;
    if (off + 4 > len) return;

    uint16_t qt = (pkt[off] << 8) | pkt[off + 1];
    uint16_t qc = (pkt[off + 2] << 8) | pkt[off + 3];
    if (qc != 1 && qc != 255) return;
    if (strcasecmp(qname, nr_llmnr_name) != 0) return;

    char src[NI_MAXHOST] = {0};
    getnameinfo(from, flen, src, sizeof(src), NULL, 0, NI_NUMERICHOST);
    char ip[64] = "?";
    if (nr_has_ipv4)
        nr_ipv4_str(ip, sizeof(ip), &nr_addr_ipv4, sizeof(nr_addr_ipv4));
    printf("  [LLMNR] %s -> %s  (from %s)\n", nr_llmnr_name, ip, src);
    fflush(stdout);

    nr_llmnr_respond(sock, from, flen, id, qname, qt, qc);
}

/* ── public API ───────────────────────────────────────────────── */

int
nr_init(const char *hostname)
{
    /* store names */
    snprintf(nr_llmnr_name, sizeof(nr_llmnr_name), "%s", hostname);
    snprintf(nr_mdns_name, sizeof(nr_mdns_name), "%s.local.", hostname);

    /* detect local addresses */
    nr_detect_addresses();
    if (!nr_has_ipv4 && !nr_has_ipv6) return -1;

    /* open mDNS sockets */
    nr_num_mdns = nr_open_mdns(nr_mdns_socks, 2);

    /* open LLMNR sockets */
    nr_num_llmnr = nr_open_llmnr(nr_llmnr_socks, 2);

    /* allocate mDNS receive buffer */
    nr_mdns_buffer = malloc(nr_mdns_capacity);



    return (nr_num_mdns > 0 || nr_num_llmnr > 0) ? 0 : -1;
}

void
nr_poll(void)
{
    /* Quick non-blocking check on all sockets */
    int nfds = 0;
    fd_set fds;
    FD_ZERO(&fds);

    for (int i = 0; i < nr_num_mdns; i++) {
        if (nr_mdns_socks[i] >= nfds) nfds = nr_mdns_socks[i] + 1;
        FD_SET(nr_mdns_socks[i], &fds);
    }
    for (int i = 0; i < nr_num_llmnr; i++) {
        if (nr_llmnr_socks[i] >= nfds) nfds = nr_llmnr_socks[i] + 1;
        FD_SET(nr_llmnr_socks[i], &fds);
    }

    if (nfds == 0) return;

    struct timeval tv = { .tv_sec = 0, .tv_usec = 0 }; /* non-blocking */
    if (select(nfds, &fds, NULL, NULL, &tv) <= 0) return;

    for (int i = 0; i < nr_num_mdns; i++) {
        if (FD_ISSET(nr_mdns_socks[i], &fds))
            mdns_socket_listen(nr_mdns_socks[i], nr_mdns_buffer, nr_mdns_capacity,
                               nr_mdns_cb, NULL);
    }

    for (int i = 0; i < nr_num_llmnr; i++) {
        if (FD_ISSET(nr_llmnr_socks[i], &fds)) {
            uint8_t buf[9216];
            struct sockaddr_storage from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(nr_llmnr_socks[i], buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &flen);
            if (n > 0)
                nr_llmnr_handle(nr_llmnr_socks[i], buf, (size_t)n,
                                (struct sockaddr *)&from, flen);
        }
    }
}

void
nr_cleanup(void)
{
    for (int i = 0; i < nr_num_mdns; i++)
        mdns_socket_close(nr_mdns_socks[i]);
    for (int i = 0; i < nr_num_llmnr; i++)
        close(nr_llmnr_socks[i]);
    free(nr_mdns_buffer);
    nr_num_mdns = 0;
    nr_num_llmnr = 0;
}


