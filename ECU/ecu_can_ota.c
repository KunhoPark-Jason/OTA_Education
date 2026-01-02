// ecu_can_ota.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

static const uint8_t START_MARK[8] = {0xff,0x00,0xff,0x00,0xff,0x00,0xff,0x00};
static const uint8_t END_MARK[8]   = {0x00,0xff,0x00,0xff,0x00,0xff,0x00,0xff};

// ECU별 pre-shared key (실무에선 안전한 저장소/HSM에 넣어야 함)
static const uint8_t ECU_KEY[] = "A12_shared_secret_32bytes_min________"; // 예시

static int open_can(const char *ifname) {
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { perror("socket"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); close(s); return -1; }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); close(s); return -1; }
    return s;
}

static int can_send8(int s, uint16_t can_id, const uint8_t data[8]) {
    struct can_frame f;
    memset(&f, 0, sizeof(f));
    f.can_id = can_id;
    f.can_dlc = 8;
    memcpy(f.data, data, 8);
    int n = write(s, &f, sizeof(f));
    return (n == sizeof(f)) ? 0 : -1;
}

static int can_read(int s, struct can_frame *out) {
    int n = read(s, out, sizeof(*out));
    return (n == sizeof(*out)) ? 0 : -1;
}

static int read_serial8_from_txt(const char *path, uint8_t out8[8]) {
    // txt 파일에는 16 hex (예: 0000000000000000) 한 줄이 있다고 가정
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char buf[256];
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); return -1; }
    fclose(fp);

    // 공백/개행 제거
    for (int i=0; buf[i]; i++) {
        if (buf[i]=='\n' || buf[i]=='\r' || buf[i]==' ' || buf[i]=='\t') { buf[i]=0; break; }
    }
    // 길이 보정
    if (strlen(buf) < 16) return -1;

    for (int i=0; i<8; i++) {
        char hx[3] = { buf[i*2], buf[i*2+1], 0 };
        out8[i] = (uint8_t)strtoul(hx, NULL, 16);
    }
    return 0;
}

static int is_mark(const uint8_t a[8], const uint8_t b[8]) {
    return memcmp(a, b, 8) == 0;
}

// START~END로 들어오는 스트림을 모아서 버퍼로 반환
static int recv_stream(int s, uint16_t can_id, uint8_t **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    int in = 0;

    uint8_t *buf = NULL;
    size_t cap = 0, len = 0;

    while (1) {
        struct can_frame f;
        if (can_read(s, &f) != 0) continue;
        if ((f.can_id & 0x7FF) != can_id) continue;
        if (f.can_dlc != 8) continue;

        if (!in) {
            if (is_mark(f.data, START_MARK)) {
                in = 1;
                len = 0;
            }
            continue;
        } else {
            if (is_mark(f.data, END_MARK)) {
                *out = buf;
                *out_len = len;
                return 0;
            }
            if (len + 8 > cap) {
                size_t ncap = (cap == 0) ? 256 : cap * 2;
                while (ncap < len + 8) ncap *= 2;
                uint8_t *nb = (uint8_t*)realloc(buf, ncap);
                if (!nb) { free(buf); return -1; }
                buf = nb;
                cap = ncap;
            }
            memcpy(buf + len, f.data, 8);
            len += 8;
        }
    }
}

//static void sha256_bytes(const uint8_t *data, size_t n, uint8_t out[32]) {
//    SHA256_CTX ctx;
//    SHA256_Init(&ctx);
//    SHA256_Update(&ctx, data, n);
//    SHA256_Final(out, &ctx);
//}

static void sha256_bytes(const uint8_t *data, size_t n, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        memset(out, 0, 32);
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, n) != 1) {
        fprintf(stderr, "EVP_DigestInit/Update failed\n");
        EVP_MD_CTX_free(ctx);
        memset(out, 0, 32);
        return;
    }

    unsigned int outlen = 0;
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1 || outlen != 32) {
        fprintf(stderr, "EVP_DigestFinal failed\n");
        memset(out, 0, 32);
    }

    EVP_MD_CTX_free(ctx);
}

static void hmac_token(const uint8_t *ota_hash32, const uint8_t *vg_hash32,
                       const char *ecu_id, const uint8_t *nonce16,
                       uint8_t out32[32]) {
    uint8_t msg[32+32+64+16];
    size_t off = 0;

    memcpy(msg+off, ota_hash32, 32); off += 32;
    memcpy(msg+off, vg_hash32, 32); off += 32;

    size_t idlen = strlen(ecu_id);
    memcpy(msg+off, ecu_id, idlen); off += idlen;

    memcpy(msg+off, nonce16, 16); off += 16;

    unsigned int outlen = 0;
    HMAC(EVP_sha256(), ECU_KEY, (int)strlen((const char*)ECU_KEY), msg, off, out32, &outlen);
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s <can_if> <ECU_ID> <ECU_ADDR_HEX> <serial_txt> <out_bin>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *ECU_ID = argv[2];
    int addr = (int)strtol(argv[3], NULL, 0);
    const char *serial_txt = argv[4];
    const char *out_bin = argv[5];

    uint16_t ATT_REQ  = 0x600 + addr;
    uint16_t ATT_RESP = 0x650 + addr;
    uint16_t META_ID  = 0x700 + addr;
    uint16_t TOKEN_ID = 0x710 + addr;
    uint16_t OTA_ID   = 0x720 + addr;
    uint16_t ACK_ID   = 0x730 + addr;

    int s = open_can(ifname);
    if (s < 0) return 1;

    uint8_t nonce16[16]={0}, ota_hash32[32]={0}, vg_hash32[32]={0};
    int have_meta = 0;
    int token_ok = 0;

    while (1) {
        struct can_frame f;
        if (can_read(s, &f) != 0) continue;
        uint16_t id = (uint16_t)(f.can_id & 0x7FF);

        // 1) Attestation request
        if (id == ATT_REQ && f.can_dlc == 8 && f.data[0] == 0xA1) {
            uint8_t serial8[8];
            if (read_serial8_from_txt(serial_txt, serial8) == 0) {
                can_send8(s, ATT_RESP, serial8);
                fprintf(stdout, "[ECU %s] attestation sent: %02x%02x...\n", ECU_ID, serial8[0], serial8[1]);
            } else {
                fprintf(stderr, "[ECU %s] serial txt read fail\n", ECU_ID);
            }
            continue;
        }

        // 2) META stream (nonce16 + ota_hash32 + vg_hash32 = 80B)
        if (id == META_ID) {
            // 이미 프레임 하나 읽었지만, stream 수신은 함수가 다시 read를 돈다.
            // 간단하게: START/END는 stream 함수에서만 처리하고,
            // 여기서는 "META_ID가 보이면 stream 수신 모드"로 들어간다고 가정.
            uint8_t *buf = NULL; size_t n = 0;
            if (recv_stream(s, META_ID, &buf, &n) == 0) {
                if (n >= 80) {
                    memcpy(nonce16, buf, 16);
                    memcpy(ota_hash32, buf+16, 32);
                    memcpy(vg_hash32,  buf+48, 32);
                    have_meta = 1;
                    fprintf(stdout, "[ECU %s] META received\n", ECU_ID);
                }
                free(buf);
            }
            continue;
        }

        // 3) TOKEN stream (32B)
        if (id == TOKEN_ID) {
            uint8_t *buf = NULL; size_t n = 0;
            if (recv_stream(s, TOKEN_ID, &buf, &n) == 0) {
                if (have_meta && n >= 32) {
                    uint8_t expect[32];
                    hmac_token(ota_hash32, vg_hash32, ECU_ID, nonce16, expect);
                    if (memcmp(expect, buf, 32) == 0) {
                        token_ok = 1;
                        uint8_t ack[8] = {0xAC, 0x01,0,0,0,0,0,0}; // token OK
                        can_send8(s, ACK_ID, ack);
                        fprintf(stdout, "[ECU %s] TOKEN OK\n", ECU_ID);
                    } else {
                        uint8_t ack[8] = {0xAC, 0x00,0,0,0,0,0,0}; // token FAIL
                        can_send8(s, ACK_ID, ack);
                        fprintf(stdout, "[ECU %s] TOKEN FAIL\n", ECU_ID);
                    }
                }
                free(buf);
            }
            continue;
        }

        // 4) OTA stream
        if (id == OTA_ID) {
            uint8_t *buf = NULL; size_t n = 0;
            if (recv_stream(s, OTA_ID, &buf, &n) == 0) {
                if (!token_ok) {
                    fprintf(stderr, "[ECU %s] OTA received but token not OK. drop.\n", ECU_ID);
                    free(buf);
                    continue;
                }

                // 저장
                FILE *fp = fopen(out_bin, "wb");
                if (!fp) { perror("fopen out_bin"); free(buf); continue; }
                fwrite(buf, 1, n, fp);
                fclose(fp);

                // 해시 검증
                uint8_t got_hash[32];
                sha256_bytes(buf, n, got_hash);
                free(buf);

                if (memcmp(got_hash, ota_hash32, 32) == 0) {
                    uint8_t ack[8] = {0xAC, 0x02,0,0,0,0,0,0}; // ota OK
                    can_send8(s, ACK_ID, ack);
                    fprintf(stdout, "[ECU %s] OTA OK saved: %s\n", ECU_ID, out_bin);
                } else {
                    uint8_t ack[8] = {0xAC, 0x03,0,0,0,0,0,0}; // ota hash mismatch
                    can_send8(s, ACK_ID, ack);
                    fprintf(stdout, "[ECU %s] OTA HASH MISMATCH\n", ECU_ID);
                }
            }
            continue;
        }
    }

    close(s);
    return 0;
}

