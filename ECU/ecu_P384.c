// ecu_can_ota_kdf.c
// ECU side: SocketCAN + MasterKey->ECUK... chunks) -> END_MARK(8B)
//
// META payload layout:
//   nonce16(16) + pq_len(4, BE) + pq_bytes + vg_hash(32) + ota_hash(32) + filename_len(2, BE) + filename bytes
//
// TOKEN payload: 32B raw
// OTA payload  : raw bytes
//
// ACK payload: 8B
//   [0]=0xAC, [1]=stage
//   stage: 0x01 token OK, 0x00 token FAIL, 0x02 ota OK, 0x03 ota hash mismatch
//
// Build: gcc -O2 -o ecu_P ecu_P.c -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>  // [ADDED] for ECDSA verify (PEM public key)

#include <time.h>

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline void perf_ms(const char *ECU_ID, const char *tag, uint64_t t0_ns) {
    uint64_t t1 = now_ns();
    double ms = (double)(t1 - t0_ns) / 1e6;
    printf("[PERF] ECU %s %s: %.3f ms\n", ECU_ID, tag, ms);
    fflush(stdout);
}

static const uint8_t START_MARK[8] = {0xff,0x00,0xff,0x00,0xff,0x00,0xff,0x00};
static const uint8_t END_MARK[8]   = {0x00,0xff,0x00,0xff,0x00,0xff,0x00,0xff};

// ===============================
// [ADDED] ECU Capability (P/H/C)
//  - P: Token(HMAC)만 강제
//  - H: Token(HMAC) + (추가로) ECDSA 서명 검증
//  - C: Token 없이 ECDSA만 (Token 체크 우회)
// ===============================
typedef enum { ECU_CLASS_P, ECU_CLASS_H, ECU_CLASS_C } ecu_class_t;

static ecu_class_t parse_capability_arg(const char *s) {
    return ECU_CLASS_P;
}


static int is_mark(const uint8_t a[8], const uint8_t b[8]) {
    return memcmp(a, b, 8) == 0;
}

static int open_can(const char *ifname) {
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(s);
        return -1;
    }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(s);
        return -1;
    }

    return s;
}

static int can_send8(int s, uint16_t can_id, const uint8_t data8[8]) {
    struct can_frame f;
    memset(&f, 0, sizeof(f));
    f.can_id = can_id;
    f.can_dlc = 8;
    memcpy(f.data, data8, 8);

    int w = write(s, &f, sizeof(f));
    if (w != (int)sizeof(f)) return -1;
    return 0;
}

static int can_read(int s, struct can_frame *out) {
    int r = read(s, out, sizeof(*out));
    if (r != (int)sizeof(*out)) return -1;
    return 0;
}

// ------------------------------
// STREAM RECEIVER (FIXED)
// ------------------------------

// START 프레임을 이미 main loop에서 "읽은 상태"에서,
// 같은 can_id에 대해 다음 프레임부터 END까지 payload(8B씩)를 모아 반환.
static int recv_stream_after_start(int s, uint16_t can_id, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;

    uint8_t *buf = NULL;
    size_t cap = 0, len = 0;

    while (1) {
        struct can_frame f;
        if (can_read(s, &f) != 0) continue;

        uint16_t id = (uint16_t)(f.can_id & 0x7FF);
        if (id != can_id) {
            continue;
        }

        if (f.can_dlc == 8 && is_mark(f.data, END_MARK)) {
            *out = buf;
            *out_len = len;
            return 0;
        }

        size_t take = (f.can_dlc <= 8) ? f.can_dlc : 8;
        if (len + take > cap) {
            size_t ncap = (cap == 0) ? 1024 : cap * 2;
            while (ncap < len + take) ncap *= 2;

            uint8_t *nb = (uint8_t*)realloc(buf, ncap);
            if (!nb) {
                free(buf);
                return -1;
            }
            buf = nb;
            cap = ncap;
        }

        memcpy(buf + len, f.data, take);
        len += take;
    }
}

// ------------------------------
// Helpers
// ------------------------------

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t out32[32]) {
    unsigned int outlen = 0;
    HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out32, &outlen);
}

static void derive_ecu_key(const uint8_t master32[32], const char *ecu_id, uint8_t out32[32]) {
    unsigned int outlen = 0;
    char msg[128];
    snprintf(msg, sizeof(msg), "ECUKEY|%s", ecu_id);

    HMAC(EVP_sha256(), master32, 32,
         (const unsigned char*)msg, (int)strlen(msg),
         out32, &outlen);
}

static void make_token(const uint8_t ecu_key32[32], const char *ecu_id,
                    const uint8_t ota_hash32[32], const uint8_t vg_hash32[32],
                    const uint8_t nonce16[16], uint8_t out32[32]) {
    unsigned int outlen = 0;
    uint8_t msg[6 + 32 + 32 + 16 + 64];
    size_t off = 0;

    memcpy(msg+off, "TOKEN|", 6); off += 6;
    memcpy(msg+off, ota_hash32, 32); off += 32;
    memcpy(msg+off, vg_hash32, 32); off += 32;
    memcpy(msg+off, nonce16, 16); off += 16;

    size_t idlen = strlen(ecu_id);
    memcpy(msg+off, ecu_id, idlen); off += idlen;

    HMAC(EVP_sha256(), ecu_key32, 32, msg, (int)off, out32, &outlen);
}

// 안전한 상대경로인지 검사: ../, ..\, 절대경로, 드라이브명 등을 제거/거부
static void sanitize_relpath(const char *in, char *out, size_t out_sz) {
    // 기본값
    strncpy(out, "receive.bin", out_sz-1);
    out[out_sz-1] = 0;

    if (!in || !in[0]) return;

    // 절대경로 거부
    if (in[0] == '/' || in[0] == '\\') return;

    // Windows drive letter 거부 (C:\ ...)
    if (strlen(in) >= 2 && ((in[1] == ':' && ((in[0]>='A'&&in[0]<='Z')||(in[0]>='a'&&in[0]<='z'))))) {
        return;
    }

    // .. 포함 거부
    if (strstr(in, "..") != NULL) {
        return;
    }

    // NUL, 제어문자 제거 + 너무 긴 경우 컷
    char tmp[512];
    size_t j = 0;
    for (size_t i=0; in[i] && j < sizeof(tmp)-1; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x20) continue;
        tmp[j++] = (char)c;
    }
    tmp[j] = 0;

    // 선행 슬래시 제거
    while (tmp[0] == '/' || tmp[0] == '\\') memmove(tmp, tmp+1, strlen(tmp));

    // 최종
    strncpy(out, tmp, out_sz-1);
    out[out_sz-1] = 0;
}

// 디렉토리 경로를 재귀 생성 (간단)
static void mkdir_p(const char *path) {
    char buf[512];
    strncpy(buf, path, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;

    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(buf, 0755);
            *p = '/';
        }
    }
    mkdir(buf, 0755);
}

static void mkdirs_for_file_path(const char *filepath) {
    // filepath에서 마지막 '/' 이전까지 디렉토리 생성
    char tmp[512];
    strncpy(tmp, filepath, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1]=0;

    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = 0;
    if (tmp[0]) mkdir_p(tmp);
}

static int parse_hex8(const char *path, uint8_t out8[8]) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char buf[256];
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // 공백/개행 제거
    for (int i=0; buf[i]; i++) {
        if (buf[i]=='\n' || buf[i]=='\r' || buf[i]==' ' || buf[i]=='\t') { buf[i]=0; break; }
    }
    if (strlen(buf) < 16) return -1;

    for (int i=0; i<8; i++) {
        char hx[3] = { buf[i*2], buf[i*2+1], 0 };
        out8[i] = (uint8_t)strtoul(hx, NULL, 16);
    }
    return 0;
}

// ====== OpenSSL EVP SHA256 ======
static void sha256_bytes(const uint8_t *data, size_t n, uint8_t out32[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(out32,0,32); return; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        memset(out32,0,32);
        return;
    }
    EVP_DigestUpdate(ctx, data, n);

    unsigned int outlen = 0;
    EVP_DigestFinal_ex(ctx, out32, &outlen);
    if (outlen != 32) memset(out32,0,32);

    EVP_MD_CTX_free(ctx);
}

// ===============================
// [ADDED] ECDSA(SHA256) verify
//  - sig는 DER(ASN.1) 형태의 ECDSA signature 바이트를 가정
//  - pub_pem_path: PEM public key path
// ===============================
static int verify_ecdsa_pem_sha256(const char *pub_pem_path,
                                  const uint8_t *data, size_t data_len,
                                  const uint8_t *sig, size_t sig_len) {
    FILE *fp = fopen(pub_pem_path, "r");
    if (!fp) { perror("fopen pub_pem"); return 0; }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) { fprintf(stderr, "PEM_read_PUBKEY fail\n"); return 0; }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return 0; }

    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data, data_len) == 1 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        ok = 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}


// ====== MasterKey 로딩 ======
static int load_master_key_32(const char *path, uint8_t out32[32]) {
    // Gateway default 와 동일해야 함
    const uint8_t fallback[32] = "DEMO_MASTER_KEY_32BYTES_LONG____";

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        memcpy(out32, fallback, 32);
        return 0;
    }
    uint8_t buf[64];
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (n < 32) {
        memcpy(out32, fallback, 32);
        return 0;
    }
    memcpy(out32, buf, 32);
    return 0;
}

static void join_path(char *out, size_t out_sz, const char *base_dir, const char *relpath) {
    if (!out || out_sz == 0) return;
    out[0] = 0;

    size_t bl = strlen(base_dir);
    if (bl == 0) {
        snprintf(out, out_sz, "%s", relpath);
        return;
    }
    if (base_dir[bl-1] == '/')
        snprintf(out, out_sz, "%s%s", base_dir, relpath);
    else
        snprintf(out, out_sz, "%s/%s", base_dir, relpath);
}


int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr,
            "usage: %s <can_if> <ECU_ID> <ECU_ADDR_HEX> <serial_txt> <out_path> <master_key_bin>\n",
            argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *ECU_ID = argv[2];
    int addr = (int)strtol(argv[3], NULL, 0);
    const char *serial_txt = argv[4];
    const char *out_dir = argv[5]; 
    const char *master_key_path = argv[6];

    // ===============================
    // [ADDED] Optional capability arg
    //   argv[7] = P | H | C
    //   - default: H
    // ===============================
    const char *cap_str = (argc >= 8) ? argv[7] : "P";
    ecu_class_t ecu_class = parse_capability_arg(cap_str);
    fprintf(stdout, "[ECU %s] capability=%c\n", ECU_ID, cap_str[0]);


    uint16_t ATT_REQ  = 0x600 + addr;
    uint16_t ATT_RESP = 0x650 + addr;
    uint16_t META_ID  = 0x700 + addr;
    uint16_t TOKEN_ID = 0x710 + addr;
    uint16_t OTA_ID   = 0x720 + addr;
    uint16_t SIG_ID   = 0x740 + addr;  // [ADDED] ECDSA signature stream
    uint16_t ACK_ID   = 0x730 + addr;

    int s = open_can(ifname);
    if (s < 0) return 1;

    // 키 준비
    uint8_t master32[32];
    uint8_t ecu_key32[32];
    load_master_key_32(master_key_path, master32);
    derive_ecu_key(master32, ECU_ID, ecu_key32);

    uint8_t nonce16[16]={0}, ota_hash32[32]={0}, vg_hash32[32]={0};
    int have_meta = 0;
    int token_ok = 0;
    // ===============================
    // [ADDED] ECDSA signature buffer
    //   Gateway가 SIG_ID(0x740+addr)로 DER 서명을 보내면 저장
    // ===============================
    uint8_t *ecdsa_sig = NULL;
    size_t ecdsa_sig_len = 0;

    char recv_relpath[256] = "receive.bin";

    while (1) {
        struct can_frame f;
        if (can_read(s, &f) != 0) continue;

        uint16_t id = (uint16_t)(f.can_id & 0x7FF);

        // 1) Attestation 요청 수신 -> 응답
        if (id == ATT_REQ && f.can_dlc == 8 && f.data[0] == 0xA1) {
            uint8_t serial8[8];
            if (parse_hex8(serial_txt, serial8) == 0) {
                can_send8(s, ATT_RESP, serial8);
                fprintf(stdout, "[ECU %s] attestation sent: %s\n", ECU_ID, serial_txt);
            } else {
                fprintf(stderr, "[ECU %s] serial txt read fail: %s\n", ECU_ID, serial_txt);
            }
            continue;
        }


        // 2) META stream
        if (id == META_ID) {
            if (f.can_dlc != 8 || !is_mark(f.data, START_MARK)) {
                continue;
            }

            uint64_t t_meta = now_ns();

            uint8_t *buf = NULL; size_t n = 0;
            if (recv_stream_after_start(s, META_ID, &buf, &n) == 0) {
                // nonce16(16) + pq_len(4) + pq_bytes + vg_hash(32) + ota_hash(32) + fn_len(2) + fn_bytes
                if (n >= 16 + 4 + 32 + 32 + 2) {
                    memcpy(nonce16, buf, 16);

                    uint32_t pq_len = 0;
                    pq_len |= (uint32_t)buf[16] << 24;
                    pq_len |= (uint32_t)buf[17] << 16;
                    pq_len |= (uint32_t)buf[18] << 8;
                    pq_len |= (uint32_t)buf[19];

                    size_t min_need = 16 + 4 + pq_len + 32 + 32 + 2;
                    if (n >= min_need) {
                        size_t off = 16 + 4 + pq_len;

                        memcpy(vg_hash32,  buf + off, 32); off += 32;
                        memcpy(ota_hash32, buf + off, 32); off += 32;

                        uint16_t fn_len = ((uint16_t)buf[off] << 8) | (uint16_t)buf[off+1];
                        off += 2;
                        if (fn_len > 0 && off + fn_len <= n) {
                            char name_tmp[256];
                            size_t cpy = (fn_len < sizeof(name_tmp)-1) ? fn_len : (sizeof(name_tmp)-1);
                            memcpy(name_tmp, buf + off, cpy);
                            name_tmp[cpy] = 0;

                            sanitize_relpath(name_tmp, recv_relpath, sizeof(recv_relpath));
                            fprintf(stdout, "[ECU %s] META received (pq_len=%u)\n", ECU_ID, pq_len);
                            fprintf(stdout, "[ECU %s] META filename=%s\n", ECU_ID, recv_relpath);

                        } else {
                            fprintf(stdout, "[ECU %s] META received (pq_len=%u)\n", ECU_ID, pq_len);
                        }

                        have_meta = 1;
                        token_ok = 0; // 새 META면 token도 새로
                    } else {
                        fprintf(stderr, "[ECU %s] META length mismatch: need>= %zu got=%zu\n", ECU_ID, min_need, n);
                    }
                } else {
                    fprintf(stderr, "[ECU %s] META too short: %zu\n", ECU_ID, n);
                }
                free(buf);
            }
            perf_ms(ECU_ID, "26.meta_recv_parse", t_meta);

            continue;
        }

        // 3) TOKEN stream
        if (id == TOKEN_ID) {
            if (f.can_dlc != 8 || !is_mark(f.data, START_MARK)) {
                continue;
            }

            uint8_t *buf = NULL; size_t n = 0;
            if (recv_stream_after_start(s, TOKEN_ID, &buf, &n) == 0) {
                if (have_meta && n >= 32) {
                    uint64_t t_token = now_ns();
                    uint8_t expect[32];
                    make_token(ecu_key32, ECU_ID, ota_hash32, vg_hash32, nonce16, expect);

                    if (memcmp(expect, buf, 32) == 0) {
                        token_ok = 1;
                        uint8_t ack[8] = {0xAC, 0x01,0,0,0,0,0,0}; // token OK
                        can_send8(s, ACK_ID, ack);
                        fprintf(stdout, "[ECU %s] TOKEN OK\n", ECU_ID);
                    } else {
                        token_ok = 0;
                        uint8_t ack[8] = {0xAC, 0x00,0,0,0,0,0,0}; // token FAIL
                        can_send8(s, ACK_ID, ack);
                        fprintf(stdout, "[ECU %s] TOKEN FAIL\n", ECU_ID);
                    }
                    perf_ms(ECU_ID, "28.token_hmac_compare", t_token);
                } else {
                    fprintf(stderr, "[ECU %s] TOKEN received but META missing or too short\n", ECU_ID);
                }
                free(buf);
            }
            continue;
        }

        // 3.5) [ADDED] ECDSA SIG stream (DER bytes)
        if (id == SIG_ID) {
            if (f.can_dlc != 8 || !is_mark(f.data, START_MARK)) {
                continue;
            }

            free(ecdsa_sig);
            ecdsa_sig = NULL;
            ecdsa_sig_len = 0;

            if (recv_stream_after_start(s, SIG_ID, &ecdsa_sig, &ecdsa_sig_len) == 0) {
                fprintf(stdout, "[ECU %s] SIG received: %zu bytes\n", ECU_ID, ecdsa_sig_len);
            }
            continue;
        }

        // 4) OTA stream
        if (id == OTA_ID) {
            if (f.can_dlc != 8 || !is_mark(f.data, START_MARK)) {
                continue;
            }

            uint8_t *buf = NULL; size_t n = 0;
            if (recv_stream_after_start(s, OTA_ID, &buf, &n) == 0) {
                // [ADDED] Capability C는 Token을 받지 않으므로 token_ok를 강제로 통과시킴
                if (ecu_class == ECU_CLASS_C) {
                    token_ok = 1;
                }

                if (!token_ok) {
                    fprintf(stderr, "[ECU %s] OTA received but token not OK. drop.\n", ECU_ID);
                    free(buf);
                    continue;
                }

                // ===============================
                // [ADDED] Capability H/C: OTA payload ECDSA 검증
                //  - Gateway가 SIG_ID로 DER 서명을 먼저 보내야 함
                // ===============================
                if (ecu_class == ECU_CLASS_H || ecu_class == ECU_CLASS_C) {
                    if (!ecdsa_sig || ecdsa_sig_len == 0) {
                        fprintf(stderr, "[ECU %s] Missing ECDSA signature. drop.\n", ECU_ID);
                        free(buf);
                        continue;
                    }

                    // 공개키 파일 경로 (필요시 인자로 확장 가능)
                    const char *pubkey_path = "./ecdsa384_public.pem";

                    if (!verify_ecdsa_pem_sha256(pubkey_path, buf, n, ecdsa_sig, ecdsa_sig_len)) {
                        fprintf(stderr, "[ECU %s] ECDSA verify FAIL. drop.\n", ECU_ID);
                        free(buf);
                        continue;
                    }

                    fprintf(stdout, "[ECU %s] ECDSA verify OK\n", ECU_ID);
                }


                char out_path[512];
                join_path(out_path, sizeof(out_path), out_dir, recv_relpath);

                // 하위폴더가 포함된 경우 자동 생성
                mkdirs_for_file_path(out_path);

                uint64_t t_write = now_ns();

                FILE *fp = fopen(out_path, "wb");  // ✅ 같은 이름이면 덮어쓰기
                if (!fp) {
                    perror("fopen out_path");
                    free(buf);
                    continue;
                }
                fwrite(buf, 1, n, fp);
                fclose(fp);
                perf_ms(ECU_ID, "35.file_write", t_write);

                uint64_t t_sha = now_ns();
                uint8_t got_hash[32];
                sha256_bytes(buf, n, got_hash);
                int same = (memcmp(got_hash, ota_hash32, 32) == 0);
                perf_ms(ECU_ID, "34.sha256_compare", t_sha);

                if (memcmp(got_hash, ota_hash32, 32) == 0) {
                    uint8_t ack[8] = {0xAC, 0x02,0,0,0,0,0,0}; // ota OK
                    can_send8(s, ACK_ID, ack);
                    fprintf(stdout, "[ECU %s] OTA OK saved: %s\n", ECU_ID, out_path);
                } else {
                    uint8_t ack[8] = {0xAC, 0x03,0,0,0,0,0,0}; // ota hash mismatch
                    can_send8(s, ACK_ID, ack);
                    fprintf(stdout, "[ECU %s] OTA HASH MISMATCH\n", ECU_ID);
                }
            }
            continue;
        }

        // 그 외 ID는 무시
    }

    close(s);
    return 0;
}
