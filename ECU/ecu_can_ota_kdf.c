// ecu_can_ota_kdf.c
// ECU side: SocketCAN + MasterKey->ECUKey(KDF) + nonce 포함 HMAC token 검증
// Stream framing: START_MARK(8B) -> payload(8B chunks) -> END_MARK(8B)
//
// META payload layout:
//   nonce16(16) || be32(pq_len) || pq_bytes(pq_len) || vg_hash32(32) || ota_hash32(32)
//
// TOKEN payload layout:
//   token32(32)  (HMAC-SHA256)
//
// OTA payload layout:
//   raw binary bytes (8B chunks), SHA256 compared with ota_hash32

#define _GNU_SOURCE
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

static const uint8_t START_MARK[8] = {0xff,0x00,0xff,0x00,0xff,0x00,0xff,0x00};
static const uint8_t END_MARK[8]   = {0x00,0xff,0x00,0xff,0x00,0xff,0x00,0xff};

static int is_mark(const uint8_t a[8], const uint8_t b[8]) {
    return memcmp(a, b, 8) == 0;
}

static int open_can(const char *ifname) {
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { perror("socket"); return -1; }

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

static int can_send8(int s, uint16_t can_id, const uint8_t data[8]) {
    struct can_frame f;
    memset(&f, 0, sizeof(f));
    f.can_id = can_id;
    f.can_dlc = 8;
    memcpy(f.data, data, 8);

    int n = write(s, &f, sizeof(f));
    return (n == (int)sizeof(f)) ? 0 : -1;
}

static int can_read(int s, struct can_frame *out) {
    while (1) {
        int n = read(s, out, sizeof(*out));
        if (n == (int)sizeof(*out)) return 0;
        if (n < 0 && errno == EINTR) continue; // retry
        return -1;
    }
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

        // ID 필터
        if ((f.can_id & 0x7FF) != can_id) continue;

        // ✅ END_MARK는 "dlc==8" 일 때만 검사 (dlc<8이면 비교 자체가 의미 없음)
        if (f.can_dlc == 8 && memcmp(f.data, END_MARK, 8) == 0) {
            *out = buf;
            *out_len = len;
            return 0;
        }

        // payload는 dlc만큼만 취함
        size_t take = (size_t)f.can_dlc;
        if (take == 0) continue;

        // 버퍼 확장
        if (len + take > cap) {
            size_t ncap = (cap == 0) ? 256 : cap * 2;
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

// txt 파일(한 줄 16 hex)을 8바이트로 읽기
static int read_serial8_from_txt(const char *path, uint8_t out8[8]) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char buf[256];
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); return -1; }
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
    unsigned int outlen = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, n) != 1 ||
        EVP_DigestFinal_ex(ctx, out32, &outlen) != 1 || outlen != 32) {
        memset(out32,0,32);
    }
    EVP_MD_CTX_free(ctx);
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

// K_ecu = HMAC-SHA256(K_master, "ECUKEY|" + ECU_ID)
static void derive_ecu_key(const uint8_t master32[32], const char *ecu_id, uint8_t out32[32]) {
    unsigned int outlen = 0;
    char msg[128];
    snprintf(msg, sizeof(msg), "ECUKEY|%s", ecu_id);

    HMAC(EVP_sha256(), master32, 32,
         (const unsigned char*)msg, (int)strlen(msg),
         out32, &outlen);
}

// token = HMAC-SHA256(K_ecu, "TOKEN|" + ota_hash + vg_hash + nonce16 + ECU_ID)
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

// big-endian u32 읽기
static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | (uint32_t)p[3];
}

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

// filename을 안전하게 정리: 절대경로/.. 차단 + 허용문자 제한
// 하위폴더( a/b/c.bin )는 허용, 하지만 ".."는 금지
static void sanitize_relpath(const char *in, char *out, size_t out_sz) {
    if (!in || !out || out_sz == 0) return;

    // 절대경로 차단
    if (in[0] == '/') {
        snprintf(out, out_sz, "receive.bin");
        return;
    }

    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_sz; i++) {
        char c = in[i];

        // 윈도우 경로/드라이브 문자 차단
        if (c == '\\' || c == ':') { out[j++] = '_'; continue; }

        // 허용: 영문/숫자/._-/ 그리고 '/'(하위폴더)
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '_' || c == '-' || c == '/') {
            out[j++] = c;
        } else {
            out[j++] = '_';
        }
    }
    out[j] = '\0';

    // '..' traversal 차단
    if (strstr(out, "..") != NULL) {
        snprintf(out, out_sz, "receive.bin");
        return;
    }

    // 빈 값이면 기본값
    if (out[0] == '\0') {
        snprintf(out, out_sz, "receive.bin");
        return;
    }

    // '.'로 시작하면 위험 소지 → 치환
    if (out[0] == '.') out[0] = '_';
}

// a/b/c 처럼 디렉토리 재귀 생성
static void mkdirs_for_file_path(const char *file_path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", file_path);

    // 마지막 '/' 이전까지만 디렉토리로 생성
    char *last = strrchr(tmp, '/');
    if (!last) return;
    *last = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void join_path(char *out, size_t out_sz, const char *base_dir, const char *relpath) {
    if (!base_dir || !relpath) {
        snprintf(out, out_sz, "./update_files/receive.bin");
        return;
    }
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

    uint16_t ATT_REQ  = 0x600 + addr;
    uint16_t ATT_RESP = 0x650 + addr;
    uint16_t META_ID  = 0x700 + addr;
    uint16_t TOKEN_ID = 0x710 + addr;
    uint16_t OTA_ID   = 0x720 + addr;
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
    char recv_relpath[256] = "receive.bin";

    while (1) {
        struct can_frame f;
        if (can_read(s, &f) != 0) continue;

        uint16_t id = (uint16_t)(f.can_id & 0x7FF);

        // 1) Attestation request (single frame)
        if (id == ATT_REQ && f.can_dlc == 8 && f.data[0] == 0xA1) {
            uint8_t serial8[8];
            if (read_serial8_from_txt(serial_txt, serial8) == 0) {
                can_send8(s, ATT_RESP, serial8);
                fprintf(stdout, "[ECU %s] attestation sent: %s\n", ECU_ID, serial_txt);
            } else {
                fprintf(stderr, "[ECU %s] serial txt read fail: %s\n", ECU_ID, serial_txt);
            }
            continue;
        }

        // 2) META stream
        // FIX: main loop에서 START 프레임을 이미 읽었으므로,
        //      START일 때만 recv_stream_after_start()로 수집 시작
        if (id == META_ID) {
            if (f.can_dlc != 8 || !is_mark(f.data, START_MARK)) {
                // START가 아닌 META 프레임은(중간 payload/END 등) 여기서 무시
                continue;
            }

            strncpy(recv_relpath, "receive.bin", sizeof(recv_relpath));
            recv_relpath[sizeof(recv_relpath)-1] = '\0';
            
            uint8_t *buf = NULL; size_t n = 0;
            if (recv_stream_after_start(s, META_ID, &buf, &n) == 0) {
                if (n >= 16 + 4 + 32 + 32) {
                    memcpy(nonce16, buf, 16);
                    uint32_t pq_len = read_be32(buf + 16);
                    size_t need = 16 + 4 + (size_t)pq_len + 32 + 32;

                    if (n >= need) {
                        memcpy(vg_hash32,  buf + 16 + 4 + pq_len, 32);
                        memcpy(ota_hash32, buf + 16 + 4 + pq_len + 32, 32);

                        have_meta = 1;
                        token_ok = 0;
                        fprintf(stdout, "[ECU %s] META received (pq_len=%u)\n", ECU_ID, pq_len);
                    } else {
                        fprintf(stderr, "[ECU %s] META too short: got=%zu need=%zu\n", ECU_ID, n, need);
                    }
                    if (n >= need + 2) {
                        uint16_t name_len = read_be16(buf + need);
                        size_t name_off = need + 2;
                    
                        if (name_len > 0 && name_len <= 200 && n >= name_off + name_len) {
                            char name_tmp[256] = {0};
                            memcpy(name_tmp, buf + name_off, name_len);
                            name_tmp[name_len] = '\0';
                    
                            sanitize_relpath(name_tmp, recv_relpath, sizeof(recv_relpath));
                            fprintf(stdout, "[ECU %s] META filename=%s\n", ECU_ID, recv_relpath);
                        }
                    }
                } else {
                    fprintf(stderr, "[ECU %s] META too short: %zu\n", ECU_ID, n);
                }
                free(buf);
            }
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
                } else {
                    fprintf(stderr, "[ECU %s] TOKEN received but META missing or too short\n", ECU_ID);
                }
                free(buf);
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
                if (!token_ok) {
                    fprintf(stderr, "[ECU %s] OTA received but token not OK. drop.\n", ECU_ID);
                    free(buf);
                    continue;
                }

                char out_path[512];
                join_path(out_path, sizeof(out_path), out_dir, recv_relpath);

                // 하위폴더가 포함된 경우 자동 생성
                mkdirs_for_file_path(out_path);

                FILE *fp = fopen(out_path, "wb");  // ✅ 같은 이름이면 덮어쓰기
                if (!fp) {
                    perror("fopen out_path");
                    free(buf);
                    continue;
                }
                fwrite(buf, 1, n, fp);
                fclose(fp);

                uint8_t got_hash[32];
                sha256_bytes(buf, n, got_hash);
                free(buf);

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
