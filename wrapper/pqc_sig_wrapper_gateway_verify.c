// pqc_sig_wrapper.c
// Jetson TX2 (Ubuntu 18.04) + liboqs용 PQC 서명 래퍼
// 빌드 후: libpqc_sig.so 로 만들어서 Python에서 ctypes로 사용

//gcc -O2 -fPIC -shared -DGATEWAY_VERIFY_ONLY=1 \
  -o libpqc_sig.so pqc_sig_wrapper_gateway_verify.c \
  -I/usr/local/include \
  -L/usr/local/lib -loqs \
  -lcrypto -lssl \
  -Wl,-rpath,/usr/local/lib

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

// 전역 상태 (간단 구현: 한 프로세스에서 한 알고리즘/한 키셋만 사용)
static OQS_SIG *g_sig = NULL;

static uint8_t *g_sk = NULL;
static size_t   g_sk_len = 0;

static uint8_t *g_pk = NULL;
static size_t   g_pk_len = 0;

// ==========================
// 내부 유틸: 파일 읽기 / 쓰기
// ==========================

static int read_file_all(const char *path, uint8_t **buf, size_t *len) {
    FILE *f;
    long size;
    uint8_t *tmp;

    if (path == NULL || buf == NULL || len == NULL) {
        return -1;
    }

    f = fopen(path, "rb");
    if (f == NULL) {
        return -1;  // 파일 없음 또는 열기 실패
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    size = ftell(f);
    if (size < 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    if (size == 0) {
        fclose(f);
        return -1;
    }

    tmp = (uint8_t *) malloc((size_t) size);
    if (tmp == NULL) {
        fclose(f);
        return -1;
    }

    if (fread(tmp, 1, (size_t) size, f) != (size_t) size) {
        free(tmp);
        fclose(f);
        return -1;
    }

    fclose(f);

    *buf = tmp;
    *len = (size_t) size;
    return 0;  // 성공
}

static int write_file_all(const char *path, const uint8_t *buf, size_t len) {
    FILE *f;

    if (path == NULL || buf == NULL) {
        return -1;
    }

    f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }

    if (len > 0) {
        if (fwrite(buf, 1, len, f) != len) {
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;  // 성공
}

// ==========================
// 내부 유틸: 전역 상태 정리
// ==========================

static void internal_cleanup(void) {
    if (g_sig != NULL) {
        OQS_SIG_free(g_sig);
        g_sig = NULL;
    }
    if (g_sk != NULL) {
        free(g_sk);
        g_sk = NULL;
    }
    if (g_pk != NULL) {
        free(g_pk);
        g_pk = NULL;
    }
    g_sk_len = 0;
    g_pk_len = 0;
}

// ==========================
// 공개 API: 초기화/키 생성/로드
// ==========================
//
// int pqc_init(const char *alg_name,
//              const char *privkey_path,
//              const char *pubkey_path);
//
// - alg_name      : liboqs 알고리즘 이름 (예: "Falcon-512")
// - privkey_path  : 비밀키 파일 경로 (바이너리)
// - pubkey_path   : 공개키 파일 경로 (바이너리)
// - 반환값 0이면 성공, 그 외 실패
//

int pqc_init_verify(const char *alg_name, const char *pubkey_path);

int pqc_init(const char *alg_name,
             const char *privkey_path,
             const char *pubkey_path) {
    uint8_t *tmp_sk = NULL;
    uint8_t *tmp_pk = NULL;
    size_t tmp_sk_len = 0;
    size_t tmp_pk_len = 0;
    int have_valid_keys = 0;

#ifdef GATEWAY_VERIFY_ONLY
    // Gateway는 검증 전용: 비밀키를 사용/생성하지 않습니다.
    (void) privkey_path;
    return pqc_init_verify(alg_name, pubkey_path);
#endif

    // 이미 초기화 되어 있으면 그냥 성공으로 처리
    if (g_sig != NULL) {
        return 0;
    }

    if (alg_name == NULL || privkey_path == NULL || pubkey_path == NULL) {
        return -1;
    }

    // 알고리즘 객체 생성 (예: "Falcon-512")
    g_sig = OQS_SIG_new(alg_name);
    if (g_sig == NULL) {
        return -1;
    }

    // 1) 기존 키 파일이 있으면 읽기 시도
    if (read_file_all(privkey_path, &tmp_sk, &tmp_sk_len) == 0 &&
        read_file_all(pubkey_path, &tmp_pk, &tmp_pk_len) == 0) {

        // 길이가 liboqs가 기대하는 키 길이와 일치하는지 확인
        if (tmp_sk_len == g_sig->length_secret_key &&
            tmp_pk_len == g_sig->length_public_key) {
            g_sk = tmp_sk;
            g_sk_len = tmp_sk_len;

            g_pk = tmp_pk;
            g_pk_len = tmp_pk_len;

            have_valid_keys = 1;
        } else {
            // 길이가 맞지 않으면 폐기
            if (tmp_sk != NULL) {
                free(tmp_sk);
                tmp_sk = NULL;
            }
            if (tmp_pk != NULL) {
                free(tmp_pk);
                tmp_pk = NULL;
            }
        }
    }

    // 2) 유효한 키가 없다면 새로 생성
    if (!have_valid_keys) {
        OQS_STATUS st;

        g_sk_len = g_sig->length_secret_key;
        g_pk_len = g_sig->length_public_key;

        g_sk = (uint8_t *) malloc(g_sk_len);
        g_pk = (uint8_t *) malloc(g_pk_len);
        if (g_sk == NULL || g_pk == NULL) {
            internal_cleanup();
            return -1;
        }

        st = OQS_SIG_keypair(g_sig, g_pk, g_sk);
        if (st != OQS_SUCCESS) {
            internal_cleanup();
            return -1;
        }

        // 파일로 저장 (쓰기 실패해도 메모리에는 있으므로, 동작은 계속 가능)
        if (write_file_all(privkey_path, g_sk, g_sk_len) != 0) {
            // 로그 정도만 가능, 여기서는 무시
        }
        if (write_file_all(pubkey_path, g_pk, g_pk_len) != 0) {
            // 로그 정도만 가능, 여기서는 무시
        }
    }

    return 0;  // 성공
}

// ==========================
// 공개 API: 검증 전용 초기화 (공개키만 로드, 키 생성 절대 안 함)
// ==========================
//
// int pqc_init_verify(const char *alg_name,
//                     const char *pubkey_path);
//
// - alg_name     : liboqs 알고리즘 이름 (예: "Falcon-1024")
// - pubkey_path  : 공개키 파일 경로 (바이너리)
// - 반환값 0이면 성공, 그 외 실패
//
// 주의:
//  - 이 함수는 g_sk(비밀키)를 로드/생성하지 않습니다.
//  - 공개키 파일이 없거나 길이가 맞지 않으면 실패(-1)합니다.
//  - 따라서 Gateway(검증 전용)에서 "키가 없으면 종료" 정책과 잘 맞습니다.
//

int pqc_init_verify(const char *alg_name,
                    const char *pubkey_path) {
    uint8_t *tmp_pk = NULL;
    size_t tmp_pk_len = 0;

    // 이미 초기화 되어 있고 공개키가 로드되어 있으면 그대로 성공
    if (g_sig != NULL && g_pk != NULL) {
        return 0;
    }

    // 혹시 중간 상태가 남아있다면 정리 후 다시 초기화
    if (g_sig != NULL || g_sk != NULL || g_pk != NULL) {
        internal_cleanup();
    }

    if (alg_name == NULL || pubkey_path == NULL) {
        return -1;
    }

    // 알고리즘 객체 생성 (예: "Falcon-1024")
    g_sig = OQS_SIG_new(alg_name);
    if (g_sig == NULL) {
        return -1;
    }

    // 공개키 파일 읽기
    if (read_file_all(pubkey_path, &tmp_pk, &tmp_pk_len) != 0) {
        internal_cleanup();
        return -1;
    }

    // 공개키 길이 검증
    if (tmp_pk_len != g_sig->length_public_key) {
        free(tmp_pk);
        internal_cleanup();
        return -1;
    }

    g_pk = tmp_pk;
    g_pk_len = tmp_pk_len;

    // 비밀키는 절대 로드/생성하지 않음
    g_sk = NULL;
    g_sk_len = 0;

    return 0;  // 성공
}


// ==========================
// 공개 API: 서명
// ==========================
//
// int pqc_sign(const uint8_t *msg, size_t msg_len,
//              uint8_t *sig_out, size_t *sig_len_inout);
//
// - msg/msg_len   : 서명할 메시지
// - sig_out       : 서명 결과를 쓸 버퍼
// - sig_len_inout : [입력] sig_out 버퍼 크기
//                   [출력] 실제 서명 길이
// - 반환값 0이면 성공, 그 외 실패
//

int pqc_sign(const uint8_t *msg, size_t msg_len,
             uint8_t *sig_out, size_t *sig_len_inout) {
#ifdef GATEWAY_VERIFY_ONLY
    (void)msg; (void)msg_len; (void)sig_out; (void)sig_len_inout;
    // Gateway 검증 전용 빌드에서는 서명 기능을 제공하지 않습니다.
    return -1;
#else
    size_t max_sig_len;
    size_t actual_sig_len = 0;
    OQS_STATUS st;

    if (g_sig == NULL || g_sk == NULL) {
        return -1;
    }
    if (msg == NULL || sig_out == NULL || sig_len_inout == NULL) {
        return -1;
    }

    max_sig_len = *sig_len_inout;
    if (max_sig_len < g_sig->length_signature) {
        // 버퍼가 최소 기대 길이보다 작으면 실패 처리
        return -2;
    }

    st = OQS_SIG_sign(
        g_sig,
        sig_out,
        &actual_sig_len,
        msg,
        msg_len,
        g_sk
    );
    if (st != OQS_SUCCESS) {
        return -1;
    }

    *sig_len_inout = actual_sig_len;
    return 0;  // 성공
#endif
}

// ==========================
// 공개 API: 검증
// ==========================
//
// int pqc_verify(const uint8_t *msg, size_t msg_len,
//               const uint8_t *sig, size_t sig_len);
//
// - msg/msg_len : 검증할 메시지
// - sig/sig_len: 검증할 서명
// - 반환값: 0  => 검증 성공
//          1  => 검증 실패(서명이 맞지 않음)
//         -1  => 내부 오류
//

int pqc_verify(const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len) {
    OQS_STATUS st;

    if (g_sig == NULL || g_pk == NULL) {
        return -1;
    }
    if (msg == NULL || sig == NULL) {
        return -1;
    }

    st = OQS_SIG_verify(
        g_sig,
        msg,
        msg_len,
        sig,
        sig_len,
        g_pk
    );

    if (st == OQS_SUCCESS) {
        return 0;  // 검증 성공
    } else if (st == OQS_ERROR) {
        return 1;  // 검증 실패(서명이 맞지 않음)
    } else {
        // 다른 상태값 (메모리 오류 등)
        return -1;
    }
}

// ==========================
// 공개 API: 정리
// ==========================
//
// void pqc_cleanup(void);
//  - 전역 상태 정리
//

void pqc_cleanup(void) {
    internal_cleanup();
}

#ifdef __cplusplus
}
#endif

