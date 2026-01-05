import paho.mqtt.client as mqtt
import os
import base64
import json
import hashlib
import hmac
import time
import struct  # [CAN-OTA-ADDED]
import ctypes
from ctypes import c_uint8, c_size_t, c_int, c_char_p, POINTER, byref

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from typing import Optional


# [ADDED] for attestation relay + CAN
import threading
import time
import errno
import can


# [ADDED] optional python-can
try:
    import can  # type: ignore
except Exception:
    can = None

# =========================
# Gateway internal secret (Token HMAC key)
# =========================

# ===============================
# [KDF/HMAC] Master key -> ECU key -> Token (nonce 포함)
# ===============================
# 운영에서는 파일/TPM/HSM 등 안전한 저장소 사용 권장

base_dir = os.path.dirname(os.path.abspath(__file__))      # .../OTA_Education/file

MASTER_KEY_PATH = os.environ.get("OTA_MASTER_KEY_PATH", os.path.join(base_dir, "master_key.bin"))

def _load_master_key() -> bytes:
    """
    Load 32-byte master key shared by Gateway and ECUs.
    - If MASTER_KEY_PATH exists and has >=32 bytes: use first 32 bytes.
    - Else fallback to an in-code default (프로토타입용).
    """
    default = b"DEMO_MASTER_KEY_32BYTES_LONG____"  # 정확히 32B로 맞추세요(프로토타입)
    try:
        if os.path.exists(MASTER_KEY_PATH):
            with open(MASTER_KEY_PATH, "rb") as f:
                b = f.read()
            if len(b) >= 32:
                return b[:32]
            print(f"[WARN] master_key.bin is too short ({len(b)} bytes). Using default.")
    except Exception as e:
        print("[WARN] master key load failed. Using default.", e)
    return default

def _derive_ecu_key(master_key: bytes, ecu_id: str) -> bytes:
    """
    K_ecu = HMAC-SHA256(K_master, b"ECUKEY|" + ECU_ID)
    """
    msg = b"ECUKEY|" + ecu_id.encode("utf-8")
    return hmac.new(master_key, msg, hashlib.sha256).digest()  # 32B

def _make_token(master_key: bytes, ecu_id: str, ota_hash: bytes, vg_hash: bytes, nonce16: bytes) -> bytes:
    """
    token = HMAC-SHA256(K_ecu, b"TOKEN|" + ota_hash + vg_hash + nonce16 + ECU_ID)
    - nonce16: 16바이트 랜덤, META로 ECU에 전달
    """
    k_ecu = _derive_ecu_key(master_key, ecu_id)
    msg = b"TOKEN|" + ota_hash + vg_hash + nonce16 + ecu_id.encode("utf-8")
    return hmac.new(k_ecu, msg, hashlib.sha256).digest()  # 32B
# =========================
# MQTT 및 경로 설정
# =========================

vg_topic = "updates/vg"
vg_sig_topic = "updates/vg/signature"
vg_pqc_sig_topic = "updates/vg/pqc_signature"

name_topic = "updates/name"
file_topic = "updates/file"
signature_topic = "updates/signature"          # ECDSA 서명 토픽
pqc_signature_topic = "updates/pqc_signature"  # PQC(Falcon) 서명 토픽

# [ADDED] Attestation topics (Cloud ↔ Gateway)
attestation_request_topic = "attestation/request"
attestation_response_topic = "attestation/response"

userId = "admin"
userPw = "1234"
brokerIp = "10.121.72.148"
port = 1883

# 현재 파일 기준 경로: /home/sea/OTA/OTA_Education/file
base_dir = os.path.dirname(os.path.abspath(__file__))

# 수신 파일을 임시 저장할 디렉터리: /home/sea/OTA/OTA_Education/file/temp
temp_dir = os.path.join(base_dir, "temp")
os.makedirs(temp_dir, exist_ok=True)

# ECDSA 공개키 경로: /home/sea/OTA/OTA_Education/certs/ecdsa/ecdsa_public.pem
certs_root_dir = os.path.abspath(os.path.join(base_dir, os.pardir, "certs"))
certs_ecdsa_dir = os.path.join(certs_root_dir, "ecdsa")
PUBLIC_KEY_PATH = os.path.join(certs_ecdsa_dir, "ecdsa_public.pem")

# PQC 키 경로: /home/sea/OTA/OTA_Education/certs/pqc
certs_pqc_dir = os.path.join(certs_root_dir, "pqc")
PQC_PUBKEY_PATH = os.path.join(certs_pqc_dir, "pqc_public.key")

# 수신 상태 저장 변수
vg_data = None
vg_sig_ecdsa = None
vg_sig_pqc = None
vg_verified = False

file_name = None
file_data = None
file_signature_ecdsa = None
file_signature_pqc = None
public_key = None  # ECDSA 공개키

# =========================
# PQC(Falcon-512)용 ctypes 래퍼
# =========================

wrapper_dir = os.path.abspath(os.path.join(base_dir, "..", "wrapper"))  # .../OTA_Education/wrapper
PQC_LIB_NAME = os.path.join(wrapper_dir, "libpqc_sig_verify.so")
PQC_ALG_NAME = b"Falcon-1024"
PQC_MAX_SIG_LEN = 4096

_pqc = None  # ctypes.CDLL 핸들


def _require_pqc_pubkey_file_exist():
    p = PQC_PUBKEY_PATH
    if (not os.path.isfile(p)) or os.path.getsize(p) <= 0:
        raise SystemExit(
            "\n".join([
                "[FATAL] PQC public key file missing or empty:",
                f"  - {p}",
                "[HINT] Gateway는 PQC 키를 생성하지 않습니다. 공개키 파일을 먼저 배치하세요.",
            ])
        )


def init_pqc():
    """
    Gateway(검증 전용):
    - libpqc_sig_verify.so 를 로드하고,
    - pqc_init_verify(alg_name, pubkey_path)로 "공개키만" 로드합니다.
    - 공개키가 없으면 즉시 종료합니다(키 자동 생성 방지).
    """
    global _pqc

    if _pqc is not None:
        return

    # ✅ .so 로드 전에 공개키 파일 체크 → 없으면 즉시 종료
    _require_pqc_pubkey_file_exist()

    lib = ctypes.CDLL(PQC_LIB_NAME)

    # 검증 전용 초기화 함수 (wrapper.c에 추가된 함수)
    lib.pqc_init_verify.argtypes = [c_char_p, c_char_p]
    lib.pqc_init_verify.restype = c_int

    # pqc_verify 프로토타입도 명시(안전)
    lib.pqc_verify.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t
    ]
    lib.pqc_verify.restype = c_int

    if hasattr(lib, "pqc_cleanup"):
        lib.pqc_cleanup.argtypes = []
        lib.pqc_cleanup.restype = None

    alg = PQC_ALG_NAME
    pub_path = PQC_PUBKEY_PATH.encode("utf-8")

    rc = lib.pqc_init_verify(alg, pub_path)
    if rc != 0:
        raise RuntimeError(f"pqc_init_verify failed with code {rc}")

    _pqc = lib
    print(f"[INFO] PQC(Falcon) library loaded: {PQC_LIB_NAME}")
    print(f"[INFO] PQC public key : {PQC_PUBKEY_PATH}")


def pqc_verify(data: bytes, sig: bytes) -> bool:
    """
    Falcon-512 공개키로 (data, sig)를 검증.
    """
    if _pqc is None:
        raise RuntimeError("PQC library not initialized. Call init_pqc() first.")

    if not data or not sig:
        return False

    msg_len = len(data)
    sig_len = len(sig)

    msg_buf = (c_uint8 * msg_len).from_buffer_copy(data)
    sig_buf = (c_uint8 * sig_len).from_buffer_copy(sig)

    rc = _pqc.pqc_verify(
        msg_buf,
        c_size_t(msg_len),
        sig_buf,
        c_size_t(sig_len)
    )
    return rc == 0

# =========================
# ECDSA 관련
# =========================


def load_ecdsa_public_key(path: str):
    with open(path, "rb") as f:
        key_data = f.read()

    return serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )


def verify_ecdsa_signature(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print("[ERROR] ECDSA verify exception:", e)
        return False
    
def is_vg_expired(vg_bytes: bytes) -> bool:
    """
    Version Graph의 valid_until 시간이 현재 UTC 시간을 초과했는지 검사
    """
    try:
        vg = json.loads(vg_bytes.decode("utf-8"))
        valid_until_str = vg.get("valid_until")
        if not valid_until_str:
            print("[FAIL] VG missing valid_until")
            return True

        valid_until = datetime.strptime(
            valid_until_str, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)

        now_utc = datetime.now(timezone.utc)

        if now_utc > valid_until:
            print(f"[EXPIRED] VG expired at {valid_until}, now={now_utc}")
            return True

        return False

    except Exception as e:
        print("[ERROR] VG validity check failed:", e)
        return True

# =========================
# VG_verify
# =========================

def verify_vg():
    global vg_verified

    if vg_verified:
        return True

    if not (vg_data and vg_sig_ecdsa and vg_sig_pqc):
        return False

    if not verify_ecdsa_signature(public_key, vg_data, vg_sig_ecdsa):
        print("[FAIL] VG ECDSA verify")
        return False

    if not pqc_verify(vg_data, vg_sig_pqc):
        print("[FAIL] VG PQC verify")
        return False
    
    if is_vg_expired(vg_data):
        print("[ABORT] OTA aborted: Version Graph expired")
        return False

    vg_verified = True
    print("[SUCCESS] VG verified")
    return True

# =========================
# Token generate
# =========================

def generate_tokens():
    """
    Generate ECU tokens based on:
    - PQ_Verification_Result
    - ECU_ID
    - Version Graph Hash
    """

    # ---------- Hash 계산 ----------
    ota_hash = hashlib.sha256(file_data).digest()
    vg_hash  = hashlib.sha256(vg_data).digest()

    master_key = _load_master_key()  # master_key.bin(32B) 로드

    # ---------- PQ Verification Result 구성 ----------
    pq_verification_result = {
        "OTA_hash": ota_hash.hex(),
        "pqc_signature_valid": True,
        "Verified_at": int(time.time()),
        "nonce_G": os.urandom(16).hex(),
        "GW_ID": "GW-001"
    }

    pq_verification_result_bytes = json.dumps(
        pq_verification_result,
        sort_keys=True
    ).encode("utf-8")

    vg = json.loads(vg_data.decode("utf-8"))

    print("\n===== TOKEN GENERATED =====")

    # ecu_id -> {"nonce": bytes16, "token": bytes32}
    tokens_by_ecu = {}

    for entry in vg.get("allowed_transitions", []):
        ecu_id = entry.get("ecu")
        if not ecu_id:
            continue

        # 기존 VG 필드 호환: "ECU_Type" 또는 "capability"
        capability = entry.get("ECU_Type", entry.get("capability", "C"))

        # P/H만 토큰 발급(기존 정책 유지)
        if capability not in ("P", "H"):
            print(f"[INFO] ECU {ecu_id} is Class {capability} → No Token issued")
            continue

        # [KDF/HMAC] ECU별 nonce 생성 + 토큰 생성(32B raw)
        nonce16 = os.urandom(16)
        token32 = _make_token(master_key, ecu_id, ota_hash, vg_hash, nonce16)  # bytes(32)

        print("Token generation inputs (KDF/HMAC)")
        print(f"  ECU_ID          : {ecu_id}")
        print(f"  NONCE16         : {nonce16.hex()}")
        print(f"  VG_HASH         : {vg_hash.hex()}")
        print(f"  OTA_HASH        : {ota_hash.hex()}")
        print(f"  pq_verification : {pq_verification_result}")
        print(f"ECU {ecu_id} Token: {token32.hex()}")

        tokens_by_ecu[ecu_id] = {"nonce": nonce16, "token": token32}

    # [CAN-OTA-ADDED] Token 생성이 끝나면, Gateway↔ECU 구간을 CAN으로 수행하여
    # META + TOKEN + OTA(payload)를 전송합니다.
    try:
        _deliver_ota_over_can_to_ecus(
            pq_verification_result_bytes,
            vg_hash,
            ota_hash,
            tokens_by_ecu
        )
    except Exception as e:
        print('[ERROR] CAN OTA delivery failed:', e)

    print("===========================\n")



# =========================
# [ADDED] CAN attestation relay (Cloud request -> CAN read 8 bytes -> Cloud response)
# =========================

MOCK_SECURE_BOOT_SERIAL_MAP = {
    "A12": "0000000000000000",
    "B03": "1111111111111111",
    "C04": "2222222222222222",
}

CAN_CHANNEL = os.environ.get("GW_CAN_CHANNEL", "can0")
CAN_BUSTYPE = os.environ.get("GW_CAN_BUSTYPE", "socketcan")

ECU_CAN_ID_MAP = {
    # "A12": {"req_id": 0x700, "resp_id": 0x708, "req_data": "0100000000000000"},
    # "B03": {"req_id": 0x701, "resp_id": 0x709, "req_data": "0100000000000000"},
}

CAN_DEFAULT_REQ_ID = int(os.environ.get("GW_CAN_REQ_ID", "0x700"), 16)
CAN_DEFAULT_RESP_ID = int(os.environ.get("GW_CAN_RESP_ID", "0x708"), 16)
CAN_DEFAULT_REQ_DATA_HEX = os.environ.get("GW_CAN_REQ_DATA_HEX", "0100000000000000")
CAN_RX_TIMEOUT_SEC = float(os.environ.get("GW_CAN_RX_TIMEOUT_SEC", "1.0"))

# =========================
# [CAN-OTA-ADDED] Gateway ↔ ECU 전체 OTA를 CAN으로 수행하기 위한 프로토콜 설정
#  - ECU 구분: ecu_id -> ecu_addr(1바이트) -> Arbitration ID에 반영
#  - ID 규칙(표준 11-bit):
#      AttReq  : 0x600 + addr
#      AttResp : 0x650 + addr
#      META    : 0x700 + addr   (pq_bytes_len + pq_bytes + vg_hash(32) + ota_hash(32))
#      TOKEN   : 0x710 + addr   (token raw 32B)
#      OTA     : 0x720 + addr   (raw firmware bytes)
#      ACK     : 0x730 + addr   (0xAC, stage_code, ...)
#  - CAN 8바이트 제약: START/END 마커 + 8B 청크 전송
# =========================
CAN_START_MARK = bytes.fromhex('ff00ff00ff00ff00')
CAN_END_MARK   = bytes.fromhex('00ff00ff00ff00ff')

# ECU 주소 매핑(예시). 실제 프로젝트에 맞게 반드시 수정하세요.
# 예) 'A12' -> 0x12, 'B03' -> 0x03 처럼 1바이트 값으로 매핑
ECU_ADDR_MAP = {
    'A12': 0x12,
    'B03': 0x03,
    'C04': 0x04,
}

def _can_ids_for_ecu(ecu_id: str):
    addr = ECU_ADDR_MAP.get(ecu_id)
    if addr is None:
        return None
    return {
        'att_req':  0x600 + addr,
        'att_resp': 0x650 + addr,
        'meta':     0x700 + addr,
        'token':    0x710 + addr,
        'ota':      0x720 + addr,
        'ack':      0x730 + addr,
        'sig': 0x740 + addr,
    }

def _can_send8(bus, can_id: int, data: bytes, retry: int = 200, backoff_sec: float = 0.002):
    """
    ENOBUFS(105) 발생 시 backoff 하며 재시도.
    data는 길이 0~8 bytes 모두 허용 (dlc는 len(data)로 자동 설정됨)
    """
    msg = can.Message(arbitration_id=int(can_id), data=data[:8], is_extended_id=False)

    for _ in range(retry):
        try:
            bus.send(msg, timeout=0.2)
            return
        except can.CanError as e:
            emsg = str(e).lower()
            if ("no buffer space available" in emsg) or ("error code 105" in emsg) or ("105" in emsg):
                time.sleep(backoff_sec)
                continue
            raise
        except OSError as e:
            if getattr(e, "errno", None) == errno.ENOBUFS:
                time.sleep(backoff_sec)
                continue
            raise

    raise RuntimeError(f"CAN TX still blocked (ENOBUFS). can_id=0x{int(can_id):X}")

def _chunk8(b: bytes):
    for i in range(0, len(b), 8):
        yield b[i:i+8]   # ✅ 패딩 금지

def _can_send_stream(bus, can_id: int, payload: bytes, inter_frame_sleep: float = 0.002):
    _can_send8(bus, can_id, CAN_START_MARK)  # START/END는 8바이트여야 함

    for c in _chunk8(payload):
        _can_send8(bus, can_id, c)
        if inter_frame_sleep:
            time.sleep(inter_frame_sleep)

    _can_send8(bus, can_id, CAN_END_MARK)

def _can_recv_next(bus, timeout: float = 0.05):
    return bus.recv(timeout=timeout)

def _can_wait_ack(bus, ack_id: int, expect_stage: int, timeout_sec: float):
    deadline = time.monotonic() + float(timeout_sec)
    while time.monotonic() < deadline:
        rx = _can_recv_next(bus, timeout=0.05)
        if rx is None:
            continue
        if int(rx.arbitration_id) != int(ack_id):
            continue
        d = bytes(rx.data)
        if len(d) < 2:
            continue
        # ACK 포맷: [0xAC, stage_code, ...]
        if d[0] == 0xAC and d[1] == expect_stage:
            return True
        # stage=0x00(token fail), 0x03(hash mismatch) 등도 여기로 들어올 수 있음
        return False
    return False

def _request_attestation_can(bus, ecu_id: str, timeout_sec: float = 1.0) -> Optional[bytes]:
    ids = _can_ids_for_ecu(ecu_id)
    if ids is None:
        print(f'[CAN] ECU_ADDR_MAP에 ecu_id={ecu_id}가 없습니다. 건너뜁니다.')
        return None
    # 요청: data[0]=0xA1 (나머지 0)
    req = bytes([0xA1, 0,0,0,0,0,0,0])
    _can_send8(bus, ids['att_req'], req)

    deadline = time.monotonic() + float(timeout_sec)
    while time.monotonic() < deadline:
        rx = _can_recv_next(bus, timeout=0.05)
        if rx is None:
            continue
        if int(rx.arbitration_id) != int(ids['att_resp']):
            continue
        data = bytes(rx.data)
        if len(data) < 8:
            data = (data + b'\x00'*8)[:8]
        return data[:8]
    return None

_can_bus_lock = threading.Lock()

def _deliver_ota_over_can_to_ecus(pq_bytes: bytes, vg_hash: bytes, ota_hash: bytes, tokens_by_ecu: dict, file_data: bytes = None):
    """
    [ADDED override]
    기존 _deliver_ota_over_can_to_ecus 기능을 유지하면서,
      - SIG(0x740+addr)로 ECDSA 서명을 먼저 전송
      - Class C(토큰 미발급 ECU)도 VG에서 추출해 전송(토큰/토큰ACK 생략)
    """

    # file_data를 인자로 안 넘기면, 전역변수 file_data를 찾음(기존 코드 호환용)
    if file_data is None:
        if "file_data" not in globals():
            raise ValueError("file_data가 없습니다. _deliver_ota_over_can_to_ecus(..., file_data=...)로 넘겨주세요.")
        file_data = globals()["file_data"]

    if can is None:
        print('[WARN] python-can 미설치로 CAN OTA 전송을 수행할 수 없습니다. pip install python-can')
        return

    # ECDSA signature 전역변수 확인
    if "file_signature_ecdsa" not in globals() or globals()["file_signature_ecdsa"] is None:
        print("[WARN] file_signature_ecdsa is missing -> ECU(H/C) ECDSA verify는 실패할 수 있습니다.")
    sig_bytes = globals().get("file_signature_ecdsa", None)

    # -------------------------------
    # [ADDED] VG에서 ECU 목록 추출 (Class C 포함)
    #  - tokens_by_ecu에는 P/H만 들어있음(기존 정책)
    #  - vg_data(전역)를 파싱해서 allowed_transitions의 ecu를 모아 Class C까지 포함
    # -------------------------------
    ecu_set = set()
    try:
        vg_obj = None
        if "vg_data" in globals() and globals()["vg_data"] is not None:
            vg_obj = _try_json_loads_maybe_base64(globals()["vg_data"])
        if isinstance(vg_obj, dict):
            for entry in vg_obj.get("allowed_transitions", []):
                ecu_id = entry.get("ecu")
                if ecu_id:
                    ecu_set.add(ecu_id)
    except Exception:
        pass

    # tokens_by_ecu(P/H) + vg에서 나온 ECU(Class C 포함) 합치기
    for ecu_id in tokens_by_ecu.keys():
        ecu_set.add(ecu_id)

    ecu_list = sorted(list(ecu_set))

    with _can_bus_lock:
        bus = _open_can_bus()
        try:
            for ecu_id in ecu_list:
                ids = _can_ids_for_ecu(ecu_id)
                if ids is None:
                    print(f'[CAN] ECU 주소 매핑 없음 ecu={ecu_id} -> 제외')
                    continue

                pack = tokens_by_ecu.get(ecu_id)  # P/H면 존재, C면 None

                # 1) Attestation
                serial8 = _request_attestation_can(bus, ecu_id, timeout_sec=CAN_RX_TIMEOUT_SEC)
                if serial8 is None:
                    print(f'[CAN] Attestation timeout ecu={ecu_id} -> 제외')
                    continue

                serial_hex = serial8.hex()
                print(f'[CAN] Attestation received ecu={ecu_id} serial={serial_hex} (no check on gateway)')

                # 2) META (nonce16 포함)
                #    - P/H: 기존처럼 pack["nonce"] 사용
                #    - C  : nonce는 임의값(ECU에서 Token 계산에 쓰지 않으므로 의미 없음)
                if pack is not None:
                    nonce16 = pack["nonce"]
                    token_bytes = pack["token"]
                else:
                    nonce16 = os.urandom(16)
                    token_bytes = None

                send_name = file_name
                relpath = f"{send_name}"

                fn_b = relpath.encode("utf-8")

                meta_payload = (
                    nonce16
                    + struct.pack('>I', len(pq_bytes))
                    + pq_bytes
                    + vg_hash
                    + ota_hash
                    + struct.pack('>H', len(fn_b))
                    + fn_b
                )
                _can_send_stream(bus, ids['meta'], meta_payload)

                # 3) TOKEN (P/H만)
                if token_bytes is not None:
                    _can_send_stream(bus, ids['token'], token_bytes)

                    # ECU가 token 검증 후 ACK(0xAC, 0x01)를 보내도록 규약
                    ok = _can_wait_ack(bus, ids['ack'], expect_stage=0x01, timeout_sec=2.0)
                    if not ok:
                        print(f'[CAN] ECU {ecu_id} token ACK fail -> 제외')
                        continue
                else:
                    # Class C: token/ack 생략
                    print(f'[CAN] ECU {ecu_id} Class C -> skip TOKEN')

                # 4) [ADDED] SIG(ECDSA signature) 먼저 전송
                if sig_bytes is not None:
                    _can_send_stream(bus, ids['sig'], sig_bytes)
                else:
                    print(f'[CAN] ECU {ecu_id} SIG missing -> ECU(H/C)에서 ECDSA verify 실패 가능')

                # 5) OTA payload
                _can_send_stream(bus, ids['ota'], file_data, inter_frame_sleep=0.02)

                # ECU가 OTA 저장/해시검증 후 ACK(0xAC, 0x02)
                ok2 = _can_wait_ack(bus, ids['ack'], expect_stage=0x02, timeout_sec=10.0)
                if not ok2:
                    print(f'[CAN] ECU {ecu_id} OTA ACK fail')
                    continue

                print(f'[CAN] ECU {ecu_id} OTA delivered')

        finally:
            try:
                bus.shutdown()
            except Exception:
                pass


def _try_json_loads_maybe_base64(payload_bytes: bytes):
    try:
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        try:
            decoded = base64.b64decode(payload_bytes)
            return json.loads(decoded.decode("utf-8"))
        except Exception:
            return None


def _open_can_bus():
    if can is None:
        raise RuntimeError("python-can is not available. Install with: pip install python-can")
    return can.interface.Bus(channel=CAN_CHANNEL, interface=CAN_BUSTYPE)


def _ecu_can_params(ecu_id: str):
    cfg = ECU_CAN_ID_MAP.get(ecu_id)
    if cfg is None:
        req_id = CAN_DEFAULT_REQ_ID
        resp_id = CAN_DEFAULT_RESP_ID
        req_data_hex = CAN_DEFAULT_REQ_DATA_HEX
    else:
        req_id = int(cfg.get("req_id", CAN_DEFAULT_REQ_ID))
        resp_id = int(cfg.get("resp_id", CAN_DEFAULT_RESP_ID))
        req_data_hex = str(cfg.get("req_data", CAN_DEFAULT_REQ_DATA_HEX))
    try:
        req_data = bytes.fromhex(req_data_hex)
    except Exception:
        req_data = bytes.fromhex(CAN_DEFAULT_REQ_DATA_HEX)
    if len(req_data) != 8:
        req_data = (req_data + b"\x00" * 8)[:8]
    return req_id, resp_id, req_data


def read_secure_boot_serial_8bytes_over_can(ecu_id: str) -> Optional[bytes]:
    req_id, resp_id, req_data = _ecu_can_params(ecu_id)

    with _can_bus_lock:
        bus = _open_can_bus()
        try:
            msg = can.Message(arbitration_id=req_id, data=req_data, is_extended_id=False)
            bus.send(msg)

            deadline = time.monotonic() + CAN_RX_TIMEOUT_SEC
            while time.monotonic() < deadline:
                rx = bus.recv(timeout=0.05)
                if rx is None:
                    continue
                if int(rx.arbitration_id) != int(resp_id):
                    continue
                data = bytes(rx.data)
                if len(data) < 8:
                    data = (data + b"\x00" * 8)[:8]
                else:
                    data = data[:8]
                return data
            return None
        finally:
            try:
                bus.shutdown()
            except Exception:
                pass


def _make_attestation_response_payload(request_id: str, reports: list) -> bytes:
    payload = {
        "request_id": request_id,
        "reports": reports,
        "ts_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gw_id": "GW-001",
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def on_attestation_request(client, userdata, msg):
    payload = _try_json_loads_maybe_base64(msg.payload)
    if not isinstance(payload, dict):
        return

    request_id = payload.get("request_id")
    ecu_list = payload.get("ecu_list")
    if not request_id or not isinstance(ecu_list, list):
        return

    reports = []

    # 버스를 ECU마다 열지 말고 1번만 열어서 처리 (성능/안정성)
    with _can_bus_lock:
        bus = _open_can_bus()
        try:
            for ecu in ecu_list:
                ecu_id = str(ecu)

                # ✅ ECU 프로토콜과 동일한 방식 사용
                serial_bytes = _request_attestation_can(bus, ecu_id, timeout_sec=CAN_RX_TIMEOUT_SEC)

                if serial_bytes is None:
                    print(f"[GW] attestation timeout ecu={ecu_id}")
                    continue

                reports.append({
                    "ecu": ecu_id,
                    "secure_boot_serial": serial_bytes.hex()
                })
        finally:
            try:
                bus.shutdown()
            except Exception:
                pass

    resp_bytes = _make_attestation_response_payload(str(request_id), reports)
    client.publish(attestation_response_topic, resp_bytes, qos=2)



# =========================
# 파일 저장 + 하이브리드 검증
# =========================


def save_file_if_complete():
    global vg_data, vg_sig_ecdsa, vg_sig_pqc
    global file_name, file_data, file_signature_ecdsa, file_signature_pqc

    if file_name is None or file_data is None:
        return
    if file_signature_ecdsa is None or file_signature_pqc is None:
        return

    save_path = os.path.join(temp_dir, file_name)
    try:
        with open(save_path, "wb") as f:
            f.write(file_data)
        print(f"[INFO] File saved: {save_path}")
    except Exception as e:
        print("[ERROR] Failed to save file:", e)
        return

    ok_ecdsa = verify_ecdsa_signature(public_key, file_data, file_signature_ecdsa)
    try:
        ok_pqc = pqc_verify(file_data, file_signature_pqc)
    except Exception as e:
        print("[ERROR] PQC verify failed:", e)
        ok_pqc = False

    if verify_vg() and ok_ecdsa and ok_pqc:
        print("[SUCCESS] Hybrid verification passed (ECDSA + PQC).")
        print("[SUCCESS] OTA verified")
        generate_tokens()   
    else:
        print("[FAIL] Hybrid verification failed.")
        print(f"  - ECDSA: {'OK' if ok_ecdsa else 'NG'}")
        print(f"  - PQC  : {'OK' if ok_pqc else 'NG'}")
        try:
            os.remove(save_path)
            print(f"[INFO] Corrupted file deleted: {save_path}")
        except Exception:
            pass


    # 다음 파일을 위해 상태 초기화
    file_name = None
    file_data = None
    file_signature_ecdsa = None
    file_signature_pqc = None


# =========================
# MQTT 콜백
# =========================


def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("Connected successfully.")
    else:
        print(f"Failed to connect, return code {reasonCode}")


def on_disconnect(client, userdata, flags, rc=0):
    print("Disconnected:", rc)


def on_message(client, userdata, msg):
    global vg_data, vg_sig_ecdsa, vg_sig_pqc
    global file_name, file_data, file_signature_ecdsa, file_signature_pqc

    topic = msg.topic
    payload = msg.payload

    if topic == name_topic:
        file_name = payload.decode("utf-8")
        print(f"[RECV] File name: {file_name}")
    elif topic == file_topic:
        try:
            file_data = base64.b64decode(payload)
            print(f"[RECV] File data received, size={len(file_data)} bytes")
        except Exception as e:
            print("[ERROR] Failed to decode file data:", e)
            file_data = None
    elif topic == signature_topic:
        try:
            file_signature_ecdsa = base64.b64decode(payload)
            print(f"[RECV] ECDSA signature received, len={len(file_signature_ecdsa)}")
        except Exception as e:
            print("[ERROR] Failed to decode ECDSA signature:", e)
            file_signature_ecdsa = None
    elif topic == pqc_signature_topic:
        try:
            file_signature_pqc = base64.b64decode(payload)
            print(f"[RECV] PQC(Falcon) signature received, len={len(file_signature_pqc)}")
        except Exception as e:
            print("[ERROR] Failed to decode PQC signature:", e)
            file_signature_pqc = None
    elif msg.topic == vg_topic:
        vg_data = base64.b64decode(payload)
        print("[RECV] Version Graph JSON:")
        print(vg_data.decode())
    elif msg.topic == vg_sig_topic:
        try:
            vg_sig_ecdsa = base64.b64decode(payload)
            print(f"[RECV] VG ECDSA signature received, len={len(vg_sig_ecdsa)}")
        except Exception as e:
            print("[ERROR] Failed to decode VG ECDSA signature:", e)
            vg_sig_ecdsa = None
    elif msg.topic == vg_pqc_sig_topic:
        vg_sig_pqc = base64.b64decode(msg.payload)
        try:
            vg_sig_pqc = base64.b64decode(payload)
            print(f"[RECV] VG PQC(Falcon) signature received, len={len(vg_sig_pqc)}")
        except Exception as e:
            print("[ERROR] Failed to decode VG PQC signature:", e)
            vg_sig_pqc = None
    else:
        return

    save_file_if_complete()


# =========================
# 메인 함수
# =========================


def main():
    global public_key

    try:
        public_key = load_ecdsa_public_key(PUBLIC_KEY_PATH)
        print(f"[INFO] ECDSA public key loaded from: {PUBLIC_KEY_PATH}")
    except FileNotFoundError:
        print(f"[FATAL] Public key file not found: {PUBLIC_KEY_PATH}")
        return
    except Exception as e:
        print("[FATAL] Failed to load ECDSA public key:", e)
        return

    try:
        init_pqc()
    except Exception as e:
        print("[FATAL] Failed to init PQC library:", e)
        return

    client = mqtt.Client()
    client.username_pw_set(userId, userPw)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    # [ADDED] topic-specific callback for attestation request (do not change existing on_message)
    client.message_callback_add(attestation_request_topic, on_attestation_request)

    client.connect(brokerIp, port, keepalive=60)

    client.subscribe(vg_topic, qos=2)
    client.subscribe(vg_sig_topic, qos=2)
    client.subscribe(vg_pqc_sig_topic, qos=2)

    client.subscribe(name_topic, qos=2)
    client.subscribe(file_topic, qos=2)
    client.subscribe(signature_topic, qos=2)
    client.subscribe(pqc_signature_topic, qos=2)

    # [ADDED] subscribe attestation request from Cloud
    client.subscribe(attestation_request_topic, qos=2)

    client.loop_forever()


if __name__ == "__main__":
    main()