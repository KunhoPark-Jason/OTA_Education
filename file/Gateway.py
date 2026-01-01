import paho.mqtt.client as mqtt
import os
import base64
import json
import hashlib
import hmac
import time
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
import uuid

# [ADDED] optional python-can
try:
    import can  # type: ignore
except Exception:
    can = None

# =========================
# Gateway internal secret (Token HMAC key)
# =========================

K_INTERNAL = b"gateway_internal_secret_key"

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
os.makedirs(certs_pqc_dir, exist_ok=True)
PQC_PRIVKEY_PATH = os.path.join(certs_pqc_dir, "pqc_private.key")  # 필요시 사용
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

PQC_LIB_NAME = "libpqc_sig.so"
PQC_ALG_NAME = b"Falcon-1024"
PQC_MAX_SIG_LEN = 4096

_pqc = None  # ctypes.CDLL 핸들


def init_pqc():
    """
    libpqc_sig.so 를 로드하고,
    pqc_init(alg_name, privkey_path, pubkey_path)를 호출한다.
    이때 키 파일이 없으면 .so 안에서 자동으로 생성한다.
    """
    global _pqc

    if _pqc is not None:
        return

    lib = ctypes.CDLL(PQC_LIB_NAME)

    # 함수 프로토타입 설정
    lib.pqc_init.argtypes = [c_char_p, c_char_p, c_char_p]
    lib.pqc_init.restype = c_int

    lib.pqc_sign.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), POINTER(c_size_t)
    ]
    lib.pqc_sign.restype = c_int

    if hasattr(lib, "pqc_cleanup"):
        lib.pqc_cleanup.argtypes = []
        lib.pqc_cleanup.restype = None

    alg = PQC_ALG_NAME
    priv_path = PQC_PRIVKEY_PATH.encode("utf-8")
    pub_path = PQC_PUBKEY_PATH.encode("utf-8")

    rc = lib.pqc_init(alg, priv_path, pub_path)
    if rc != 0:
        raise RuntimeError(f"pqc_init failed with code {rc}")

    _pqc = lib
    print(f"[INFO] PQC(Falcon) library loaded: {PQC_LIB_NAME}")
    print(f"[INFO] PQC private key : {PQC_PRIVKEY_PATH}")
    print(f"[INFO] PQC public  key : {PQC_PUBKEY_PATH}")


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
    vg_hash = hashlib.sha256(vg_data).digest()

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

    for entry in vg["allowed_transitions"]:
        ecu_id = entry["ecu"]
        capability = entry.get("ECU_Type", "C")

        if capability not in ("P", "H"):
            print(f"[INFO] ECU {ecu_id} is Class {capability} → No Token issued")
            continue

        token_input = (
            pq_verification_result_bytes +
            ecu_id.encode("utf-8") +
            vg_hash
        )

        token = hmac.new(
            K_INTERNAL,
            token_input,
            hashlib.sha256
        ).hexdigest()

        print("\nToken generation inputs")
        print(f"  ECU_ID          : {ecu_id}")
        print(f"  VG_HASH         : {vg_hash.hex()}")
        print(f"  OTA_HASH        : {ota_hash.hex()}")
        print(f"  pq_verification : {pq_verification_result}")
        print(f"  HMAC_MESSAGE  : "
              f"{pq_verification_result_bytes.hex()} | "
              f"{ecu_id.encode('utf-8').hex()} | "
              f"{vg_hash.hex()}")

        print(f"ECU {ecu_id} Token: {token}")

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

_can_bus_lock = threading.Lock()


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
    return can.interface.Bus(channel=CAN_CHANNEL, bustype=CAN_BUSTYPE)


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

    for ecu in ecu_list:
        ecu_id = str(ecu)

    # [MOCK] CAN 대신 하드코딩된 serial 사용
        serial_hex = MOCK_SECURE_BOOT_SERIAL_MAP.get(ecu_id)
        if not serial_hex:
            continue  # 맵에 없으면 report 안 보냄(= Pub에서 no_attestation_report로 제외)

    # 혹시 모를 포맷 보정: 16 hex(8 bytes)로 맞춤
        serial_hex = serial_hex.lower().replace("0x", "")
        serial_hex = (serial_hex + "0"*16)[:16]

        reports.append({
        "ecu": ecu_id,
        "secure_boot_serial": serial_hex
        })

    # can 활성화 시 활성화
    
    # for ecu in ecu_list:
    #     ecu_id = str(ecu)
    #     try:
    #         serial_bytes = read_secure_boot_serial_8bytes_over_can(ecu_id)
    #     except Exception as e:
    #         serial_bytes = None

    #     if serial_bytes is None:
    #         continue

    #     serial_hex = serial_bytes.hex()
    #     reports.append({
    #         "ecu": ecu_id,
    #         "secure_boot_serial": serial_hex
    #     })

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
