import paho.mqtt.client as mqtt
import os
import base64
import json
import ctypes
from ctypes import c_uint8, c_size_t, c_int, c_char_p, POINTER, byref

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone


# =========================
# MQTT 설정
# =========================

vg_topic = "updates/vg"
vg_sig_topic = "updates/vg/signature"
vg_pqc_sig_topic = "updates/vg/pqc_signature"

name_topic = "updates/name"
file_topic = "updates/file"
signature_topic = "updates/signature"          # ECDSA 서명 토픽
pqc_signature_topic = "updates/pqc_signature"  # PQC(Falcon) 서명 토픽

broker_ip = "10.173.149.148"                    # 필요시 수정

# 현재 파일 기준 경로 설정
base_dir = os.path.dirname(os.path.abspath(__file__))  # /home/sea/OTA/OTA_Education/file

# 전송할 파일을 넣어둘 디렉터리: /home/sea/OTA/OTA_Education/file/upload
publish_dir = os.path.join(base_dir, "upload")
os.makedirs(publish_dir, exist_ok=True)

# ECDSA 키 경로: /home/sea/OTA/OTA_Education/certs/ecdsa
certs_root_dir = os.path.abspath(os.path.join(base_dir, os.pardir, "certs"))
certs_ecdsa_dir = os.path.join(certs_root_dir, "ecdsa")
DEFAULT_PRIVKEY_PATH = os.path.join(certs_ecdsa_dir, "ecdsa_private.pem")

# PQC 키 경로: /home/sea/OTA/OTA_Education/certs/pqc
certs_pqc_dir = os.path.join(certs_root_dir, "pqc")
os.makedirs(certs_pqc_dir, exist_ok=True)
PQC_PRIVKEY_PATH = os.path.join(certs_pqc_dir, "pqc_private.key")
PQC_PUBKEY_PATH = os.path.join(certs_pqc_dir, "pqc_public.key")

# =========================
# PQC(Falcon-512)용 ctypes 래퍼
# =========================

# libpqc_sig.so 는 /usr/local/lib 에 설치되어 있다고 가정
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


def pqc_sign(data: bytes) -> bytes:
    """
    data(파일 내용)에 대해 Falcon-512 서명을 수행하고, 서명 바이트열을 반환.
    """
    if _pqc is None:
        raise RuntimeError("PQC library not initialized. Call init_pqc() first.")

    msg_len = len(data)
    if msg_len == 0:
        raise ValueError("Cannot sign empty message")

    msg_buf = (c_uint8 * msg_len).from_buffer_copy(data)
    sig_buf = (c_uint8 * PQC_MAX_SIG_LEN)()
    sig_len = c_size_t(PQC_MAX_SIG_LEN)

    rc = _pqc.pqc_sign(
        msg_buf,
        c_size_t(msg_len),
        sig_buf,
        byref(sig_len)
    )
    if rc != 0:
        raise RuntimeError(f"pqc_sign failed with code {rc}")

    return bytes(sig_buf[: sig_len.value])


# =========================
# Valid Time Setting
# =========================


def generate_vg_validity(duration_seconds: int):
    """
    Generate valid_from and valid_until timestamps for Version Graph.

    - valid_from : current UTC time
    - valid_until: valid_from + duration_seconds
    """

    valid_from_dt = datetime.now(timezone.utc)
    valid_until_dt = valid_from_dt + timedelta(seconds=duration_seconds)

    valid_from = valid_from_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_until = valid_until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    return valid_from, valid_until


# =========================
# VG 생성
# =========================


def build_version_graph(validity_seconds: int):
    """
    Build Version Graph (VG) with dynamically generated validity period.
    """

    valid_from, valid_until = generate_vg_validity(validity_seconds)

    vg = {
        "vg_id": "VG-OTA-2025-001",
        "version": 3,
        "campaign_id": "CAMP2025-03",

        "allowed_transitions": [
            {
                "ecu": "A12",
                "from": "2.1",
                "to": "3.0",
                "ECU_Type": "P"
            },
            {
                "ecu": "B03",
                "from": "1.0",
                "to": "2.0",
                "ECU_Type": "H"
            },
            {
                "ecu": "C04",
                "from": "2.0",
                "to": "2.1",
                "ECU_Type": "C"
            }
        ],

        # ===============================
        # Explicitly denied transitions
        # ===============================
        "denied_transitions": [
            {
                "ecu": "B03",
                "from": "1.0",
                "to": "3.0",
                "reason": "safety_violation"
            }
        ],

        # ===============================
        # Cross-ECU dependency constraints
        # ===============================
        "cross_dependencies": [
            {
                "ecu_set": ["A12", "B03"],
                "versions": {
                    "A12": "3.0",
                    "B03": "1.0"
                },
                "valid": False,
                "reason": "incompatible braking logic"
            }
        ],

        # ===============================
        # Rollback prevention policy
        # ===============================
        "rollback_policies": [
            {
                "ecu": "A12",
                "min_version": "2.1"
            }
        ],

        "valid_from": valid_from,
        "valid_until": valid_until
        #"valid_until": "2025-12-19T04:32:53Z"
    }

    return json.dumps(vg, sort_keys=True).encode("utf-8")


# =========================
# ECDSA 관련 유틸 함수들
# =========================


def load_ecdsa_private_key(key_path: str, password: str = None):
    """
    PEM 형식의 ECDSA 개인키를 로드한다.
    """
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()

    if password:
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = None

    private_key = serialization.load_pem_private_key(
        key_data,
        password=password_bytes,
        backend=default_backend()
    )
    return private_key


def sign_data_ecdsa(private_key, data: bytes) -> bytes:
    """
    data(바이트열)에 대해 ECDSA(SHA256) 서명을 수행하고,
    서명값(바이너리)을 반환한다.
    """
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature


# =========================
# 파일 → MQTT 메시지 생성
# =========================


def make_message_and_signatures(file_path: str, private_key):
    """
    파일을 읽어서:
      - message       : base64 인코딩된 파일 데이터
      - ecdsa_sig_b64 : ECDSA 서명(base64)
      - pqc_sig_b64   : Falcon-512 서명(base64)
    를 생성해 반환한다.
    """
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    # MQTT 전송용 파일 내용 (base64)
    message = base64.b64encode(file_bytes)

    # 1) ECDSA 서명
    ecdsa_sig = sign_data_ecdsa(private_key, file_bytes)
    ecdsa_sig_b64 = base64.b64encode(ecdsa_sig)

    # 2) PQC(Falcon) 서명
    pqc_sig = pqc_sign(file_bytes)
    pqc_sig_b64 = base64.b64encode(pqc_sig)

    return message, ecdsa_sig_b64, pqc_sig_b64


# =========================
# MQTT 콜백
# =========================


def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("Connected successfully.")
    else:
        print("Failed to connect. Return code:", reasonCode)


def on_disconnect(client, userdata, flags, rc=0):
    print("Disconnected, RC:", rc)


def on_publish(client, userdata, mid):
    print("Message published, MID:", mid)


# =========================
# 메인 동작
# =========================


def send_file_to_broker(broker_ip, username, password,
                        privkey_path, privkey_password=None,
                        port=1883):

    # ECDSA 개인키 로드
    private_key = load_ecdsa_private_key(privkey_path, privkey_password)
    print(f"ECDSA private key loaded from: {privkey_path}")

    # PQC 라이브러리 초기화 (이 시점에 PQC 키 자동 생성 또는 로드)
    init_pqc()

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish

    try:
        client.username_pw_set(username, password)
        client.connect(broker_ip, port)

        vg_bytes = build_version_graph(60)

        vg_ecdsa_sig = sign_data_ecdsa(private_key, vg_bytes)
        vg_pqc_sig = pqc_sign(vg_bytes)

        client.publish(vg_topic, base64.b64encode(vg_bytes), qos=2)
        client.publish(vg_sig_topic, base64.b64encode(vg_ecdsa_sig), qos=2)
        client.publish(vg_pqc_sig_topic, base64.b64encode(vg_pqc_sig), qos=2)

        print("[INFO] Version Graph published")

        while True:
            for file in os.listdir(publish_dir):
                publish_file = os.path.join(publish_dir, file)
                try:
                    message, ecdsa_sig_b64, pqc_sig_b64 = make_message_and_signatures(
                        publish_file, private_key
                    )
                    file_name = os.path.basename(publish_file)

                    client.loop_start()

                    client.publish(name_topic, file_name, qos=2)
                    client.publish(file_topic, message, qos=2)
                    client.publish(signature_topic, ecdsa_sig_b64, qos=2)
                    client.publish(pqc_signature_topic, pqc_sig_b64, qos=2)

                    client.loop_stop()

                    print(f"Success sending file(updates/name): {file_name}")

                except Exception as e:
                    print("Error:", e)
                    break
                finally:
                    try:
                        os.remove(publish_file)
                        print(f"File deleted: {publish_file}")
                    except FileNotFoundError:
                        pass
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    print("=" * 80)
    username = "admin"
    password = "1234"

    privkey_path = DEFAULT_PRIVKEY_PATH
    privkey_password = None

    print(f"Using ECDSA private key: {privkey_path}")
    print(f"Using PQC private key  : {PQC_PRIVKEY_PATH}")
    print(f"Using PQC public key   : {PQC_PUBKEY_PATH}")

    send_file_to_broker(
        broker_ip,
        username,
        password,
        privkey_path=privkey_path,
        privkey_password=privkey_password,
    )

