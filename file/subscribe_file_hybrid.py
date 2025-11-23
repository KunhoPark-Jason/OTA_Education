import paho.mqtt.client as mqtt
import os
import base64
import ctypes
from ctypes import c_uint8, c_size_t, c_int, c_char_p, POINTER, byref

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

# =========================
# MQTT 및 경로 설정
# =========================

name_topic = "updates/name"
file_topic = "updates/file"
signature_topic = "updates/signature"          # ECDSA 서명 토픽
pqc_signature_topic = "updates/pqc_signature"  # PQC(Falcon) 서명 토픽

userId = "admin"
userPw = "1234"
brokerIp = "192.168.1.170"
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
file_name = None
file_data = None
file_signature_ecdsa = None
file_signature_pqc = None
public_key = None  # ECDSA 공개키

# =========================
# PQC(Falcon-512)용 ctypes 래퍼
# =========================

PQC_LIB_NAME = "libpqc_sig.so"
PQC_ALG_NAME = b"Falcon-512"
PQC_MAX_SIG_LEN = 4096

_pqc = None  # ctypes.CDLL 핸들


def init_pqc():
    """
    libpqc_sig.so 를 로드하고,
    pqc_init(alg_name, privkey_path, pubkey_path)를 호출한다.
    """
    global _pqc

    if _pqc is not None:
        return

    lib = ctypes.CDLL(PQC_LIB_NAME)

    lib.pqc_init.argtypes = [c_char_p, c_char_p, c_char_p]
    lib.pqc_init.restype = c_int

    lib.pqc_verify.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t
    ]
    lib.pqc_verify.restype = c_int

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


# =========================
# 파일 저장 + 하이브리드 검증
# =========================


def save_file_if_complete():
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

    if ok_ecdsa and ok_pqc:
        print("[SUCCESS] Hybrid verification passed (ECDSA + PQC).")
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

    client.connect(brokerIp, port, keepalive=60)

    client.subscribe(name_topic, qos=2)
    client.subscribe(file_topic, qos=2)
    client.subscribe(signature_topic, qos=2)
    client.subscribe(pqc_signature_topic, qos=2)

    client.loop_forever()


if __name__ == "__main__":
    main()

