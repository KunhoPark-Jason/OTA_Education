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

# [ADDED] secure-boot / version-graph-plan / attestation
import threading
import uuid
import re
import copy
import time


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

# [ADDED] Attestation topics (Gateway ↔ Cloud)
attestation_request_topic = "attestation/request"
attestation_response_topic = "attestation/response"

broker_ip = "10.121.72.148"                    # 필요시 수정

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
PQC_PRIVKEY_PATH = os.path.join(certs_pqc_dir, "pqc_private.key")
PQC_PUBKEY_PATH = os.path.join(certs_pqc_dir, "pqc_public.key")

# [ADDED] Cloud-managed TXT files
SECURE_BOOT_DB_PATH = os.path.join(base_dir, "secure_boot_db.txt")
VERSION_GRAPH_PLAN_PATH = os.path.join(base_dir, "version_graph_plan.txt")

# =========================
# PQC(Falcon-512)용 ctypes 래퍼
# =========================

# libpqc_sig.so 는 /usr/local/lib 에 설치되어 있다고 가정
PQC_LIB_NAME = "libpqc_sig.so"
PQC_ALG_NAME = b"Falcon-1024"
PQC_MAX_SIG_LEN = 4096

_pqc = None  # ctypes.CDLL 핸들


def _require_pqc_key_files_exist():
    """PQC 키 파일이 없으면 종료(자동 생성 방지)."""
    missing = []
    for p in (PQC_PRIVKEY_PATH, PQC_PUBKEY_PATH):
        if not os.path.isfile(p) or os.path.getsize(p) <= 0:
            missing.append(p)
    if missing:
        msg = "\n".join([
            "[FATAL] PQC key file(s) missing or empty:",
            *[f"  - {m}" for m in missing],
            "[HINT] 키 파일을 먼저 배치한 뒤 다시 실행하세요. (이 코드는 키 자동 생성을 하지 않습니다.)",
        ])
        raise SystemExit(msg)


def init_pqc():
    """
    libpqc_sig.so 를 로드하고,
    pqc_init(alg_name, privkey_path, pubkey_path)를 호출한다.
    이때 키 파일이 없으면 자동 생성하지 않고 즉시 종료한다.
    """
    global _pqc

    if _pqc is not None:
        return

    # ✅ 핵심: .so를 로드하기 전에 키 파일 존재/크기 체크 → 없으면 즉시 종료
    _require_pqc_key_files_exist()

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
# [ADDED] Secure boot DB + VG Plan + Attestation helpers
# =========================


def _read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_secure_boot_db_txt(path: str) -> dict:
    """
    secure_boot_db.txt 예시(형식 유연 파싱):
      ecu_id : A01, secure_boot_serial : 0000000000000000
      ecu_id:A12 secure_boot_serial:0123ABCD...
      A12,0000000000000000
    반환: { "A12": "0000...", ... }
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"secure_boot_db.txt not found: {path}")

    raw = _read_text_file(path)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    mapping = {}
    for ln in lines:
        m = re.search(r"(ecu_id|ecu)\s*[:=]\s*([A-Za-z0-9_-]+)", ln)
        n = re.search(r"(secure_boot_serial|sb_serial|serial)\s*[:=]\s*([A-Za-z0-9]+)", ln)
        if m and n:
            mapping[m.group(2)] = n.group(2)
            continue

        parts = re.split(r"\s*,\s*", ln)
        if len(parts) >= 2:
            ecu = parts[0].strip()
            serial = parts[1].strip()
            if ecu and serial:
                mapping[ecu] = serial

    return mapping


def load_version_graph_plan_txt(path: str) -> dict:
    """
    version_graph_plan.txt 는 JSON 텍스트로 가정.
    (allowed_transitions/denied_transitions/cross_dependencies 등 모든 rule 포함)
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"version_graph_plan.txt not found: {path}")

    raw = _read_text_file(path).strip()
    plan = json.loads(raw)
    if not isinstance(plan, dict):
        raise ValueError("version_graph_plan.txt must be a JSON object")
    return plan


def extract_ecus_from_allowed_transitions(vg_plan: dict) -> list:
    allowed = vg_plan.get("allowed_transitions", [])
    ecu_list = []
    for t in allowed:
        if isinstance(t, dict):
            ecu = t.get("ecu") or t.get("ecu_id")
            if ecu:
                ecu_list.append(str(ecu))
    return sorted(list(dict.fromkeys(ecu_list)))


def _try_json_loads_maybe_base64(payload_bytes: bytes):
    try:
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        try:
            decoded = base64.b64decode(payload_bytes)
            return json.loads(decoded.decode("utf-8"))
        except Exception:
            return None


def request_attestation_for_ecus(client: mqtt.Client, ecu_list: list, timeout_sec: int = 10) -> dict:
    """
    Cloud → Gateway: allowed_transitions에 포함된 ECU만 attestation 요청.
    Gateway → Cloud: attestation_response_topic 으로 응답.
    반환: { "A12": "SECURE_BOOT_SERIAL", ... }
    """
    req_id = str(uuid.uuid4())
    event = threading.Event()
    box = {"att": None}

    def _on_message(_client, _userdata, msg):
        if msg.topic != attestation_response_topic:
            return
        payload = _try_json_loads_maybe_base64(msg.payload)
        if not isinstance(payload, dict):
            return
        if payload.get("request_id") != req_id:
            return
        box["att"] = payload
        event.set()

    client.subscribe(attestation_response_topic, qos=2)
    client.on_message = _on_message

    req = {
        "request_id": req_id,
        "ecu_list": ecu_list,
        "ts_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    client.publish(attestation_request_topic, json.dumps(req).encode("utf-8"), qos=2)

    deadline = time.monotonic() + float(timeout_sec)
    while time.monotonic() < deadline and not event.is_set():
        client.loop(timeout=0.2)

    if not event.is_set() or not isinstance(box["att"], dict):
        return {}

    payload = box["att"]
    reports = payload.get("reports", payload.get("attestations", payload.get("data", [])))

    att_map = {}
    if isinstance(reports, list):
        for r in reports:
            if not isinstance(r, dict):
                continue
            ecu = r.get("ecu") or r.get("ecu_id")
            serial = r.get("secure_boot_serial") or r.get("sb_serial") or r.get("serial")
            if ecu and serial:
                att_map[str(ecu)] = str(serial)

    if isinstance(reports, dict):
        for ecu, serial in reports.items():
            if ecu and serial:
                att_map[str(ecu)] = str(serial)

    return att_map


def filter_allowed_transitions_by_secure_boot(vg_plan: dict, secure_boot_db: dict, att_map: dict):
    allowed = vg_plan.get("allowed_transitions", [])
    kept = []
    excluded = []

    for t in allowed:
        if not isinstance(t, dict):
            excluded.append({"transition": t, "reason": "invalid_format"})
            continue

        ecu = t.get("ecu") or t.get("ecu_id")
        if not ecu:
            excluded.append({"transition": t, "reason": "missing_ecu"})
            continue

        ecu = str(ecu)
        expected_serial = secure_boot_db.get(ecu)
        actual_serial = att_map.get(ecu)

        if expected_serial is None:
            excluded.append({"transition": t, "ecu": ecu, "reason": "no_secure_boot_db_entry"})
            continue

        if actual_serial is None:
            excluded.append({"transition": t, "ecu": ecu, "reason": "no_attestation_report"})
            continue

        if str(expected_serial) != str(actual_serial):
            excluded.append({
                "transition": t,
                "ecu": ecu,
                "reason": "secure_boot_serial_mismatch",
                "expected": str(expected_serial),
                "actual": str(actual_serial),
            })
            continue

        kept.append(t)

    return kept, excluded


def build_vg_bytes_from_plan_and_attestation(
    client: mqtt.Client,
    plan_path: str,
    secure_boot_db_path: str,
    validity_seconds: int,
    attestation_timeout_sec: int = 10,
):
    """
    version_graph_plan.txt를 그대로 불러오고,
    allowed_transitions만 secure boot serial 정상 여부로 삭제/유지하여 최종 VG를 생성한다.
    """
    secure_boot_db = load_secure_boot_db_txt(secure_boot_db_path)
    vg_plan = load_version_graph_plan_txt(plan_path)

    ecu_list = extract_ecus_from_allowed_transitions(vg_plan)
    att_map = request_attestation_for_ecus(client, ecu_list, timeout_sec=attestation_timeout_sec)

    kept, excluded = filter_allowed_transitions_by_secure_boot(vg_plan, secure_boot_db, att_map)

    final_vg = copy.deepcopy(vg_plan)
    final_vg["allowed_transitions"] = kept

    valid_from, valid_until = generate_vg_validity(validity_seconds)
    final_vg["valid_from"] = valid_from
    final_vg["valid_until"] = valid_until

    vg_bytes = json.dumps(final_vg, sort_keys=True).encode("utf-8")
    return vg_bytes, {
        "requested_ecus": ecu_list,
        "attested_ecus": sorted(list(att_map.keys())),
        "excluded": excluded,
        "kept_count": len(kept),
        "excluded_count": len(excluded),
    }


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

        # [ADDED] version_graph_plan.txt(전체 rule) 로드 + allowed_transitions만 Secure Boot/Attestation 기반으로 필터링
        vg_bytes_from_plan, vg_debug = build_vg_bytes_from_plan_and_attestation(
            client=client,
            plan_path=VERSION_GRAPH_PLAN_PATH,
            secure_boot_db_path=SECURE_BOOT_DB_PATH,
            validity_seconds=60,
            attestation_timeout_sec=10,
        )
        vg_bytes = vg_bytes_from_plan

        vg_ecdsa_sig = sign_data_ecdsa(private_key, vg_bytes)
        vg_pqc_sig = pqc_sign(vg_bytes)

        client.publish(vg_topic, base64.b64encode(vg_bytes), qos=2)
        client.publish(vg_sig_topic, base64.b64encode(vg_ecdsa_sig), qos=2)
        client.publish(vg_pqc_sig_topic, base64.b64encode(vg_pqc_sig), qos=2)

        # [ADDED] visibility (필요한 정보만)
        print(f"[INFO] Version Graph published (kept={vg_debug.get('kept_count')}, excluded={vg_debug.get('excluded_count')})")
        if vg_debug.get("excluded_count", 0) > 0:
            print("[INFO] Excluded ECUs due to secure boot mismatch or missing data:")
            for item in vg_debug.get("excluded", [])[:50]:
                ecu = item.get("ecu") or (item.get("transition", {}) if isinstance(item.get("transition"), dict) else {}).get("ecu")
                reason = item.get("reason")
                print(f"  - ecu={ecu}, reason={reason}")

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

    # [ADDED] show TXT paths being used by Cloud
    print(f"Using secure boot DB   : {SECURE_BOOT_DB_PATH}")
    print(f"Using VG plan TXT      : {VERSION_GRAPH_PLAN_PATH}")

    send_file_to_broker(
        broker_ip,
        username,
        password,
        privkey_path=privkey_path,
        privkey_password=privkey_password,
    )
