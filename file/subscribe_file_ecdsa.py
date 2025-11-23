import paho.mqtt.client as mqtt
import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend


name_topic = "updates/name"
file_topic = "updates/file"
signature_topic = "updates/signature"  # ECDSA 서명 토픽 추가

userId = "admin"
userPw = "1234"
brokerIp = '192.168.1.170'
port = 1883

temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp")
os.makedirs(temp_dir, exist_ok=True)

# ECDSA 공개키 파일 경로 (필요에 따라 수정 가능)
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecdsa_public.pem")

file_name = None
file_data = None
file_signature = None   # 서명 저장용
public_key = None       # 로드된 ECDSA 공개키


# =========================
# ECDSA 관련 함수
# =========================

def load_ecdsa_public_key(path: str):
    """
    PEM 형식의 ECDSA 공개키를 로드한다.
    """
    with open(path, "rb") as f:
        key_data = f.read()

    return serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )


def verify_ecdsa_signature(data: bytes, signature: bytes) -> bool:
    """
    data(파일 바이트)에 대해 ECDSA(SHA256) 서명을 검증한다.
    검증 성공 시 True, 실패 시 False 반환.
    """
    global public_key
    if public_key is None:
        print("[ERROR] ECDSA public key not loaded.")
        return False

    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        print("[WARNING] ECDSA signature invalid.")
        return False
    except Exception as e:
        print("[ERROR] ECDSA verification error:", e)
        return False


def save_file_if_complete():
    """
    파일 이름, 데이터, 서명이 모두 수신되었을 때
    ECDSA 검증 후, 성공 시에만 파일을 저장한다.
    """
    global file_name, file_data, file_signature

    if not (file_name and file_data and file_signature):
        # 세 가지가 모두 채워지지 않으면 아무 것도 하지 않음
        return

    print(f"[INFO] Received all parts for file: {file_name}")
    print("[INFO] Verifying ECDSA signature...")

    if verify_ecdsa_signature(file_data, file_signature):
        # 검증 성공 시 파일 저장
        file_path = os.path.join(temp_dir, file_name)
        try:
            with open(file_path, 'wb') as file:
                file.write(file_data)
            print(f"[SUCCESS] ECDSA verified. File saved as: {file_name}")
        except Exception as e:
            print("[ERROR] Failed to save file:", e)
    else:
        print("[WARNING] Signature verification failed. File will NOT be saved.")

    # 다음 파일을 위해 초기화
    file_name = None
    file_data = None
    file_signature = None


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
    global file_name, file_data, file_signature

    topic = msg.topic

    try:
        if topic == name_topic:
            # 파일 이름은 일반 문자열
            file_name = msg.payload.decode('utf-8')
            print(f"[INFO] File name received: {file_name}")

        elif topic == file_topic:
            # base64로 인코딩된 파일 데이터를 디코딩
            payload = msg.payload.decode('utf-8')
            file_data = base64.b64decode(payload)
            print("[INFO] File data received.")

        elif topic == signature_topic:
            # base64로 인코딩된 서명 데이터를 디코딩
            payload = msg.payload.decode('utf-8')
            file_signature = base64.b64decode(payload)
            print("[INFO] ECDSA signature received.")

    except Exception as e:
        print("[ERROR] on_message error:", e)

    # 세 가지(이름/데이터/서명)가 모두 들어왔는지 확인 후 처리
    save_file_if_complete()


# =========================
# 메인
# =========================

def main():
    global public_key

    # ECDSA 공개키 로드
    try:
        public_key = load_ecdsa_public_key(PUBLIC_KEY_PATH)
        print(f"[INFO] ECDSA public key loaded from: {PUBLIC_KEY_PATH}")
    except FileNotFoundError:
        print(f"[FATAL] Public key file not found: {PUBLIC_KEY_PATH}")
        return
    except Exception as e:
        print("[FATAL] Failed to load ECDSA public key:", e)
        return

    client = mqtt.Client()
    client.username_pw_set(userId, userPw)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(brokerIp, port, keepalive=60)

    # 세 개의 토픽 모두 구독
    client.subscribe(name_topic, qos=2)
    client.subscribe(file_topic, qos=2)
    client.subscribe(signature_topic, qos=2)

    client.loop_forever()


if __name__ == "__main__":
    main()

