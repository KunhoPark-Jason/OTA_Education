import paho.mqtt.client as mqtt
import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

name_topic = "updates/name"
file_topic = "updates/file"
signature_topic = "updates/signature"  # ECDSA 서명 전송용 토픽
broker_ip = "192.168.1.170"

# 현재 파일 기준 경로들 설정
base_dir = os.path.dirname(os.path.abspath(__file__))
publish_dir = os.path.join(base_dir, 'upload')

# ../certs/ecdsa_private.pem 자동 사용
certs_dir = os.path.abspath(os.path.join(base_dir, os.pardir, 'certs/ecdsa'))
DEFAULT_PRIVKEY_PATH = os.path.join(certs_dir, 'ecdsa_private.pem')


# =========================
# ECDSA 관련 유틸 함수들
# =========================

def load_ecdsa_private_key(key_path: str, password: str = None):
    """
    PEM 형식의 ECDSA 개인키를 로드한다.
    password가 None이 아니면 bytes 로 인코딩해서 사용.
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

def make_message_and_signature(file_path: str, private_key):
    """
    파일을 읽어서:
    - file_bytes: 원본 바이트
    - message: base64로 인코딩된 전송용 데이터
    - signature_b64: file_bytes에 대한 ECDSA 서명(base64 인코딩)
    을 생성해 반환한다.
    """
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        # 파일 내용을 base64로 인코딩하여 전송용 메시지 생성
        message = base64.b64encode(file_bytes)

        # 파일 원본 바이트에 대해 ECDSA 서명 생성
        signature = sign_data_ecdsa(private_key, file_bytes)
        signature_b64 = base64.b64encode(signature)

        return message, signature_b64

    except FileNotFoundError as e:
        print("Error:", e)
        raise


# =========================
# MQTT 콜백 함수들
# =========================

def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("connected OK")
    else:
        print("Error: Connection failed, Return code =", reasonCode)


def on_disconnect(client, userdata, flags, rc=0):
    print("Disconnected, RC:", rc)


def on_publish(client, userdata, mid):
    print("Message published, MID:", mid)


# =========================
# 메인 작업 함수
# =========================

def send_file_to_broker(broker_ip, username, password,
                        privkey_path, privkey_password=None,
                        port=1883):

    # ECDSA 개인키 로드
    private_key = load_ecdsa_private_key(privkey_path, privkey_password)
    print(f"ECDSA private key loaded from: {privkey_path}")

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish

    try:
        client.username_pw_set(username, password)
        client.connect(broker_ip, port)

        while True:
            for file in os.listdir(publish_dir):
                publish_file = os.path.join(publish_dir, file)
                try:
                    # 파일 내용 + 서명 생성
                    message, signature_b64 = make_message_and_signature(
                        publish_file, private_key
                    )
                    file_name = os.path.basename(publish_file)

                    client.loop_start()

                    # 1) 파일 이름 전송
                    client.publish(name_topic, file_name, qos=2)
                    # 2) 파일 데이터(base64) 전송
                    client.publish(file_topic, message, qos=2)
                    # 3) ECDSA 서명(base64) 전송
                    client.publish(signature_topic, signature_b64, qos=2)

                    client.loop_stop()

                    print(f"Success sending file(updates/name): {file_name}")
                    print("Success sending file(updates/file)")
                    print("Success sending file(updates/signature)")

                except FileNotFoundError as e:
                    print("File not found:", e)
                except Exception as e:
                    print("Error:", e)
                    break
                finally:
                    # 전송 완료 후 원본 파일 삭제
                    try:
                        os.remove(publish_file)
                        print(f"File deleted: {publish_file}")
                    except FileNotFoundError:
                        pass
    finally:
        client.loop_stop()
        client.disconnect()


# =========================
# 모듈 테스트 실행
# =========================

if __name__ == '__main__':
    print("=" * 100)
    username = input("Please write your username: ")
    password = input("please write your password: ")

    # 사용자 입력 없이 ../certs/ecdsa_private.pem 자동 사용
    privkey_path = DEFAULT_PRIVKEY_PATH
    privkey_password = None

    print(f"Using ECDSA private key: {privkey_path}")

    send_file_to_broker(
        broker_ip,
        username,
        password,
        privkey_path=privkey_path,
        privkey_password=privkey_password
    )

