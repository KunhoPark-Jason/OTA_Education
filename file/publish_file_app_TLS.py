import paho.mqtt.client as mqtt
import os
import base64
import ssl # ssl 모듈을 추가합니다.


name_topic = "updates/name"
file_topic = "updates/file"
broker_ip = "192.168.1.70"

# TLS 인증서 및 키 파일 경로 설정
# 현재 실행 중인 파일과 같은 경로에 있다고 가정합니다.
certs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../certs')
ca_certs = os.path.join(certs_dir, "ca.crt")
client_cert = os.path.join(certs_dir, "client.crt")
client_key = os.path.join(certs_dir, "client.key")

# 파일 전송을 위한 디렉터리 설정
publish_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),'upload')
os.makedirs(publish_dir, exist_ok=True)



# 메시지 생성 함수
def make_message(file_path):
    try:
        with open(file_path, "rb") as file:
            message = base64.b64encode(file.read())
        return message
    except FileNotFoundError as e:
        print("Error:", e)
        raise

# MQTT 이벤트 콜백 함수들
def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("connected OK")
    else:
        print("Error: Connection failed, Return code =", reasonCode)
        # 연결 실패 시 원인 코드를 상세히 출력
        print("Reason Code:", reasonCode)
        
def on_disconnect(client, userdata, flags, rc=0):
    print("Disconnected, RC:", rc)

def on_publish(client, userdata, mid):
    print("Message published, MID:", mid)

# 메인 작업 함수
# TLS를 사용하기 위해 함수 이름을 변경하고 port를 8883으로 설정
def send_file_to_broker_tls(broker_ip, username, password, port=8883):
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    
    try:
        client.username_pw_set(username, password)
        
        # --- TLS 설정 부분 ---
        # TLS/SSL 활성화 및 인증서 경로 설정
        client.tls_set(ca_certs=ca_certs, 
                       certfile=client_cert, 
                       keyfile=client_key,
                       tls_version=ssl.PROTOCOL_TLSv1_2)
        # --- TLS 설정 부분 끝 ---
        
        client.connect(broker_ip, port)
        client.loop_start() # 연결 상태를 유지하기 위해 loop_start를 미리 호출
        
        while True:
            for file in os.listdir(publish_dir):
                publish_file = os.path.join(publish_dir, file)
                try:
                    message = make_message(publish_file)
                    file_name = os.path.basename(publish_file)
                    
                    client.publish(name_topic, file_name, qos=2)
                    client.publish(file_topic, message, qos=2)
                    
                    print(f"Success sending file(updates/name): {file_name}")
                    print("Success sending file(updates/file)")
                    
                except FileNotFoundError as e:
                    print(f"File not found: {e}")
                except Exception as e:
                    print(f"Error occurred: {e}")
                    break
                finally:
                    os.remove(publish_file)
                    print(f"File deleted: {publish_file}")
            
            # 모든 파일을 보낸 후 잠시 대기 (CPU 부하 방지)
            import time
            time.sleep(10)
            
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.loop_stop()
        client.disconnect()
        print("Client disconnected.")

# 모듈 테스트 실행
if __name__ == '__main__':
    print("="*100)
    username = input("Please write your username: ")
    password = input("please write your password: ")
    # TLS 버전의 함수를 호출
    send_file_to_broker_tls(broker_ip, username, password)