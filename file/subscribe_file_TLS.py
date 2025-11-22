import paho.mqtt.client as mqtt
import os
import base64
import ssl # ssl 모듈을 추가합니다.

name_topic = "updates/name"
file_topic = "updates/file"

userId = "mose"
userPw = "mose"
brokerIp = '192.168.1.70'
port = 8883 # TLS 포트(8883)로 변경합니다.

# --- TLS 인증서 및 키 파일 경로 설정 ---
# 현재 실행 중인 파일과 같은 경로에 있다고 가정합니다.
# 실제 경로에 맞게 수정해야 합니다.
certs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../certs')
ca_certs = os.path.join(certs_dir, "ca.crt")
client_cert = os.path.join(certs_dir, "client.crt")
client_key = os.path.join(certs_dir, "client.key")
# --- TLS 인증서 및 키 파일 경로 설정 끝 ---

temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp")
os.makedirs(temp_dir, exist_ok= True)

file_name = None
file_data = None

def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("Connected successfully.")
        # 연결 성공 후 구독
        client.subscribe(name_topic, qos=2)
        client.subscribe(file_topic, qos=2)
    else:
        print(f"Failed to connect, return code {reasonCode}")

def on_disconnect(client, userdata, flags, rc = 0):
    print(str(rc)+'/')

def on_message(client, userdata, msg):
    global file_name, file_data
    
    try:
        if msg.topic == name_topic:
            file_name = msg.payload.decode('utf-8')
        elif msg.topic == file_topic:
            file_data = base64.b64decode(msg.payload)
    except:
        pass

    if file_name and file_data:
        file_path = os.path.join(temp_dir, file_name)
        with open(file_path, 'wb') as file:
            file.write(file_data)
        print(f"File received and saved as {file_name}")
        
        # 다음 파일을 위해 변수 초기화
        file_name = None
        file_data = None

def main():
    client = mqtt.Client()
    client.username_pw_set(userId, userPw)
    client.on_connect = on_connect
    client.on_message = on_message

    # --- TLS 설정 추가 ---
    client.tls_set(ca_certs=ca_certs, 
                   certfile=client_cert, 
                   keyfile=client_key,
                   tls_version=ssl.PROTOCOL_TLSv1_2)
    # --- TLS 설정 끝 ---

    client.connect(brokerIp, port, keepalive=60)
    client.loop_forever()

if __name__ == "__main__":
    main()