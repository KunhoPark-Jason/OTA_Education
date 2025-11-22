import paho.mqtt.client as mqtt
import os
import base64


name_topic = "updates/name"
file_topic = "updates/file"
hash_topic = "updates/hash"  # Add hash topic
broker_ip = "192.168.1.70"

publish_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),'upload')
hash_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),'hash')


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

def on_disconnect(client, userdata, flags, rc=0):
    print("Disconnected, RC:", rc)

def on_publish(client, userdata, mid):
    print("Message published, MID:", mid)

# 메인 작업 함수
def send_file_to_broker(broker_ip, username, password, port=1883):
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    
    try:
        client.username_pw_set(username, password)
        client.connect(broker_ip, port)
        while True:
            for file in os.listdir(publish_dir):
                try:
                    publish_file = os.path.join(publish_dir, file)
                    message = make_message(publish_file)
                    file_name = os.path.basename(publish_file)
                    
                    # Read the hash file
                    hash_file = os.path.join(hash_dir, f"{file_name}.hash")
                    if not os.path.exists(hash_file):
                        print(f"Hash file not found for {file_name}. Skipping.")
                        continue
                    with open(hash_file, 'r', encoding='utf-8') as hash_f:
                        file_hash = hash_f.read().strip()
                    
                    client.loop_start()
                    client.publish(name_topic, file_name, qos=2)
                    client.publish(file_topic, message, qos=2)
                    client.publish(hash_topic, file_hash, qos=2)  # Publish the hash
                    client.loop_stop()
                    print(f"Success sending file(updates/name): {file_name}")
                    print("Success sending file(updates/file)")
                    print(f"Success sending hash(updates/hash): {file_hash}")
                except FileNotFoundError as e:
                    print("File not found:", e)
                except Exception as e:
                    print("Error:", e)
                    break
                finally:
                    os.remove(publish_file)
                    print(f"File deleted: {publish_file}")
    finally:
        client.loop_stop()
        client.disconnect()
        


# 모듈 테스트 실행
if __name__ == '__main__':
    print("="*100)
    username = input("Please write your username: ")
    password = input("please write your password: ")
    send_file_to_broker(broker_ip, username, password)
