# subscribe_min_tls.py
import paho.mqtt.client as mqtt
import ssl, os

BROKER = "192.168.1.70"
PORT = 8883
TOPIC = "updates/#"

BASE = os.path.dirname(os.path.abspath(__file__))
CA_CERT = os.path.join(BASE, "../certs", "ca.crt")

def on_connect(c,u,f,rc,props=None):
    print("on_connect rc:", rc)
    if rc == 0:
        c.subscribe(TOPIC, qos=1)
        print("subscribed:", TOPIC)

def on_message(c,u,msg):
    print("recv:", msg.topic, "bytes:", len(msg.payload))

client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

# 필요 시 계정 인증(브로커가 allow_anonymous false 이면 필수)
client.username_pw_set("admin", "1234")

# TLS(서버 인증만): 브로커를 서명한 CA 지정
client.tls_set(ca_certs=CA_CERT, tls_version=ssl.PROTOCOL_TLS_CLIENT)
client.tls_insecure_set(False)

client.connect(BROKER, PORT, keepalive=60)
client.loop_forever()
