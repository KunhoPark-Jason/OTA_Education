import paho.mqtt.client as mqtt
import os
import base64

name_topic = "updates/name"
file_topic = "updates/file"

userId = "admin"
userPw = "1234"
brokerIp = '192.168.1.70'
port = 1883
temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp")
os.makedirs(temp_dir, exist_ok= True)

file_name = None
file_data = None

def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("Connected successfully.")

    else:
        print(f"Failed to connect, return code {reasonCode}")

def on_disconnect(client,userdata,flags,rc = 0):
    print(str(rc)+'/')

def on_message(client, userdata, msg):
    global file_name, file_data

    try:
        payload = msg.payload.decode('utf-8')
        topic = msg.topic

        if topic == name_topic:
            file_name = payload
            
        elif topic == file_topic:
            file_data = base64.b64decode((payload))
    except:
        pass

    if file_name and file_data:
        file_path = os.path.join(temp_dir, file_name)
        with open(file_path, 'wb') as file:
            file.write(file_data)
        print(f"File received and saved as {file_name}")


def main():                      
    client = mqtt.Client()
    client.username_pw_set(userId, userPw)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(brokerIp,port, keepalive=60)
    client.subscribe(name_topic, qos=2)
    client.subscribe(file_topic, qos=2)
    client.loop_forever()

if __name__ == "__main__":
    main()