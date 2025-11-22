import paho.mqtt.client as mqtt
import os
import base64
import hashlib

name_topic = "updates/name"
file_topic = "updates/file"
hash_topic = "updates/hash"

userId = "admin"
userPw = "1234"
brokerIp = '192.168.1.70'
port = 1883
temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp")
os.makedirs(temp_dir, exist_ok= True)

file_name = None
file_data = None
file_hash = None  # Variable to store the received hash

def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("Connected successfully.")

    else:
        print(f"Failed to connect, return code {reasonCode}")

def on_disconnect(client,userdata,flags,rc = 0):
    print(str(rc)+'/')

def on_message(client, userdata, msg):
    global file_name, file_data, file_hash

    try:
        payload = msg.payload.decode('utf-8')
        topic = msg.topic

        if topic == name_topic:
            file_name = payload
            
        elif topic == file_topic:
            file_data = base64.b64decode(payload)
        
        elif topic == hash_topic:
            file_hash = payload
    except Exception as e:
        print(f"Error processing message: {e}")

    if file_name and file_data and file_hash:
        # Calculate the hash of the received file data
        calculated_hash = hashlib.sha256(file_data).hexdigest()
        if calculated_hash == file_hash:
            file_path = os.path.join(temp_dir, file_name)
            with open(file_path, 'wb') as file:
                file.write(file_data)
            print(f"File received and saved as {file_name}")
        else:
            print("Hash mismatch! File not saved.")
        
        # Reset variables for the next file
        file_name = None
        file_data = None
        file_hash = None

def main():                      
    client = mqtt.Client()
    client.username_pw_set(userId, userPw)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(brokerIp, port, keepalive=60)
    client.subscribe(name_topic, qos=2)
    client.subscribe(file_topic, qos=2)
    client.subscribe(hash_topic, qos=2)  # Subscribe to the hash topic
    client.loop_forever()

if __name__ == "__main__":
    main()