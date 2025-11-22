import paho.mqtt.client as mqtt
import os

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to broker")
    elif rc == 5:
        print("Connection refused: not authorized")
    else:
        print(f"Connection failed with code {rc}")
        os._exit(1)

def on_disconnect(client, userdata, rc):
    if rc == 0:
        print("Disconnected from broker") 
    elif rc == 5:
        username = input("Enter username: ")
        password = input("Enter password: ")
        client.username_pw_set(username, password)
    elif rc != 0:
        print(f"Unexpected disconnection: {rc}")

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode()
        split_payload = payload.split(':')
        if len(split_payload) == 2:
            username, message = split_payload
            with open('user_list.txt', 'r') as f:
                user_list = f.read()
            if username in user_list:
                print(f"Message received from {username}: {message}")
            else:
                print(f"User {username} not found in user list")
        else:
            print("Invalid message format")
            return
    except Exception as e:
        print(f"Error decoding message: {e}")

def receive_message_to_broker(broker_ip, username, password, topic, port=1883):
    # Create an MQTT client instance
    client = mqtt.Client()
    
    # Assign the callback functions
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    
    # Set username and password for authentication
    client.username_pw_set(username, password)
    client.connect(broker_ip, port)

    # Subscribe to the topic
    client.subscribe(topic)
    print(f"Subscribed to topic: {topic}")
    
    # Start the loop to process network events
    client.loop_forever()

if __name__ == "__main__":
    # Example usage
    broker_ip = '192.168.1.70'
    topic = 'message'
    username = input("Enter username: ")
    password = input("Enter password: ")
    receive_message_to_broker(broker_ip, username, password, topic)

