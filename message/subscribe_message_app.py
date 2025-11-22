import paho.mqtt.client as mqtt
import sys  # Import sys for sys.exit()

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to broker")
    elif rc == 5:
        print("Connection refused: not authorized")
    else:
        print(f"Connection failed with code {rc}")
        sys.exit(1)  # Use sys.exit() instead of os._exit()

def on_disconnect(client, userdata, rc):
    if rc == 0:
        print("Disconnected from broker")
    elif rc == 5:
        username = input("Enter username: ")
        password = input("Enter password: ")
        client.username_pw_set(username, password)
        print("Reconnecting with new credentials...")
        client.reconnect()  # Reconnect after setting new credentials
    elif rc != 0:
        print(f"Unexpected disconnection: {rc}")

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode()
        print(f"Message received on topic {msg.topic}: {payload}")
        
        # Send a response message
        response_topic = f"{msg.topic}/response"
        response_message = f"Received your message: {payload}"
        client.publish(response_topic, response_message)
        print(f"Response sent to topic {response_topic}: {response_message}")
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
    
    client.loop_forever()  # Start the loop to process network events

if __name__ == "__main__":
    # Example usage
    broker_ip = '192.168.1.189'
    topic = 'message'
    username = input("Enter username: ")
    password = input("Enter password: ")
    receive_message_to_broker(broker_ip, username, password, topic)

