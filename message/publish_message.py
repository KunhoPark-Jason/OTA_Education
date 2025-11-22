import paho.mqtt.client as mqtt

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to broker")
    else:
        print(f"Connection failed with code {rc}")

def on_disconnect(client, userdata, rc):
    print("Disconnected from broker, code:", rc)

def on_publish(client, userdata, mid):
    print(f"Message {mid} published successfully")

def send_message_to_broker(message, broker_ip, username, password, port=1883):
    # Create an MQTT client instance
    client = mqtt.Client()

    # Assign callbacks
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish

    # Set username and password for authentication
    client.username_pw_set(username, password)

    # Connect to the broker
    client.connect(broker_ip, port=port)

    # Start the loop to process network traffic
    client.loop_start()

    # Publish the message
    client.publish(topic, message)

    # Stop the loop and disconnect
    client.loop_stop()
    client.disconnect()

if __name__ == "__main__":
    # Example usage
    topic = 'message'
    broker_ip = '192.168.1.189'
    username = input("Enter username: ")
    password = input("Enter password: ")
    message = input("Enter message to publish: ")
    send_message_to_broker(message, broker_ip, username, password)