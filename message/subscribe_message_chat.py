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

        
        # Save messages to a file
        filename = f"{msg.topic.replace('/', '_')}.txt"
        with open(filename, 'a', encoding='utf-8') as file:
            file.write(payload + '\n')
        print(f"Message saved to file: {filename}")
    except Exception as e:
        print(f"Error decoding message: {e}")

def read_topics_from_file(filename="topic_list.txt"):
    """Read topics from a file and return them as a list."""
    if not os.path.exists(filename):
        print(f"File '{filename}' does not exist. Please create it with topics listed line by line.")
        return []
    with open(filename, 'r', encoding='utf-8') as file:
        topics = [line.strip() for line in file if line.strip()]
    return topics

def receive_message_to_broker(broker_ip, username, password, port=1883):
    # Create an MQTT client instance
    client = mqtt.Client()
    
    # Assign the callback functions
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    
    # Set username and password for authentication
    client.username_pw_set(username, password)
    client.connect(broker_ip, port)

    # Read topics from the file and subscribe to them
    topics = read_topics_from_file()
    if not topics:
        print("No topics to subscribe to. Exiting.")
        return
    for topic in topics:
        client.subscribe(topic)
        print(f"Subscribed to topic: {topic}")
    
    # Start the loop to process network events
    client.loop_forever()

if __name__ == "__main__":
    # Example usage
    broker_ip = '192.168.1.70'
    username = input("Enter username: ")
    password = input("Enter password: ")
    receive_message_to_broker(broker_ip, username, password)