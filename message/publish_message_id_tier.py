import paho.mqtt.client as mqtt
import json
import time
import os

status = 'login'

current_dir = os.path.dirname(__file__)
pw_path = os.path.join(current_dir, 'pwfile.json')
topic_tier_path = os.path.join(current_dir, 'topic_tier_list.json')

def change_status(new_status):
    global status
    status = new_status

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))

def on_disconnect(client, userdata, rc):
    print("Disconnected with result code " + str(rc))

def on_publish(client, userdata, mid):
    print("Message published with mid: " + str(mid))

def check_command(client, message, topic):
    if message == '\\exit':
        client.disconnect()
        change_status('login')
    elif message == '\\help':
        print("Available commands: \\exit, \\help, \\logout, \\topic")
    elif message == '\\logout':
        client.disconnect()
        change_status('login')
    elif message == '\\topic':
        change_status('topic')
    else:
        client.publish(topic, message)

def main():
    global status
    broker_ip = '192.168.1.70'
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    change_status('login')

    # Load user data from pwfile.json
    with open(pw_path, 'r') as f:
        user_data = json.load(f)

    # Load topic data from topic_tier_list.json
    with open(topic_tier_path, 'r') as f:
        topic_data = json.load(f)

    while status == 'login':
        username = input("Enter username: ")
        password = input("Enter password: ")

        # Validate username and password
        if username in user_data and user_data[username]["pw"] == password:
            user_tier = user_data[username]["Tier"]
            print(f"Login successful. Your Tier: {user_tier}")
        else:
            print("Invalid username or password.")
            continue

        client.username_pw_set(username, password)
        client.connect(broker_ip, port=1883)
        client.loop_start()

        for i in range(10):
            if client.is_connected():
                change_status('topic')
                break
            time.sleep(1)
        else:
            print("Failed to connect to broker within the timeout period")
            client.loop_stop()

        while status == 'topic':
            tier_key = f"Tier-{user_tier}"
            if tier_key in topic_data:
                print("Available topics:")
                for idx, topic in enumerate(topic_data[tier_key]["topics"], start=1):
                    print(f"{idx}: {topic}")
            else:
                print(f"No topics available for Tier-{user_tier}.")
                continue

            topic_idx = input("Enter topic number: ")

            # Validate topic selection
            try:
                topic_idx = int(topic_idx) - 1
                if 0 <= topic_idx < len(topic_data[tier_key]["topics"]):
                    topic = topic_data[tier_key]["topics"][topic_idx]
                    change_status('message')
                    print("Type '\\exit' to exit, '\\help' for help, '\\logout' to log out, or '\\topic' to change topic.")
                else:
                    print("Invalid topic number.")
                    continue
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue

            while status == 'message':
                message = input(f"Enter message to publish {topic}: ")
                check_command(client, message, topic)

if __name__ == "__main__":
    main()