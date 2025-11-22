import paho.mqtt.client as mqtt
import time

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to broker")
    elif rc == 5:
        print("Connection refused: not authorized")
    else:
        print(f"Connection failed with code {rc}")

def on_disconnect(client, userdata, rc):
    pass

def on_publish(client, userdata, mid):
    pass

def main():
    global status
    broker_ip = '192.168.1.189'
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    change_status('login')
    while status == 'login':
        username = input("Enter username: ")
        password = input("Enter password: ")
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
            topic = input("Enter topic: ")
            change_status('message')
            print("Type '\\exit' to exit, '\\help' for help, '\\logout' to log out, or '\\topic' to change topic.")
            while status == 'message':
                message = input(f"Enter message to publish {topic}: ")
                check_command(client,message, topic)

def change_status(new_status):
    global status
    status = new_status

def check_command(client,message, topic):
    if message == '\\exit':
        change_status('exit')
        print("Exiting...")
        client.loop_stop()
        client.disconnect()
    elif message == '\\help':
        print("Available commands:")
        print("\t\\exit - Exit the program")
        print("\t\\help - Show this help message")
        print("\t\\logout - Log out")
        print("\t\\topic - Change topic")
    elif message == '\\topic':
        change_status('topic')
    elif message == '\\logout':
        change_status('login')
        print("Logging out...")
    else:
        print(f"Message '{message}' sent to topic.")

        # Publish the message
        client.publish(topic, message)


if __name__ == "__main__":
    stauts = 'start'
    main()