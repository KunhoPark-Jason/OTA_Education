import os
import can



os.system('sudo ip link set can0 type can bitrate 125000')
os.system('sudo ip link set can0 up')
can0 = can.interface.Bus(channel='can0', bustype='socketcan')
flag = False  # Flag to indicate if file transmission is in progress

file_data_chunks = []  # List to store file data chunks

while True:
    frame = can0.recv()  # Timeout set to 1000ms
    if frame.arbitration_id == 0x123:
        print(frame.data)
        if frame.data == b'\xff\x00\xff\x00\xff\x00\xff\x00':
            print("Start of file receive.")
            flag = True
            file_data_chunks = []  # Reset chunks for a new file
        elif frame.data == b'\x00\xff\x00\xff\x00\xff\x00\xff':
            print("End of file transmission.")
            flag = False
            if file_data_chunks:
                data = b"".join(file_data_chunks).decode('utf-8')
                file_name, file_data = data.split(':', 1)
                file_path = os.path.join(os.path.dirname(__file__), 'received_files', file_name)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'wb') as f:
                    f.write(file_data.encode('utf-8'))
                print(f"File '{file_name}' received and saved.")
        elif flag:
            file_data_chunks.append(frame.data)  # Accumulate chunks