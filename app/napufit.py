import rsa
import cryptography.fernet
import hashlib
import requests
import socket
import threading
import argparse
import uuid
import re
import time
import sys
import os
import json
import struct

# Understanding gained from: https://tools.ietf.org/html/rfc7857 

class ZeroLengthTransfer(Exception):
    def __str__(self):
        return "Zero length transfer detected."

class ConfigHandler():
    def __init__(self):
        with open("config.json") as f:
            config = json.load(f)
            self.LAN_BROADCAST_PORT = config["lan_broadcast_port"]
            self.FACILITATOR_URL = config["facilitator_url"]
            CHUNK_SIZE = config["chunk_size"].split("^")
            self.CHUNK_SIZE = int(CHUNK_SIZE[0]) ** int(CHUNK_SIZE[1])

config = ConfigHandler()

NETWORK_TYPE_LAN = "lan"
NETWORK_TYPE_INTERNET = "net"

LAN_BROADCAST_PORT = config.LAN_BROADCAST_PORT

FACILITATOR_URL = config.FACILITATOR_URL
PHP_NEW = "?new"
PHP_DELETE = "?delete="
PHP_GET_DOWNLOADER = "?get_downloader="
PHP_GET_UPLOADER = "?get_uploader="
PHP_SET_READY = "?set_ready="
PHP_CHECK_READY = "?check_ready="

MESSAGE_DELIMITER = b"|||DELIMITER|||"  
RETURN_RECEIPT_MSG = b"OK"
CHUNK_SIZE = config.CHUNK_SIZE
print_transfer_progress_timer = time.monotonic()
PRINT_TRANFER_PROGRESS_INTERVAL = 5
TRANSFER_CHECK_INTERVAL = 1
CONNECT_ATTEMPT_INTERVAL = 5
MAX_WAIT_TIME = 180
user_choice_yes = b"y"
user_choice_no = b"n"

PRINT_LOCK = threading.Lock()

def thread_safe_print(msg):
    with PRINT_LOCK:
        print(msg, flush=True)

def print_file_transfer_progress(file_size, transferred_amount):
    global print_transfer_progress_timer
    current_time = time.monotonic()
    if current_time - print_transfer_progress_timer > PRINT_TRANFER_PROGRESS_INTERVAL:
        thread_safe_print("{}%".format(str(transferred_amount / int(file_size) * 100)))
        print_transfer_progress_timer = current_time

def print_and_exit(msg):
    thread_safe_print(msg)
    sys.exit()

def get_user_consent(msg):
    consent = b""
    while consent != user_choice_yes and consent != user_choice_no:
        consent = input(msg).lower().strip().encode()
    return consent == user_choice_yes

def efficient_binary_file_read(file_path, chunk_size, action):
    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(chunk_size), b""):
                action(chunk)
    except Exception as e:
        print_and_exit("Error while reading binary file")

# Conversations are turn-based. The receiver knows when the sender is done once the first (and what should be the only) message delimiter is seen.

def conversation_send(connected_socket, message):
    try:
        full_message = message + MESSAGE_DELIMITER
        sent_length = 0     
        while sent_length < len(full_message):
            sent_length = sent_length + connected_socket.send(full_message[sent_length:])
        return sent_length
    except Exception as e:
        print_and_exit("Unknown error occurred while sending. Exiting... {}".format(e))

def conversation_recv(connected_socket):  
    message = b""
    try:
        while MESSAGE_DELIMITER not in message: 
            received_message = connected_socket.recv(CHUNK_SIZE)
            if len(received_message) == 0: raise ZeroLengthTransfer # length of zero returned, connection considered dead.
            message = message + received_message
        return message.split(MESSAGE_DELIMITER)[0]
    except ZeroLengthTransfer:
        print_and_exit("Connection closed while receiving. Exiting...")
    except Exception as e:
        print_and_exit("Unknown error occurred while receiving. Exiting... {}".format(e))

def upload(network_type, abs_file_path):
    def tcp_punch(local_port, dest_address):
        try:
            with socket.socket() as punch_socket:
                punch_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # SO_REUSEADDR is insufficient if a duplicate socket is made during the TIME_WAIT interval.
                # i.e. if the source and destination address are exactly the same, an error will be thrown
                # SO_LINGER with a value of 0 will ensure that TIME_WAIT never occurs and that the socket is discarded immediately.
                punch_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                punch_socket.settimeout(1)
                punch_socket.bind(('', local_port))
                punch_socket.connect(dest_address)
        except:
            pass

    def upload_on_connect(connected_socket):
        thread_safe_print("Connected.")

        #### Generate RSA fingerprint
        thread_safe_print("Generating and sending fingerprint.")
        (public_rsa_key, private_rsa_key) = rsa.newkeys(2048)
        public_rsa_key_string = public_rsa_key.save_pkcs1()
        conversation_send(connected_socket, public_rsa_key_string)
        sha256_rsa_hash = hashlib.sha256()
        sha256_rsa_hash.update(public_rsa_key_string)
        fingerprint = re.sub(r'(..)',r'\1:',sha256_rsa_hash.hexdigest())[:-1]
        thread_safe_print("Awaiting downloader to verify your fingerprint: \n{}\n".format(fingerprint))
        if conversation_recv(connected_socket) == user_choice_no:
            print_and_exit("Downloader rejected fingerprint.")
        else:
            thread_safe_print("Downloader has accepted your fingerprint.")

        #### Get the public key of downloader
        thread_safe_print("Waiting for downloader's fingerprint.")
        public_rsa_key = conversation_recv(connected_socket)
        sha256_rsa_hash = hashlib.sha256()
        sha256_rsa_hash.update(public_rsa_key)
        fingerprint = re.sub(r'(..)',r'\1:',sha256_rsa_hash.hexdigest())[:-1]
        if not get_user_consent("Confirm downloader's fingerprint \n {} \n (Y/N): ".format(fingerprint)):
            conversation_send(connected_socket, user_choice_no)
            print_and_exit("Fingerprint rejected. Exiting...")
        conversation_send(connected_socket, user_choice_yes)

        public_rsa_key = rsa.PublicKey.load_pkcs1(public_rsa_key)

        thread_safe_print("Sharing symmetric encryption key.")

        #### Generate and send symmetric key, encrypted with RSA.
        secret_key = cryptography.fernet.Fernet.generate_key()
        cipher_text = rsa.encrypt(secret_key, public_rsa_key)
        conversation_send(connected_socket, cipher_text)
        fernet_encryptor = cryptography.fernet.Fernet(secret_key)
        if fernet_encryptor.decrypt(conversation_recv(connected_socket)) != RETURN_RECEIPT_MSG: print_and_exit("Bad response. Exiting...")       

        thread_safe_print("Sending file info to downloader and waiting for confirmation.")

        #### Send file name
        cipher_text = fernet_encryptor.encrypt(os.path.split(abs_file_path)[1].encode())
        conversation_send(connected_socket, cipher_text)
        if fernet_encryptor.decrypt(conversation_recv(connected_socket)) != user_choice_yes: print_and_exit("File rejected. Exiting...")

        #### Send file hash
        sha256_file_hash = hashlib.sha256()
        efficient_binary_file_read(abs_file_path, CHUNK_SIZE, sha256_file_hash.update)
        cipher_text = fernet_encryptor.encrypt(sha256_file_hash.hexdigest().encode())
        conversation_send(connected_socket, cipher_text)
        if fernet_encryptor.decrypt(conversation_recv(connected_socket)) != RETURN_RECEIPT_MSG: print_and_exit("Bad response. Exiting...")                 

        #### Send file size
        file_size = os.path.getsize(abs_file_path)
        cipher_text = fernet_encryptor.encrypt(str(file_size).encode())
        conversation_send(connected_socket, cipher_text)
        if fernet_encryptor.decrypt(conversation_recv(connected_socket)) != RETURN_RECEIPT_MSG: print_and_exit("Bad response. Exiting...")

        thread_safe_print("Upload started.")

        #### Begin file send
        sent_amount = 0
        def send_chunk(chunk):
            length_sent = len(chunk)            
            conversation_send(connected_socket, fernet_encryptor.encrypt(chunk))
            nonlocal sent_amount
            sent_amount = sent_amount + length_sent
            print_file_transfer_progress(file_size, sent_amount)

        upload_thread = threading.Thread(target=efficient_binary_file_read, args=(abs_file_path, CHUNK_SIZE, send_chunk))            
        upload_thread.daemon = True
        upload_thread.start()

        while upload_thread.is_alive():
            time.sleep(TRANSFER_CHECK_INTERVAL)

        thread_safe_print("Upload complete.")
        thread_safe_print("(Optional): File fingerprint is displayed for manual verification with downloader: \n{}\n".format(re.sub(r'(..)',r'\1:',sha256_file_hash.hexdigest())[:-1]))        

    def upload_discovery_internet():
        # Send a request to the server to make sure it's up.
        try:
            with requests.get(FACILITATOR_URL) as facilitator_server_response:
                if facilitator_server_response.status_code != 200:
                    raise Exception
        except:
            print_and_exit("Facilitator server down")
                
        #### Listen for downloader
        is_stream_request_closed = False
        try:
            # Send a request to the facilitator, get a unique ID in return.
            # Facilitator saves external IP and port of uploader, associating them with the unique ID.
            with requests.get(FACILITATOR_URL+PHP_NEW, stream=True) as facilitator_server_response: #stream=true to expose underlying socket
                requests_socket = socket.fromfd(facilitator_server_response.raw.fileno(), socket.AF_INET, socket.SOCK_STREAM)
                requests_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                requests_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1,0))
                # Get local port of socket used to contact the facilitator, must reuse same port to utilise NAPT-EIM
                # Uploader will bind the punch-thru socket to the same port & then bind the file transfer socket to the same port
                locally_bound_port = requests_socket.getsockname()[1] 
                remote_server_ip = requests_socket.getpeername()[0]
                remote_server_port = requests_socket.getpeername()[1]
                unique_conn_id = facilitator_server_response.content.decode()
                thread_safe_print("Share your unique connection ID with your intended recipient: {}".format(unique_conn_id))
                # Only call close on the socket, calling shutdown stops SO_LINGER from taking effect for some reason.
                requests_socket.close()
                is_stream_request_closed = True
        except:
            if is_stream_request_closed:
                thread_safe_print("Connection to the facilitator server has terminated suddenly. However, all data was received. Attempting to continue...")
            else:
                print_and_exit("Connection to the facilitator server has terminated suddenly. Unable to recover. Exiting...")
        if facilitator_server_response.status_code != 200:
            print_and_exit("Facilitator error. Exiting...")

        thread_safe_print("Waiting for downloader...")       

        # Periodically check the facilitator to see if a downloader is available & associated with your unique ID.
        time_ref = time.monotonic()
        downloader_details = ""
        while downloader_details == "":
            if time.monotonic() - time_ref >= MAX_WAIT_TIME:
                tcp_punch(locally_bound_port, (remote_server_ip, remote_server_port)) # Ensure that the endpoint independent port mapping doesn't expire in the router.
                time_ref = time.monotonic()
            time.sleep(CONNECT_ATTEMPT_INTERVAL)
            # Keep checking until downloader is available. If not available yet, empty string "" is returned.
            downloader_details = requests.get(FACILITATOR_URL+PHP_GET_DOWNLOADER+unique_conn_id).text
        downloader_details = downloader_details.split("|") # ip|port
        downloader_address = (downloader_details[0], int(downloader_details[1]))

        # Allow the downloader to connect.
        tcp_punch(locally_bound_port, downloader_address) # Punch-thru to let downloader reach the listening socket below.

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_socket.bind(('', locally_bound_port)) # Downloader should be directed to this socket now
            listen_socket.listen() 
            requests.get(FACILITATOR_URL+PHP_SET_READY+unique_conn_id)          
            try:
                received_socket_info = listen_socket.accept()  # Wait for downloader
            except KeyboardInterrupt as ki:
                print_and_exit("User quit.")
            with received_socket_info[0] as connected_socket:
                requests.get(FACILITATOR_URL+PHP_DELETE+unique_conn_id) # Connection established; online data can be purged.
                upload_on_connect(connected_socket) # Connection established. Move onto file transfer.

    def upload_discovery_lan():
        is_connected = False
        is_connected_lock = threading.Lock()
        def broadcast_connection(tcp_port_string):
            def get_is_connected():
                with is_connected_lock:
                    return is_connected
            unique_conn_id = str(uuid.uuid4()).split("-")[0]
            thread_safe_print("Share this pairing with your recipient: {}".format(unique_conn_id))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as broadcast_send_socket: # Create a UDP socket for broadcasting
                broadcast_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                broadcast_send_socket.bind(('',0))
                BROADCAST_INTERVAL = 1
                while not get_is_connected(): # Main thread will set this to true when a connection comes thru, which will result in this broadcast thread closing.
                    broadcast_send_socket.sendto((unique_conn_id+"|"+tcp_port_string).encode(), ("<broadcast>", LAN_BROADCAST_PORT))
                    time.sleep(BROADCAST_INTERVAL)
            return 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket: # Create the socket that will be used to upload the file.
            listen_socket.bind(('', 0))
            listen_socket.listen()
            locally_bound_port = listen_socket.getsockname()[1]
            broadcast_thread = threading.Thread(target=broadcast_connection, args=(str(locally_bound_port),)) # Broadcast what port the socket is bound to.
            broadcast_thread.daemon = True
            broadcast_thread.start()
            try:
                received_socket_info = listen_socket.accept() # Begin accepting connections as the broadcast begins.
            except KeyboardInterrupt as ki:
                print_and_exit("User quit.")
            with received_socket_info[0] as connected_socket:
                with is_connected_lock:
                    is_connected = True
                upload_on_connect(connected_socket) # Discovery complete & connection established. Move onto file transfer.

    if network_type == NETWORK_TYPE_LAN:
        upload_discovery_lan()
    elif network_type == NETWORK_TYPE_INTERNET:
        upload_discovery_internet()

def download(network_type, unique_conn_id, download_path):
    def file_recv(connected_socket, file_path, fernet_encryptor, bytes_received_callback):
        fragment = b""
        try:
            with open(file_path, "wb") as file:
                while True:
                    received_message = connected_socket.recv(CHUNK_SIZE)
                    if len(received_message) == 0: raise ZeroLengthTransfer
                    received_message = fragment + received_message # Add fragment to the beginning of the newly received bytes
                    fragment = b""
                    received_message_list = received_message.split(MESSAGE_DELIMITER) # If all messages are delimited properly, last element will be an empty length 0 (bytes) string
                    if len(received_message_list[-1]) > 0: # Fragment found
                        fragment = received_message_list[-1]
                        received_message_list = received_message_list[:-1] # Truncate fragmented message
                    received_message_list = list(filter(len, received_message_list)) # Remove any empty elements
                    written_bytes = 0
                    for cipher_text in received_message_list:
                        plaintext = fernet_encryptor.decrypt(cipher_text)
                        written_bytes = written_bytes + file.write(plaintext)
                    bytes_received_callback(written_bytes)
        except ZeroLengthTransfer:
            thread_safe_print("Download ended.")
        except Exception as e:
            print_and_exit("Unknown error occurred while downloading. Exiting... {}".format(e))

    def download_on_connect(connected_socket):
        thread_safe_print("Connected.")

        #### Get the fingerprint of uploader
        thread_safe_print("Waiting for uploader's fingerprint.")
        public_rsa_key = conversation_recv(connected_socket)
        sha256_rsa_hash = hashlib.sha256()
        sha256_rsa_hash.update(public_rsa_key)
        fingerprint = re.sub(r'(..)',r'\1:',sha256_rsa_hash.hexdigest())[:-1]
        if not get_user_consent("Confirm uploader's fingerprint \n {} \n (Y/N): ".format(fingerprint)):
            conversation_send(connected_socket, user_choice_no)
            print_and_exit("Fingerprint rejected. Exiting...")
        conversation_send(connected_socket, user_choice_yes)

        #### Generate RSA keys and send public key to receive the symmetric key securely.
        thread_safe_print("Generating and sending fingerprint.")
        (public_rsa_key, private_rsa_key) = rsa.newkeys(2048)
        public_rsa_key_string = public_rsa_key.save_pkcs1()
        conversation_send(connected_socket, public_rsa_key_string)
        sha256_rsa_hash = hashlib.sha256()
        sha256_rsa_hash.update(public_rsa_key_string)
        fingerprint = re.sub(r'(..)',r'\1:',sha256_rsa_hash.hexdigest())[:-1]
        thread_safe_print("Awaiting uploader to verify your fingerprint: \n{}\n".format(fingerprint))
        if conversation_recv(connected_socket) == user_choice_no:
            print_and_exit("Uploader rejected fingerprint.")
        else:
            thread_safe_print("Uploader has accepted your fingerprint.")

        #### Receive symmetric key, decrypt with RSA.
        cipher_text = conversation_recv(connected_socket)
        secret_key = rsa.decrypt(cipher_text, private_rsa_key)
        fernet_encryptor = cryptography.fernet.Fernet(secret_key)
        conversation_send(connected_socket, fernet_encryptor.encrypt(RETURN_RECEIPT_MSG))

        #### Receive file name
        cipher_text = conversation_recv(connected_socket)
        file_name = fernet_encryptor.decrypt(cipher_text).decode()
        if not get_user_consent("Confirm file '{}' (Y/N): ".format(file_name)):
            conversation_send(connected_socket, fernet_encryptor.encrypt(user_choice_no))
            print_and_exit("File rejected. Exiting...")        
        conversation_send(connected_socket, fernet_encryptor.encrypt(user_choice_yes)) 

        file_name = os.path.join(download_path, file_name)

        #### Receive file hash
        cipher_text = conversation_recv(connected_socket)
        sha256_file_hash = fernet_encryptor.decrypt(cipher_text).decode()
        conversation_send(connected_socket, fernet_encryptor.encrypt(RETURN_RECEIPT_MSG))    

        #### Receive file size
        cipher_text = conversation_recv(connected_socket)
        file_size = fernet_encryptor.decrypt(cipher_text).decode()
        conversation_send(connected_socket, fernet_encryptor.encrypt(RETURN_RECEIPT_MSG))

        #### Begin download
        received_amount = 0
        def update_received_amount(amount):
            nonlocal received_amount
            received_amount = received_amount + amount
            print_file_transfer_progress(file_size, received_amount)
                 
        download_thread = threading.Thread(target=file_recv, args=(connected_socket, file_name, fernet_encryptor, update_received_amount))
        download_thread.daemon = True
        download_thread.start()

        while download_thread.is_alive():
            time.sleep(TRANSFER_CHECK_INTERVAL)    

        thread_safe_print("Download complete.")
        sha256_local_file_hash = hashlib.sha256()
        efficient_binary_file_read(file_name, CHUNK_SIZE, sha256_local_file_hash.update)
        thread_safe_print("File integrity verified." if sha256_local_file_hash.hexdigest() == sha256_file_hash else "File corrupted. Download failed.")
        thread_safe_print("(Optional): File fingerprint is displayed for manual verification with uploader: \n{}\n".format(re.sub(r'(..)',r'\1:',sha256_local_file_hash.hexdigest())[:-1]))

    def download_discovery_internet():
        #### Connect to uploader
        is_stream_request_closed = False
        try:
            # Send the unique ID to the facilitator and get the associated external ip and port of the uploader in return.
            # Facilitator saves external IP and port of downloader, associating them with the unique ID.
            with requests.get(FACILITATOR_URL+PHP_GET_UPLOADER+unique_conn_id, stream=True) as facilitator_server_response: #stream=true to expose underlying socket
                requests_socket = socket.fromfd(facilitator_server_response.raw.fileno(), socket.AF_INET, socket.SOCK_STREAM)
                requests_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Get local port of socket used to contact the facilitator, must reuse same port to utilise NAPT-EIM.
                # Downloader will bind the file transfer socket to the same port and then attempt to connect to the uploader.
                locally_bound_port = requests_socket.getsockname()[1] 
                uploader_details = facilitator_server_response.content.decode().split("|") # ip|port
                # Only need to call close, calling shutdown is unnecesssary
                requests_socket.close()
                is_stream_request_closed = True
        except:
            if is_stream_request_closed:
                thread_safe_print("Connection to the facilitator server has terminated suddenly. However, all data was received. Attempting to continue...")
            else:
                print_and_exit("Connection to the facilitator server has terminated suddenly. Unable to recover. Exiting...")

        uploader_address = (uploader_details[0], int(uploader_details[1]))    
        if facilitator_server_response.status_code != 200:
            print_and_exit("Facilitator error. Exiting...")

        thread_safe_print("Attempting to connect to uploader.")

        is_ready = False
        while not is_ready:
            time.sleep(CONNECT_ATTEMPT_INTERVAL)
            is_ready = bool(int(requests.get(FACILITATOR_URL+PHP_CHECK_READY+unique_conn_id).text))

        # Attempt to connect to the uploader. 
        # Once the uploader does a punch-thru to the external ip and port combo recorded by the facilitator, a connection should be established
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connected_socket:
            connected_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            connected_socket.bind(('', locally_bound_port))
            time_ref = time.monotonic()
            try: 
                while connected_socket.connect_ex(uploader_address) != 0:
                    if time.monotonic() - time_ref >= MAX_WAIT_TIME:
                        print_and_exit("Timed out waiting to connect. Exiting...") # If a connection isn't established after MAX_WAIT seconds, it never will. Something has gone wrong.
                    time.sleep(CONNECT_ATTEMPT_INTERVAL)
            except KeyboardInterrupt as ki:
                print_and_exit("User quit.")
            except Exception as e:
                print_and_exit("Socket connection error. Exiting...")
            download_on_connect(connected_socket) # Connection established. Move onto file transfer.

    def download_discovery_lan():
        found_uploader = False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as broadcast_listener_socket: # Create UDP socket to listen for broadcast with supplied ID
            broadcast_listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            broadcast_listener_socket.bind(('',LAN_BROADCAST_PORT))
            while not found_uploader:
                try:
                    r = broadcast_listener_socket.recvfrom(CHUNK_SIZE)
                except KeyboardInterrupt as e:
                    print_and_exit("User quit.")
                data = r[0].decode().split("|") # r[0] contains packet, r[1] contains remote socket info
                if data[0] == unique_conn_id:
                    found_uploader = True
                    uploader_ip_address = r[1][0]
                    uploader_port = int(data[1])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connected_socket: # Create socket to be used for file download
            connected_socket.bind(('', 0))
            try:
                connected_socket.connect((uploader_ip_address, uploader_port))
            except KeyboardInterrupt as ki:
                print_and_exit("User quit.")
            except Exception as e:
                print_and_exit("Socket connection error. Exiting...")
            download_on_connect(connected_socket) # Connection established. Move onto file download

    if network_type == NETWORK_TYPE_LAN:
        download_discovery_lan()
    elif network_type == NETWORK_TYPE_INTERNET:
        download_discovery_internet()

p = argparse.ArgumentParser()

p.add_argument("network_type", type=str, nargs=1, choices=[NETWORK_TYPE_LAN, NETWORK_TYPE_INTERNET], help="Run on a LAN or over the Internet")

transfer_parser = p.add_subparsers(required=True, dest="transfer_type", help="Further help can be found by appending '-h' after the chosen mode.")

client_args = transfer_parser.add_parser('download', help="download mode")
client_args.add_argument("i", metavar="id", type=str, help="Connection ID")
client_args.add_argument("-p", metavar="path", default=".", type=str, help="Optional path to save downloaded file to. Default: Current working directory")

server_args = transfer_parser.add_parser('upload', help="upload mode")
server_args.add_argument("f", metavar="file", type=str, help="The path of the file to be sent") 

parser_argument = p.parse_args()

if parser_argument.transfer_type == "download":
    download_folder_path = os.path.abspath(parser_argument.p)
    download_unique_id = parser_argument.i
    if os.path.exists(download_folder_path):
        download(parser_argument.network_type[0], download_unique_id, download_folder_path)
    else:
        print_and_exit("Download folder not found.")
elif parser_argument.transfer_type == "upload":
    upload_file_path = os.path.abspath(parser_argument.f)
    if os.path.exists(upload_file_path):
        upload(parser_argument.network_type[0], upload_file_path)
    else:
        print_and_exit("File not found.")
else:
    sys.exit()