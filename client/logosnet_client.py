import argparse
import socket
import select
import queue
import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
import LNP

def get_args():
    '''
    Gets command line arguments.
    '''
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--port",
        metavar='p',
        dest='port',
        help="port number",
        type=int,
        default=42069
    )

    parser.add_argument(
        "--ip",
        metavar='i',
        dest='ip',
        help="IP address for client",
        default='127.0.0.1'
    )

    parser.add_argument(
        "--username",
        metavar='u',
        dest='username',
        help="Username for the client",
        required=True
    )

    return parser.parse_args()

# Main method
def main():
    '''
    Uses a select loop to process user and server messages. Forwards user input to the server.
    '''
    args = get_args()
    server_addr = args.ip
    port = args.port
    username = args.username

    server = socket.socket()
    server.connect((server_addr, port))

    # Load server's public key
    server_public_key_bytes = server.recv(450)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    # Generate a symmetric key
    symmetric_key = os.urandom(32)

    # Encrypt the symmetric key with the server's public key
    encrypted_symmetric_key = server_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    # Send the encrypted symmetric key to the server
    server.send(encrypted_symmetric_key)

    # Use the symmetric key for further communication
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    # Load the client's certificate
    cert_file = f"{username}.cert"
    with open(cert_file, 'rb') as cert_file:
        client_cert = cert_file.read()

    # Send the client's certificate to the server
    server.send(client_cert)

    msg_buffer = {}
    recv_len = {}
    msg_len = {}
    msg_ids = {}
    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    waiting_accept = True

    while server in inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:
            if s == server:
                code = LNP.recv(s, msg_buffer, recv_len, msg_len, msg_ids)
                if code != "LOADING_MSG":
                    code_id, msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len, msg_ids, symmetric_keys={server: (symmetric_key, decryptor)})

                    if code_id is not None:
                        code = code_id

                if code == "MSG_CMPLT":
                    if msg:
                        sys.stdout.write('\r' + msg + '\n')
                        sys.stdout.flush()
                elif code == "ACCEPT":
                    waiting_accept = False
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                elif code == "NO_MSG" or code == "EXIT":
                    sys.stdout.write(msg + '\n')
                    sys.stdout.flush()
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)

            else:
                msg = sys.stdin.readline()
                if not waiting_accept:
                    msg = msg.rstrip()
                    if msg:
                        encrypted_msg = encryptor.update(msg.encode()) + encryptor.finalize()
                        message_queue.put(encrypted_msg)
                    if not ((username == '') or (msg == "exit()")):
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()

        for s in writable:
            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

            if msg:
                if msg == b"exit()":
                    outputs.remove(s)
                    LNP.send(s, '', "EXIT")
                else:
                    LNP.send(s, msg)

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()

if __name__ == '__main__':
    main()
