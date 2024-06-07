import struct

symmetric_keys = {}  # This should be accessible where needed

def send(sock, msg, msg_id="MSG"):
    '''
    Sends a message using the LNP protocol. Prefixes the length of the message and appends a message ID.
    '''
    if isinstance(msg, str):
        msg = msg.encode()

    msg = msg_id.encode() + msg
    msg_len = len(msg)
    msg_header = struct.pack('>I', msg_len)

    # Encrypt the message if a symmetric key is provided
    if sock in symmetric_keys:
        symmetric_key, encryptor = symmetric_keys[sock]
        msg = encryptor.update(msg) + encryptor.finalize()

    sock.sendall(msg_header + msg)

def recv(sock, msg_buffer, recv_len, msg_len, msg_ids):
    '''
    Receives a message using the LNP protocol. Reads the length of the message, then the message itself.
    '''
    if sock not in recv_len:
        recv_len[sock] = 0
        msg_len[sock] = 0
        msg_buffer[sock] = b''

    while True:
        if msg_len[sock] == 0:
            data = sock.recv(4 - recv_len[sock])
            if data == b'':
                return "NO_MSG"
            recv_len[sock] += len(data)
            msg_buffer[sock] += data
            if recv_len[sock] == 4:
                msg_len[sock] = struct.unpack('>I', msg_buffer[sock])[0]
                recv_len[sock] = 0
                msg_buffer[sock] = b''
        else:
            data = sock.recv(msg_len[sock] - recv_len[sock])
            if data == b'':
                return "NO_MSG"
            recv_len[sock] += len(data)
            msg_buffer[sock] += data
            if recv_len[sock] == msg_len[sock]:
                recv_len[sock] = 0
                msg_len[sock] = 0
                msg = msg_buffer[sock]

                # Decrypt the message if a symmetric key is provided
                if sock in symmetric_keys:
                    symmetric_key, decryptor = symmetric_keys[sock]
                    msg = decryptor.update(msg) + decryptor.finalize()

                msg_id = msg[:3].decode()
                msg_ids[sock] = msg_id
                msg_buffer[sock] = msg[3:]
                return "MSG_CMPLT"
