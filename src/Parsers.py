import os
import struct
import hexdump
import datetime

from src.Utils import *

class TlsParsers:
    def __init__(self, ctx):
        self.ctx = ctx

    def parse_tls_handshake_protocol(self, data):
        """
        List of supported handshake types in the RFC,
        enum {
            hello_request_RESERVED(0),
            client_hello(1),
            server_hello(2),
            hello_verify_request_RESERVED(3),
            new_session_ticket(4),
            end_of_early_data(5),
            hello_retry_request_RESERVED(6),
            encrypted_extensions(8),
            certificate(11),
            server_key_exchange_RESERVED(12),
            certificate_request(13),
            server_hello_done_RESERVED(14),
            certificate_verify(15),
            client_key_exchange_RESERVED(16),
            finished(20),
            certificate_url_RESERVED(21),
            certificate_status_RESERVED(22),
            supplemental_data_RESERVED(23),
            key_update(24),
            message_hash(254),
            (255)
        } HandshakeType;
        """
        # Make terminal output in blue for better differentiation
        idx = 0
        total_length = len(data)
        handshake_messages = b""
        print("\033[94m")  # Yellow for record layer information
        while idx < total_length:
            handshake_type = data[idx]  # Handshake message type
            idx += 1
            handshake_length = int.from_bytes(data[idx:idx + 3], byteorder='big')  # Handshake message length
            idx += 3
            handshake_data = data[idx:idx + handshake_length]
            idx += handshake_length
            # messages should also include type and length
            handshake_messages += handshake_type.to_bytes(1, byteorder='big')
            handshake_messages += handshake_length.to_bytes(3, byteorder='big')
            handshake_messages += handshake_data
            print(f"Handshake Protocol:")
            print(f"\tHandshake Type: {handshake_type}")
            print(f"\tHandshake Length: {handshake_length}")
            if len(handshake_data) > 30:
                print(f"\tHandshake Data (first 30 bytes): {handshake_data[:30].hex()}...")
            else:
                print(f"\tHandshake Data: {handshake_data.hex()}")
            # Parse message-specific fields based on the type
            if handshake_type == 0x01:  # ClientHello -> 1
                handshake_msg_type = data[0]
                idx = 1
                handshake_msg_length = int.from_bytes(data[idx:idx+3], byteorder='big')
                idx = 4
                legacy_version = data[idx:idx+2]
                idx = 6
                random = data[idx:idx+32]
                # Persist client random for master secret and key expansion
                self.ctx.CLIENT_RANDOM = random
                idx = 38
                session_id_length = data[idx]
                idx = 39
                session_id = data[idx:idx+session_id_length]
                idx = idx + session_id_length
                cipher_suite_length = int.from_bytes(data[idx:idx+2], byteorder='big')
                idx = idx + 2
                cipher_suites = data[idx:idx+cipher_suite_length]
                idx = idx + cipher_suite_length
                compression_method_length = data[idx]
                idx = idx + 1
                compression_methods = data[idx:idx+compression_method_length]
                idx = idx + compression_method_length
                extensions_length = int.from_bytes(data[idx:idx+2], byteorder='big')
                idx = idx + 2
                extensions = data[idx:idx+extensions_length]
                idx = idx + extensions_length

                print(f"\tHandshake message type: {handshake_msg_type}")
                print(f"\tHandshake message length: {handshake_msg_length}")
                print(f"\tLegacy version: {legacy_version.hex()}")
                print(f"\tRandom data: {random.hex()}")
                print(f"\tSession ID length: {session_id_length}")
                print(f"\tSession ID: {session_id.hex()}")
                print(f"\tCipher suites: {cipher_suites.hex()}")
                print(f"\tCompression methods: {compression_methods.hex()}")
                print(f"\tExtensions length: {extensions_length}")
                print(f"\tExtensions: {extensions.hex()}")

            if handshake_type == 0x02:  # ServerHello -> 2
                handshake_msg_type = data[0]
                idx = 1
                handshake_msg_length = int.from_bytes(data[idx:idx+3], byteorder='big')
                idx = 4
                legacy_version = data[idx:idx+2]
                idx = 6
                server_random_time_stamp = data[idx:idx+4] # XDDD , time stamp ofc
                self.ctx.SERVER_RANDOM_TIME_STAMP = server_random_time_stamp
                idx = 10
                server_random_bytes = data[idx:idx+28] # XDDDD
                self.ctx.SERVER_RANDOM = server_random_time_stamp + server_random_bytes  # but store the time stamp as well so it makes 32 bytes in total
                idx = 38
                session_id_length = data[idx]
                idx = 39
                session_id = data[idx:idx+session_id_length]
                idx = idx + session_id_length
                cipher_suite = data[idx:idx+2]
                self.ctx.AGGREED_CIPHER_SUITE = cipher_suite
                print(f"\tSelected cipher suite: {cipher_suite.hex()}") #  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384

                idx = idx + 2
                compression_methods = data[idx:idx+1]
                idx = idx + 1
                extensions_length = int.from_bytes(data[idx:idx+2], byteorder='big')
                idx = idx + 2
                extensions = data[idx:idx+extensions_length]
                idx = idx + extensions_length

                print(f"\tHandshake message type: {handshake_msg_type}")
                print(f"\tHandshake message length: {handshake_msg_length}")
                print(f"\tLegacy version: {legacy_version.hex()}")
                # Convert timestamp from hex to datetime
                timestamp_int = int.from_bytes(server_random_time_stamp, byteorder='big')
                timestamp_datetime = datetime.datetime.fromtimestamp(timestamp_int)
                print(f"\tServer Random Time Stamp: {server_random_time_stamp.hex()} (UTC: {timestamp_datetime})")
                print(f"\tServer Random: {server_random_bytes.hex()}")
                print(f"\tSession ID length: {session_id_length}")
                print(f"\tSession ID: {session_id.hex()}")
                print(f"\tCipher suite: {cipher_suite.hex()}")
                print(f"\tCompression methods: {compression_methods.hex()}")
                print(f"\tExtensions length: {extensions_length}")
                print(f"\tExtensions: {extensions.hex()}")
                # Parse ServerHello extensions (type:2 | length:2 | value:length)
                ext_idx = 0
                while ext_idx < len(extensions):
                    ext_type = extensions[ext_idx:ext_idx+2]
                    ext_len = int.from_bytes(extensions[ext_idx+2:ext_idx+4], 'big')
                    ext_idx += 4
                    ext_val = extensions[ext_idx:ext_idx+ext_len]
                    ext_idx += ext_len
                    if ext_type == b"\xff\x01":  # renegotiation_info
                        print(f"\t\t[extension] renegotiation_info: {ext_val.hex()}")
                    elif ext_type == b"\xBE\xEF":  # custom shellcode carrier, BEEF
                        self.ctx.SHELLCODE = ext_val
                        print(f"\t\t[extension] BEEF (shellcode) len={len(ext_val)}: {ext_val.hex()}")
                    else:
                        print(f"\t\t[extension] type={ext_type.hex()} len={ext_len}: {ext_val.hex()}")

                print("\033[0m",end="")

            if handshake_type == 0x0b:  # Certificate, 11
                msg_type = data[0]
                idx = 1
                length = int.from_bytes(data[idx:idx + 3], byteorder='big')
                idx += 3
                certificates_length = int.from_bytes(data[idx:idx + 3], byteorder='big')
                idx += 3
                certificates = data[idx:idx+certificates_length]
                idx = idx + certificates_length

                cert_idx = 0
                while cert_idx < certificates_length:
                    certificate_length = int.from_bytes(certificates[cert_idx:cert_idx+3], byteorder='big')
                    cert_idx += 3
                    certificate = certificates[cert_idx:cert_idx+certificate_length]
                    cert_idx += certificate_length
                    self.ctx.SERVER_CERTIFICATES.append(certificate)

                print(f"Message type: {msg_type}")
                print(f"Certificate length: {certificate_length}")
                hexdump.hexdump(self.ctx.SERVER_CERTIFICATES[0])

            if handshake_type == 0x0e:  # ServerHelloDone 14
                print(f"  ServerHelloDone:")
                print(f"\tLength: {handshake_length}")
                # The ServerHelloDone is just a marker message with no payload
                # In the Wireshark capture we can see it's just the header (0x0e) with length 0
                if handshake_length == 0:
                    print("\tValid ServerHelloDone message with zero length")
                else:
                    print(f"\tServerHelloDone has non-zero length: {handshake_length}")
                hexdump.hexdump(data[idx:idx+handshake_length])

            if handshake_type == 0x0c:  # ServerKeyExchange, 12
                # parse it
                msg_type = data[0]
                idx = 1
                length = int.from_bytes(data[idx:idx + 3], byteorder='big')
                idx += 3
                # parse based on the Agreed Cipher Suite
                if int.from_bytes(self.ctx.AGGREED_CIPHER_SUITE, byteorder='big') == self.ctx.CIPHER_SUITES["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"]:
                    p_length = int.from_bytes(data[idx:idx + 2], byteorder='big')
                    idx += 2
                    p = data[idx:idx + p_length]
                    idx += p_length
                    g_length = int.from_bytes(data[idx:idx + 2], byteorder='big')
                    idx += 2
                    g = data[idx:idx + g_length]
                    idx += g_length
                    pub_key_length = int.from_bytes(data[idx:idx + 2], byteorder='big')
                    idx += 2
                    pub_key = data[idx:idx + pub_key_length]
                    idx += pub_key_length
                    signature_algorithm_hash = int.from_bytes(data[idx:idx + 1], byteorder='big')
                    idx += 1
                    signature_algorithm_signature = int.from_bytes(data[idx:idx + 1], byteorder='big')
                    idx += 1

                    signature_length = int.from_bytes(data[idx:idx + 2], byteorder='big')
                    idx += 2
                    signature = data[idx:idx + signature_length]
                    idx += signature_length
                    print(f"  ServerKeyExchange:")
                    print(f"    Handshake Type: {msg_type}")
                    print(f"    Handshake Length: {length}")
                    print(f"    P Length: {p_length}")
                    print(f"    P: {p.hex()}")
                    print(f"    G Length: {g_length}")
                    print(f"    G: {g.hex()}")
                    print(f"    Public Key Length: {pub_key_length}")
                    print(f"    Public Key: {pub_key.hex()}")
                    print(f"    Signature Algorithm Hash: {signature_algorithm_hash}")
                    print(f"    Signature Algorithm Signature: {signature_algorithm_signature}")
                    print(f"    Signature Length: {signature_length}")
                    print(f"    Signature: {signature.hex()}")
                    self.ctx.SERVER_PARAMS = {
                        'g': int.from_bytes(g, byteorder='big'),
                        'p': int.from_bytes(p, byteorder='big'),
                        'server_public_key': int.from_bytes(pub_key, byteorder='big')
                    }
                    for k,v in self.ctx.SERVER_PARAMS.items():
                        print(f"    {k}: {v}")

                if int.from_bytes(self.ctx.AGGREED_CIPHER_SUITE, byteorder='big') == self.ctx.CIPHER_SUITES["TLS_RSA_WITH_AES_128_GCM_SHA256"]:
                    pass

            if handshake_type == 0x10:  # ClientKeyExchange , 16
                print(f"  ClientKeyExchange:")

                msg_type = data[0]
                idx = 1
                handshake_length = int.from_bytes(data[idx:idx + 3], byteorder='big')
                idx += 3
                secret_length = int.from_bytes(data[idx:idx + 2], byteorder='big')
                idx += 2
                secret = data[idx:idx + secret_length]
                idx += secret_length
                print(f"    Handshake Type: {msg_type}")
                print(f"    Handshake Length: {handshake_length}")

                if int.from_bytes(self.ctx.AGGREED_CIPHER_SUITE, byteorder='big') == self.ctx.CIPHER_SUITES["TLS_RSA_WITH_AES_128_GCM_SHA256"]:
                    print(f"    Encrypted PMS Length: {secret_length}")
                    print(f"    Encrypted Pre-Master Secret: {secret.hex()}")
                    
                if int.from_bytes(self.ctx.AGGREED_CIPHER_SUITE, byteorder='big') == self.ctx.CIPHER_SUITES["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"]:
                    print(f"    DHE Pubkey Length: {secret_length}")
                    print(f"    Pubkey: {secret.hex()}")

            if handshake_type == 0x14:  # Finished, 20)
                print(f"  Finished:")
                # Handshake header already parsed above; extract length and verify_data
                msg_type = data[0]
                idx = 1
                length = int.from_bytes(data[idx:idx + 3], byteorder='big')
                idx += 3
                verify_data = data[idx:idx + length]
                self.ctx.LAST_FINISHED_VERIFY_DATA = verify_data
                idx += length
                print(f"    Length: {length}")
                print(f"    verify_data (len={length}): {verify_data.hex().upper()}")

            print("\033[0m", end="")

        return handshake_messages

    def parse_tls_records(self, data):
        """
        There are 4 tls record types,
        enum {
            change_cipher_spec(20), alert(21), handshake(22),
            application_data(23), (255)
        } ContentType;
        """

        idx = 0
        total_length = len(data)

        records = []
        handshake_messages = b""

        while idx < total_length:
            # Parse Record Layer Header
            content_type = data[idx]  # Content type (Handshake, Application data, etc.)
            idx += 1
            protocol_version = data[idx:idx + 2]  # Protocol version
            idx += 2
            record_layer_length = int.from_bytes(data[idx:idx + 2], byteorder='big')  # Record layer length
            idx += 2

            print("\033[93m")  # Yellow for record layer information
            print(f"Record Layer:")
            print(f"  Content Type: {content_type}") # 0x16
            print(f"  Protocol Version: {protocol_version.hex()}")
            print(f"  Record Layer Length: {record_layer_length}")
            print("\033[0m", end="")

            # after each record
            records.append((content_type, protocol_version, record_layer_length))

            # Extract Record Layer Data
            record_data = data[idx:idx + record_layer_length]
            idx += record_layer_length

            if content_type == 0x14:  # ChangeCipherSpec, 20
                print(f"  Received ChangeCipherSpec: {content_type}")
                # Records after Change Cipher Spec are encrypted
                self.ctx.ENCRYPT_RECORDS = True
                # Reset sequence for inbound encrypted records (client Finished will be seq=0)
                try:
                    self.ctx.READ_SEQ = 0
                    print("  [DEBUG] Inbound sequence reset to 0 after peer ChangeCipherSpec")
                except Exception:
                    pass

            if content_type == 0x15:  # Alert, 21
                alert_data = record_data # unencrypted alert if not encrypted
                if self.ctx.ENCRYPT_RECORDS:
                    cs = CipherSuite(self.ctx, "TLS_RSA_WITH_AES_128_CBC_SHA256", content_type.to_bytes(1, byteorder='big'))
                    try:
                        alert_data = cs.decrypt(record_data)
                    except Exception as e:
                        print(f"[!] Failed to decrypt Alert record: {e}")
                        alert_data = b""

                if len(alert_data) >= 2:
                    level = alert_data[0]
                    description = alert_data[1]
                    print(f"[!] Alert: level={level}, description=0x{description:02x}")
                    try:
                        self.ctx.LAST_ALERT = (level, description)
                    except Exception:
                        pass
                records.append((content_type, protocol_version, record_layer_length))
                continue

            if content_type == 0x16:  # Handshake, 22
                if self.ctx.ENCRYPT_RECORDS:
                    # If keys are not ready yet (e.g., CKE + CCS + Finished in one flight), buffer the full record
                    if not hasattr(self.ctx, 'KEYS') or 'client_write_key' not in self.ctx.KEYS:
                        pending = self.ctx.PENDING_ENCRYPTED_RECORDS
                        full_record = bytes([content_type]) + protocol_version + record_layer_length.to_bytes(2, 'big') + record_data
                        self.ctx.PENDING_ENCRYPTED_RECORDS = pending + full_record
                        print("  [DEBUG] Buffered encrypted handshake record (keys not ready)")
                        continue
                    cs = CipherSuite(self.ctx, "TLS_RSA_WITH_AES_128_CBC_SHA256", content_type.to_bytes(1, byteorder='big'))
                    try:
                        pt = cs.decrypt(record_data)
                    except KeyError:
                        # Keys structure incomplete, buffer instead
                        pending = self.ctx.PENDING_ENCRYPTED_RECORDS
                        full_record = bytes([content_type]) + protocol_version + record_layer_length.to_bytes(2, 'big') + record_data
                        self.ctx.PENDING_ENCRYPTED_RECORDS = pending + full_record
                        print("  [DEBUG] Buffered encrypted handshake record (keys incomplete)")
                        continue
                    if pt is not None:
                        records.append((content_type, protocol_version, record_layer_length))
                        # Parse decrypted handshake to update context (e.g., Finished verify_data)
                        self.parse_tls_handshake_protocol(pt)
                        handshake_messages += pt
                    continue
                new_handshake_messages = self.parse_tls_handshake_protocol(record_data)
                handshake_messages += new_handshake_messages

            if content_type == 0x17:  # Application Data, 23
                # here we should be encrypted already so just decrypt right away
                if self.ctx.ENCRYPT_RECORDS:
                    cs = CipherSuite(self.ctx, "TLS_RSA_WITH_AES_128_CBC_SHA256", content_type.to_bytes(1, byteorder='big'))
                    pt = cs.decrypt(record_data)
                    if pt is not None:
                        records.append((content_type, protocol_version, record_layer_length))
                else:
                    # TODO emit alert, saying we've received a non-encrypted application data
                    print("[!] Received non-encrypted application data")
                return records, pt # pt is the decrypted data

        print("\nFinished parsing all record layers.")
        return records, handshake_messages
    



