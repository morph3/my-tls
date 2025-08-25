import hashlib
import hmac
import os
from Crypto.Cipher import AES

def pseudo_random_function(secret: bytes, label: bytes, seed: bytes, output_length: int, hash_function=hashlib.sha256) -> bytes:
    """
    section 5 of rfc 5246
    https://datatracker.ietf.org/doc/html/rfc5246#section-5

    TLS 1.2 PRF(secret, label, seed) = P_hash(secret, label + seed)
    """
    full_seed = label + seed
    return p_hash(secret, full_seed, output_length, hash_function)


def p_hash(secret: bytes, seed: bytes, output_length: int, hash_function) -> bytes:
    """
    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                           HMAC_hash(secret, A(2) + seed) + ...
    where:
      A(0) = seed
      A(i) = HMAC_hash(secret, A(i-1))
    """
    result = bytearray()
    A = seed
    while len(result) < output_length:
        A = hmac.new(secret, A, hash_function).digest()
        result.extend(hmac.new(secret, A + seed, hash_function).digest())
    return bytes(result[:output_length])



def expand_keys(pre_master_secret, client_random, server_random):
    """
    6.3.  Key Calculation
    ...
    To generate the key material, compute

        key_block = PRF(SecurityParameters.master_secret,
                        "key expansion",
                        SecurityParameters.server_random +
                        SecurityParameters.client_random);

    until enough output has been generated.  Then, the key_block is
    partitioned as follows:

        client_write_MAC_key[SecurityParameters.mac_key_length]
        server_write_MAC_key[SecurityParameters.mac_key_length]
        client_write_key[SecurityParameters.enc_key_length]
        server_write_key[SecurityParameters.enc_key_length]
        client_write_IV[SecurityParameters.fixed_iv_length]
        server_write_IV[SecurityParameters.fixed_iv_length]

    Currently, the client_write_IV and server_write_IV are only generated
    for implicit nonce techniques as described in Section 3.2.1 of
    [AEAD].

    Expand keys from master secret for TLS_RSA_WITH_AES_128_CBC_SHA256.

    For CBC with HMAC-SHA256:
    - MAC key length: 32 bytes (SHA256)
    - Encryption key length: 16 bytes (AES-128)
    - IV length: 16 bytes

    """

    # first we calc master secret
    """
    8.1.  Computing the Master Secret
        For all key exchange methods, the same algorithm is used to convert
        the pre_master_secret into the master_secret.  The pre_master_secret
        should be deleted from memory once the master_secret has been
        computed.

            master_secret = PRF(pre_master_secret, "master secret",
                                ClientHello.random + ServerHello.random)
                                [0..47];

        The master secret is always exactly 48 bytes in length.  The length
        of the premaster secret will vary depending on key exchange method.
    """
    master_secret = pseudo_random_function(pre_master_secret, b"master secret", client_random + server_random, 48)


    # TLS_RSA_WITH_AES_128_CBC_SHA256
    mac_key_len = 32      # HMAC-SHA256
    enc_key_len = 16      # AES-128
    iv_len = 16           # CBC IVs

    total_len = 2 * (mac_key_len + enc_key_len + iv_len)  # 2 sides, 128?

    # PRF with SHA-256 for TLS 1.2
    seed = server_random + client_random 
    key_block = pseudo_random_function(master_secret, b"key expansion", seed, total_len)

    keys = {
        'master_secret': master_secret,
        'client_write_MAC_key': key_block[0:32],
        'server_write_MAC_key': key_block[32:64],
        'client_write_key': key_block[64:80],
        'server_write_key': key_block[80:96],
        'client_write_IV': key_block[96:112],
        'server_write_IV': key_block[112:128],
    }

    print(f"[!] Dumping keys:")
    print(f"\tTotal key block length: {total_len}")
    print(f"\tpre master secret: {pre_master_secret.hex()}")
    print(f"\tKey block: {key_block.hex()}")
    for k, v in keys.items():
        print(f"\t{k}: {v.hex()}")

    return keys


class CipherSuite:
    def __init__(self, ctx, alg: str, msg_type: bytes):
        self.ctx = ctx
        self.alg = alg
        self.msg_type = msg_type

    def encrypt(self, data):
        if self.alg == "TLS_RSA_WITH_AES_128_CBC_SHA256":
            seq_num_raw = self.ctx.WRITE_SEQ.to_bytes(8, 'big')
            self.ctx.WRITE_SEQ += 1

            # AES 128 CBC encrypt message with client_write_key and client_write_IV
            if self.ctx.IS_SERVER:
                key = self.ctx.KEYS['server_write_key']
                iv =  self.ctx.KEYS['server_write_IV']
                mac_key = self.ctx.KEYS['server_write_MAC_key']
            else:
                key = self.ctx.KEYS['client_write_key']
                iv =  self.ctx.KEYS['client_write_IV']
                mac_key = self.ctx.KEYS['client_write_MAC_key']

            # ---- Compute MAC ----
            mac_data = (
                seq_num_raw +
                self.msg_type +
                self.ctx.TLS_VERSION_1_2 +
                len(data).to_bytes(2, 'big') +
                data
            )
            mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()

            # mac
            plaintext = data + mac

            # padding 
            block_size = AES.block_size
            pad_len = block_size - ((len(plaintext) + 1) % block_size)
            padding = bytes([pad_len] * (pad_len + 1))  # pad_len + 1 bytes
            plaintext += padding

            # AES encrypt - CBC
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(plaintext)

            # prepend iv for further use
            full_msg = iv + ciphertext
            return full_msg

    def decrypt(self, data):
        """
        Decrypts a TLS record (AES-128-CBC + HMAC-SHA256).
        """
        if not self.ctx.ENCRYPT_RECORDS:
            raise ValueError("Decryption called, but encryption is not enabled.")
        
        # data itself is encrypted completely
        encrypted = data

        # Select inbound keys based on role
        if self.ctx.IS_SERVER:
            # Server decrypts records coming from client -> client_write keys
            key = self.ctx.KEYS['client_write_key']
            mac_key = self.ctx.KEYS['client_write_MAC_key']
        else:
            # Client decrypts records coming from server -> server_write keys
            key = self.ctx.KEYS['server_write_key']
            mac_key = self.ctx.KEYS['server_write_MAC_key']
        block_size = AES.block_size

        # extract iv
        iv = encrypted[:block_size]
        ciphertext = encrypted[block_size:]

        # AES-CBC Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        # Strip CBC padding (last byte is padding length; total padding = pad_len + 1)
        pad_len = plaintext[-1]
        if pad_len + 1 > len(plaintext):
            raise ValueError("Invalid padding length")
        plaintext_wo_pad = plaintext[:-(pad_len + 1)]

        # Split message and MAC (MAC is 32 bytes for HMAC-SHA256)
        if len(plaintext_wo_pad) < 32:
            raise ValueError("Plaintext too short for MAC")
        msg = plaintext_wo_pad[:-32]
        received_mac = plaintext_wo_pad[-32:]

        # Recalc mac
        seq_num_raw = self.ctx.READ_SEQ.to_bytes(8, 'big')

        mac_data = (
            seq_num_raw +
            self.msg_type +
            self.ctx.TLS_VERSION_1_2 +
            len(msg).to_bytes(2, 'big') +
            msg
        )
        computed_mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()
        if not hmac.compare_digest(computed_mac, received_mac):
            raise ValueError("Bad record MAC")

        print(f"\n\n---- Decrypt ----")
        print(f"Comparing computed_mac and received_mac {computed_mac.hex()} == {received_mac.hex()} : {computed_mac == received_mac}")

        # increment inbound sequence after successful auth
        self.ctx.READ_SEQ += 1
        # print("plaintext: ", plaintext.hex())
        # print(f"msg: {msg.hex()}")
        # print(f"received_mac: {received_mac.hex()}")


        return msg        
