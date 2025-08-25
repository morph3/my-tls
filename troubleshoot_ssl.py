import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate

SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
SERVER_CERTIFICATES = None

def load_keys():
    global SERVER_PRIVATE_KEY
    with open("certs/server.key", "rb") as f:
        key_data = f.read()
        # Load the PEM private key
        SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
            key_data,
            password=None  # The key is not password-protected
        )

    global SERVER_PUBLIC_KEY
    global SERVER_CERTIFICATES
    with open("certs/server.crt", "rb") as f:
        SERVER_CERTIFICATES = f.read().strip()



    cert = load_pem_x509_certificate(SERVER_CERTIFICATES)
    subject = cert.subject.rfc4514_string()  # Get subject as a string
    print(f"Certificate Subject: {subject}")

    SERVER_PUBLIC_KEY = cert.public_key()




if __name__ == "__main__":
    load_keys()
    print("Server Public Key: ")
    print(f"{SERVER_PUBLIC_KEY.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")

    # let's encrypt a string of ours with the public key of the server and try to decrypt it with the private key of the server
    data = "TLS Shellcode Hiding".encode()
    encrypted_data = SERVER_PUBLIC_KEY.encrypt(
                data,
                padding.PKCS1v15()
            )
    print("Encrypted: ", encrypted_data.hex())

    decrypted_data = SERVER_PRIVATE_KEY.decrypt(encrypted_data, padding.PKCS1v15())
    print("Decrypted: ", decrypted_data.decode())


    # decrypt a custom data now
    encrypred_pre_master_secret = "13f95c4bda5f13726a0b8d00b18a07d2649b1791d124a28c94a99bd528855403268cb185976a830b1342be23d4a748c6936fe3dd35ec06897b51c428bf9a4b9cd08eeb29e7ba4eb9a0234404da63e21229d2bf4509c75a19eaf25aa69996dc33f61c802b29bed5f76bcae945d9fed5f82cb354f7605fd60def2af77365e5c227d747bdb242006a9a0ce59edbefbb85aabac0115d9ca3c7d4555cf5f3b5cdf2ab9c6d8fe4acb830838c2370be90cdf01c44ebe303879d13d717bb9bff5a5c94ee89544859ae2bd9f8a803c5d412f51036dd8cfdf31cd1283a0cb3ff8394baf5d78005ec291f58a82a9a58da7ec2dd8dabfa1e2e0c8dd260ac59141bfea3656637"
    encrypred_pre_master_secret_raw = bytes.fromhex(encrypred_pre_master_secret)
    decrypted_pre_master_secret_raw = SERVER_PRIVATE_KEY.decrypt(encrypred_pre_master_secret_raw, padding.PKCS1v15())

    print(f"Decrypted Pre Master Secret: {decrypted_pre_master_secret_raw.hex()}")

    # 030380f51fca9328f244101d6aef3386542605af95213816b7e2dadce69dfad9ef76a591d909a1085d5b5eedaa9d9d90 correct ? 
    cond = decrypted_pre_master_secret_raw.hex() == "030380f51fca9328f244101d6aef3386542605af95213816b7e2dadce69dfad9ef76a591d909a1085d5b5eedaa9d9d90"
    print(cond)