from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os

# Generate RSA key pair for asymmetric encryption
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

print("------------------------serialize---------------------")
def serials(akey):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return(pem_private_key)
print()
the_serial = serials(private_key)
print()
# -------------------------desirialize-----------------------------------------

def desirials(aserial):
    rsa_private_key = serialization.load_pem_private_key(
        aserial,
        password=None,
        backend=default_backend()
    )
    print()
    return rsa_private_key
deserial_key = desirials(the_serial)
print(deserial_key)
print()

# ----------------------------------------------------------------------------------
public_key = private_key.public_key()

# Generate a random AES key for symmetric encryption
aes_key = Fernet.generate_key()
# Encrypt the AES key using RSA public key
cipher_rsa = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#print("ciphe_rsa", cipher_rsa)

def encryptNumber(original):
    # Encrypt the phone number using the AES key

# Phone number to be encrypted
    phone_number = original

    cipher_suite = Fernet(aes_key)
    cipher_text = cipher_suite.encrypt(phone_number.encode())
    return cipher_text

def decryptNumber(theCypher):
    decrypted_aes_key = deserial_key.decrypt(
        cipher_rsa,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the phone number using the decrypted AES key
    decipher_suite = Fernet(decrypted_aes_key)
    decrypted_phone_number = decipher_suite.decrypt(theCypher).decode()

    print("Decrypted Phone Number:", decrypted_phone_number)
    return decrypted_phone_number

cypher = encryptNumber("011111111111111111111")
print("-------------:", cypher)

not_cypher = decryptNumber(cypher)
print("------------:::", not_cypher)