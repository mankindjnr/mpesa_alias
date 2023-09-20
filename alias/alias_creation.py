from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os

def encryptNumber(original):
    # generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

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

    # Phone number to be encrypted
    phone_number = original

    cipher_suite = Fernet(aes_key)
    cipher_text = cipher_suite.encrypt(phone_number.encode())

    context = {
        "theCipher": cipher_text,
        "privateKeys": private_key,
        "rsaCipher": cipher_rsa
    }
    return context

def decryptNumber(theCypher):
    decrypted_aes_key = theCypher['privateKeys'].decrypt(
        theCypher['rsaCipher'],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the phone number using the decrypted AES key
    decipher_suite = Fernet(decrypted_aes_key)
    decrypted_phone_number = decipher_suite.decrypt(theCypher['theCipher']).decode()
    return decrypted_phone_number

encryptNumber("785634332")