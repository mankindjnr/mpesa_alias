from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import binascii

# ------------------------serialize- the private key for storage--------------------
def serials(akey):
    pem_private_key = akey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return(pem_private_key)
# -------------------------desirialize- key for decrypting----------------------------------------

def deserials(aserial):
    deserialized_private_key = serialization.load_pem_private_key(
        aserial,
        password=None,
        backend=default_backend()
    )
    print()
    return deserialized_private_key

# ----------------------------------------------------------------------------------
