from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
import os


def key_generation(signature_name, sk_pem_name, vk_pem_name):
    base_path = "Keys/" + signature_name
    os.makedirs(base_path, exist_ok=True)

    if signature_name == "ECDSA":
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        private_format = serialization.PrivateFormat.TraditionalOpenSSL
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
        print("ECDSA key generating")
    elif signature_name == "EdDSA":
        print("EdDSA key generating")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_format = serialization.PrivateFormat.PKCS8
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    else:
        raise ValueError("Unsupported key type")

    sk_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=private_format,
        encryption_algorithm=serialization.NoEncryption()
    )
    vk_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=public_format
    )

    private_key_path = os.path.join(base_path, sk_pem_name)
    public_key_path = os.path.join(base_path, vk_pem_name)

    with open(private_key_path, "wb") as f:
        f.write(sk_pem)
    with open(public_key_path, "wb") as f:
        f.write(vk_pem)

    return private_key, public_key



def sign_message(private_key, message, signature_name):
    print("Key type:", type(private_key))
    print("Signature name:", signature_name)
    if signature_name == "ECDSA":
        # ECDSA requires specifying the hash algorithm.
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    elif signature_name == "EdDSA":
        # EdDSA does not require specifying the hash algorithm in this library.
        signature = private_key.sign(message)
    else:
        raise ValueError("Unsupported signature type: " + signature_name)

    return signature


def verify_signature(public_key, message, signature, signature_name):
    try:
        if signature_name == "ECDSA":
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        elif signature_name == "EdDSA":
            public_key.verify(
                signature,
                message
            )
        else:
            raise ValueError("Unsupported key type")
        return True
    except InvalidSignature:
        return False


