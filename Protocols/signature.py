from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

def key_generation(key_type, sk_pem_name, vk_pem_name):
    if key_type == 'ECDSA':
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        private_format = serialization.PrivateFormat.TraditionalOpenSSL
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    elif key_type == 'EdDSA':
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

    with open("CryptoKeys/" + key_type + "/" + sk_pem_name, "wb") as f:
        f.write(sk_pem)
    with open("CryptoKeys/" + key_type + "/" + vk_pem_name, "wb") as f:
        f.write(vk_pem)

    return sk_pem, vk_pem

def sign_file(key_type, file_path, private_pem):
    with open(file_path, "rb") as f:
        message = f.read()

    with open(private_pem, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    if key_type == 'ECDSA':
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    elif key_type == 'EdDSA':
        signature = private_key.sign(
            message
        )
    else:
        raise ValueError("Unsupported key type")

    return signature

def verify_file(key_type, file_path, signature, public_pem):
    with open(file_path, "rb") as f:
        message = f.read()

    with open(public_pem, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    try:
        if key_type == 'ECDSA':
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        elif key_type == 'EdDSA':
            public_key.verify(
                signature,
                message
            )
        else:
            raise ValueError("Unsupported key type")
        return True
    except InvalidSignature:
        return False

# Příklad použití
key_type = 'EdDSA' # Nebo 'ECDSA'
private_pem, public_pem = generate_keys(key_type, "sk_test.pem", "pk_test.pem")
message = "Hello, world!"
signature = sign_message(key_type, message.encode(), private_pem)
print("Signature:", signature.hex())

verification_result = verify_message(key_type, message.encode(), signature, public_pem)
print("Verification result:", verification_result)