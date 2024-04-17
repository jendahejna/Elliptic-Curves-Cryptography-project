from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

def generate_ECDSA_keys(sk_pem_name, vk_pem_name):
    # Generování klíčů
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Převod klíčů do PEM formátu
    sk_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    vk_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Uložení klíčů
    with open("Keys/ECDSA/" + sk_pem_name, "wb") as f:
        f.write(sk_pem)
    with open("Keys/ECDSA/" + vk_pem_name, "wb") as f:
        f.write(vk_pem)

    return sk_pem, vk_pem

def sign_message(message, private_pem):
    with open(private_pem, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    return signature


def verify_message(message, signature, public_pem):
    with open(public_pem, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

# Příklad použití
private_pem, public_pem = generate_ECDSA_keys("sk_test.pem", "pk_test.pem")
message = "Hello, world!"
signature = sign_message(message, private_pem)
print("Signature:", signature.hex())

verification_result = verify_message(message, signature, public_pem)
print("Verification result:", verification_result)