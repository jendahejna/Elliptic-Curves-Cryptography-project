from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def generate_EdDSA_keys(sk_pem_name, pk_pem_name):
    # Generování klíčů
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Převod klíčů do formátu PEM
    sk_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
    pk_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with open("Keys/EdDSA/" + sk_pem_name, "wb") as f:
        f.write(sk_pem)
    with open("Keys/EdDSA/" + pk_pem_name, "wb") as f:
        f.write(pk_pem)

    return sk_pem, pk_pem

def sign_message(message, private_pem):
    # Načtení privátního klíče z PEM formátu
    private_key = serialization.load_pem_private_key(private_pem, password=None)

    # Podpis zprávy
    signature = private_key.sign(message.encode())

    return signature

def verify_message(message, signature, public_pem):
    # Načtení veřejného klíče z PEM formátu
    public_key = serialization.load_pem_public_key(public_pem)

    try:
        # Ověření podpisu
        public_key.verify(signature, message.encode())
        return True
    except InvalidSignature:
        return False

