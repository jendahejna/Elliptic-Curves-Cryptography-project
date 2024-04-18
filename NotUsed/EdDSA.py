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

    with open("../Keys/EdDSA/" + sk_pem_name, "wb") as f:
        f.write(sk_pem)
    with open("../Keys/EdDSA/" + pk_pem_name, "wb") as f:
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


# Názvy souborů pro uložení klíčů (předpokládá existenci složky)
private_key_filename = "eddsa_private_key.pem"
public_key_filename = "eddsa_public_key.pem"

# Generuj klíče a ulož je
private_pem, public_pem = generate_EdDSA_keys(private_key_filename, public_key_filename)

# Definuj zprávu, kterou chceš podepsat
message = "Hello, this is a test message!"

# Podepiš zprávu
signature = sign_message(message, private_pem)

# Ověř podpis
verification_result = verify_message(message, signature, public_pem)

# Vypiš výsledek ověření
print("Verification successful" if verification_result else "Verification failed.")
print(signature.hex(), verification_result)