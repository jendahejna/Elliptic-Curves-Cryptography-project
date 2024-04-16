"""
ECDH protocol file.

Functions:
generate_ECDH_keys: Generates private and public keys for Alice and Bob.
approve_ECDH_keys: Generates shared keys of Alice and Bob and test if they are same.
save_ECDH_keys: Saves public keys of Alice and Bob and their shared keys.

File author:
Daniel Kluka, 203251

Version:
2.0

Date:
3.4.2024
"""
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_ECDH_keys():
    """
    Generates private and public keys for Alice and Bob.

    Returns:
    alicePrivKey, alicePubKey, bobPrivKey, bobPubKey
    """
    # generation of private and public key of Alice
    alicePrivKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    alicePubKey = alicePrivKey.public_key()

    # generation of private and public key of Bob
    bobPrivKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    bobPubKey = bobPrivKey.public_key()

    return alicePrivKey, alicePubKey, bobPrivKey, bobPubKey

def approve_ECDH_keys(alicePrivKey, alicePubKey, bobPrivKey, bobPubKey):
    """
    Generates shared keys of Alice and Bob and test if they are same.

    Args:
    alicePrivKey: Private key of Alice.
    alicePubKey: Public key of Alice.
    bobPrivKey: Private key of Bob.
    bobPubKey: Public key of Bob.

    Returns:
    aliceSharedKey: Generated shared key for Alice using alicePrivKey and bobPubKey
    bobSharedKey: Generated shared key for Bob using bobPrivKey and alicePubKey
    """
    # Alice creates its secret key using Bob public key
    aliceSharedKey = alicePrivKey.exchange(ec.ECDH(), bobPubKey)

    # Bob creates its secret key using Alice public key
    bobSharedKey = bobPrivKey.exchange(ec.ECDH(), alicePubKey)

    # test, if both keys are identical
    assert aliceSharedKey == bobSharedKey
    print("Keys are identical")
    return aliceSharedKey, bobSharedKey

def save_ECDH_keys(alicePubKey, bobPubKey, aliceSharedKey, bobSharedKey):
    """
    Saves public keys of Alice and Bob and their shared keys.

    Args:
    alicePubKey: Public key of Alice.
    bobPubKey: Public key of Bob.
    aliceSharedKey: Shared key of Alice.
    bobSharedKey: Shared key of Bob.
    """
    base_dir = "CryptoKeys/ECDH"
    os.makedirs(base_dir, exist_ok=True)  # Vytvára priečinok ak neexistuje

    # serialization and saving of Alice public key
    with open(os.path.join(base_dir, "alicePubKey.pem"), "wb") as f:
        f.write(alicePubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # serialization and saving of Bob public key
    with open(os.path.join(base_dir, "bobPubKey.pem"), "wb") as f:
        f.write(bobPubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # saving of Alice shared key
    with open(os.path.join(base_dir, "aliceSharedKey.bin"), "wb") as f:
        f.write(aliceSharedKey)

    # saving of Bob shared key
    with open(os.path.join(base_dir, "bobSharedKey.bin"), "wb") as f:
        f.write(bobSharedKey)

    print("Keys successfully saved")

# test of created functions for further implementaions
alicePrivKey, alicePubKey, bobPrivKey, bobPubKey = generate_ECDH_keys()
aliceSharedKey, bobSharedKey = approve_ECDH_keys(alicePrivKey, alicePubKey, bobPrivKey, bobPubKey)
save_ECDH_keys(alicePubKey, bobPubKey, aliceSharedKey, bobSharedKey)

print("AliceSharedKey: " + aliceSharedKey.hex())
print("BodSharedKey: " + bobSharedKey.hex())
