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

def generate_ECDH_keys_test():
    """
    Generates private and public keys for Alice and Bob.

    Returns:
    alice_priv_key, alicePubKey, bob_priv_key, bobPubKey
    """
    # generation of private and public key of Alice
    alicePrivKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    alicePubKey = alicePrivKey.public_key()

    # generation of private and public key of Bob
    bobPrivKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    bobPubKey = bobPrivKey.public_key()

    return alicePrivKey, alicePubKey, bobPrivKey, bobPubKey

def generate_ECDH_keys():
    """
    Generates private and public keys for peer.

    Returns:
    PrivKey, PubKey
    """
    # generation of private and public key of Alice
    privKey = ec.generate_private_key(ec.SECP384R1(), default_backend())
    pubKey = privKey.public_key()

    return privKey, pubKey


def approve_ECDH_keys_demo(alicePrivKey, alicePubKey, bobPrivKey, bobPubKey):
    """
    Generates shared keys of Alice and Bob and test if they are same - demonstrational purposes.

    Args:
    alice_priv_key: Private key of Alice.
    alicePubKey: Public key of Alice.
    bob_priv_key: Private key of Bob.
    bobPubKey: Public key of Bob.

    Returns:
    aliceSharedKey: Generated shared key for Alice using alice_priv_key and bobPubKey
    bobSharedKey: Generated shared key for Bob using bob_priv_key and alicePubKey
    """
    # Alice creates its secret key using Bob public key
    aliceSharedKey = shared_ECDH_key(alicePrivKey, bobPubKey)

    # Bob creates its secret key using Alice public key
    bobSharedKey = shared_ECDH_key(bobPrivKey, alicePubKey)

    # test, if both keys are identical
    assert aliceSharedKey == bobSharedKey
    print("Keys are identical")
    return aliceSharedKey, bobSharedKey

def shared_ECDH_key(privKey, peerPubKey):
    """
    Generates shared key for peer.

    Args:
    privKey: Private key of this peer.
    peerPubKey: Public key of other peer.

    Returns:
    SharedKey: Generated shared key for peer using this peer privKey and other peer's peerPubKey
    """
    # peer creates its secret key using Bob public key
    sharedKey = privKey.exchange(ec.ECDH(), peerPubKey)

    return sharedKey

def save_ECDH_keys(pubKey, sharedKey, base_dir):
    """
    Saves public key of peer and shared key.

    Args:
    pubKey: Public key of this peer.
    sharedKey: Shared key of this peer.
    base_dir: This peer directory for saving keys.
    """

    # serialization and saving of Alice public key
    with open(os.path.join(base_dir, "pubKey.pem"), "wb") as f:
        f.write(pubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # saving of Alice shared key
    with open(os.path.join(base_dir, "sharedKey.bin"), "wb") as f:
        f.write(sharedKey)

    print("keys successfully saved")

# demonstration of created functions for further implementaions
def main():
    alice_priv_key, alice_pub_key = generate_ECDH_keys()
    bob_priv_key, bob_pub_key = generate_ECDH_keys()

    alice_shared_key, bob_shared_key = approve_ECDH_keys_demo(alice_priv_key, alice_pub_key, bob_priv_key, bob_pub_key)

    base_dir = "CryptoKeys/ECDH/Demonstration/Alice"
    os.makedirs(base_dir, exist_ok=True)
    save_ECDH_keys(alice_pub_key, alice_shared_key, base_dir)

    base_dir = "CryptoKeys/ECDH/Demonstration/Bob"
    os.makedirs(base_dir, exist_ok=True)
    save_ECDH_keys(bob_pub_key, bob_shared_key, base_dir)

    print("AliceSharedKey: " + alice_shared_key.hex())
    print("BodSharedKey: " + bob_shared_key.hex())

if __name__ == "__main__":
    main()
