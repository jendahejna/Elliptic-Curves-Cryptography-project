"""
ECDH protocol file.

Functions:
generate_ecdh_keys: Generates private and public keys for this peer.
approve_ecdh_keys_demo: Demonstrates generation of shared keys for Alice and Bob and test if they are same.
shared_ecdh_key: Generates shared key for this peer.
save_ecdh_keys: Saves public key of peer, and it's shared key.
main: Demonstrates created functions and their implementation.

File author:
Daniel Kluka, 203251

Version:
3.0

Date:
17.4.2024
"""
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_ecdh_keys():
    """
    Generates private and public keys for peer.

    Returns:
    priv_key: Generated private key for this peer.
    pub_key: Generated public key for this peer.
    """
    # generation of private and public key of Alice
    priv_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    pub_key = priv_key.public_key()

    return priv_key, pub_key


def approve_ecdh_keys_demo(alice_priv_key, alice_pub_key, bob_priv_key, bob_pub_key):
    """
    Generates shared keys of Alice and Bob and test if they are same - demonstration purposes.

    Args:
    alice_priv_key: Private key of Alice.
    alice_pub_key: Public key of Alice.
    bob_priv_key: Private key of Bob.
    bob_pub_key: Public key of Bob.

    Returns:
    alice_shared_key: Generated shared key for Alice using alice_priv_key and bob_pub_key
    bob_shared_key: Generated shared key for Bob using bob_priv_key and alice_pub_key
    """
    # Alice creates its secret key using Bob public key
    alice_shared_key = shared_ecdh_key(alice_priv_key, bob_pub_key)

    # Bob creates its secret key using Alice public key
    bob_shared_key = shared_ecdh_key(bob_priv_key, alice_pub_key)

    # test, if both keys are identical
    assert alice_shared_key == bob_shared_key
    print("Keys are identical")
    return alice_shared_key, bob_shared_key


def shared_ecdh_key(priv_key, peer_pub_key):
    """
    Generates shared key for peer.

    Args:
    priv_key: Private key of this peer.
    peer_pub_key: Public key of other peer.

    Returns:
    shared_key: Generated shared key for peer using this peer priv_key and other peer's peer_pub_key
    """
    # peer creates its secret key using Bob public key
    shared_key = priv_key.exchange(ec.ECDH(), peer_pub_key)

    return shared_key


def save_ecdh_keys(pub_key, shared_key, base_dir):
    """
    Saves public key of peer, and it's shared key.

    Args:
    pub_key: Public key of this peer.
    shared_key: Shared key of this peer.
    base_dir: This peer directory for saving keys.
    """

    # serialization and saving of Alice public key
    with open(os.path.join(base_dir, "pub_key.pem"), "wb") as f:
        f.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # saving of Alice shared key
    with open(os.path.join(base_dir, "shared_key.bin"), "wb") as f:
        f.write(shared_key)

    print("Keys successfully saved.")


# demonstration of created functions for further implementations
def main():
    alice_priv_key, alice_pub_key = generate_ecdh_keys()
    bob_priv_key, bob_pub_key = generate_ecdh_keys()

    alice_shared_key, bob_shared_key = approve_ecdh_keys_demo(alice_priv_key, alice_pub_key, bob_priv_key, bob_pub_key)

    base_dir = "Keys/ECDH/Demonstration/Alice"
    os.makedirs(base_dir, exist_ok=True)
    save_ecdh_keys(alice_pub_key, alice_shared_key, base_dir)

    base_dir = "Keys/ECDH/Demonstration/Bob"
    os.makedirs(base_dir, exist_ok=True)
    save_ecdh_keys(bob_pub_key, bob_shared_key, base_dir)

    print("AliceSharedKey: " + alice_shared_key.hex())
    print("BodSharedKey: " + bob_shared_key.hex())


if __name__ == "__main__":
    main()
