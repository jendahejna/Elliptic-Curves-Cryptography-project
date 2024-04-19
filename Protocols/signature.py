"""
Digital Signature Utility Module.

This module provides essential functionalities to generate, sign, and verify digital signatures using ECDSA and EdDSA algorithms. It supports key generation, saving keys in PEM format, signing messages, and verifying the authenticity of signatures.

Functions:
    key_generation:       Generates and saves a pair of private and public keys for digital signatures.
    sign_message:         Signs a given message using a private key and specified signature algorithm.
    verify_signature:     Verifies a digital signature using the corresponding public key.

File author:
    Jan Hejna

Date:
    19.4.2024

Dependencies:
    This module requires the `cryptography` library and is designed to work with ECDSA and EdDSA keys within a

"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519,rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
import os



def key_generation(signature_name, sk_pem_name, vk_pem_name, password):
    """
       Generates a pair of private and public keys, saves them as PEM files.

       Parameters:
           signature_name:  The type of signature ('ECDSA' or 'EdDSA').
           sk_pem_name:     Filename for the private key PEM file.
           vk_pem_name:     Filename for the public key PEM file.
           password:        Used for encrypting saved private key.
       Raises:
           ValueError: If an unsupported key type is provided.

       Returns:
           private_key, public_key: A tuple containing the private key and public key objects.
       """
    base_path = "../Keys/Signature/" + signature_name
    os.makedirs(base_path, exist_ok=True)


    if signature_name == "ECDSA":
        # print("ECDSA key generating.")
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        private_format = serialization.PrivateFormat.TraditionalOpenSSL
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    elif signature_name == "EdDSA":
        # print("EdDSA key generating.")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_format = serialization.PrivateFormat.PKCS8
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    else:
        raise ValueError("Unsupported key type.")

    sk_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=private_format,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
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

    # print("Finished generating.")
    return private_key, public_key


def sign_message(private_key, message, signature_name):
    """
        Signs a message with a specified private key.

        Parameters:
            private_key:    The private key object for signing.
            message:        The message data to be signed.
            signature_name: The type of signature to create ('ECDSA', 'EdDSA').

        Raises:
            ValueError: If an unsupported signature type is provided.

        Returns:
            signature: The digital signature.
        """
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
    """
        Verifies a digital signature against a message using the corresponding public key.

        Parameters:
            public_key:     The public key for verification.
            message:        The message that was originally signed.
            signature:      The signature to verify.
            signature_name: The type of signature used ('ECDSA', 'EdDSA').

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
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
