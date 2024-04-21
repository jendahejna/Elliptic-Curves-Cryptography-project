"""
ECIES protocol file.

Functions:
    derive_encryption_parameters:    Generates encryption parameters for encryption
    encrypt_message_aes:             Encrypts message using AES-CFB cipher protocol
    decrypt_message_aes:             Decrypts message encrypted by AES-CFB
    encrypt_message_chacha:          Encrypts message using ChaCha20
    decrypt_message_chacha:          Decrypts message encrypted by ChaCha20
    create_hmac:                     Creates HMAC for ciphertext using SHA-256
    verify_hmac:                     Verifies HMAC for delivered message
    encryption_aes:                  Works like main function for AES-CFB encryption
    encryption_chacha                Works like main function for ChaCha20 encryption

Author:
    Michal Rosa, 221012

Version:
    3.0

Date:
    19.4.2024
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Protocols.ECDH import *


def derive_encryption_parameters(shared_key):
    """
    Derives AES and HMAC keys from the shared ECDH key using HKDF.

    Parameters:
        shared_key: The shared key from ECDH key exchange.

    Returns:
        tuple: A tuple containing AES key and HMAC key (both 32 bytes).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'ECIES using ECDH',
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_key)
    ecies_key, hmac_key = derived_key[:32], derived_key[32:]
    return ecies_key, hmac_key


def encrypt_message_aes(aes_key, message):
    """
    Encrypts a message using AES in CFB mode with a random IV.

    Parameters:
        aes_key: The AES key for encryption.
        message: The plaintext message to be encrypted.

    Returns:
        tuple: A tuple containing the IV and the ciphertext.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv, ciphertext


def decrypt_message_aes(aes_key, iv, ciphertext):
    """
    Decrypts a message using AES in CFB mode.

    Parameters:
        aes_key: The AES key for decryption.
        iv: The initialization vector.
        ciphertext: The encrypted message.

    Returns:
        bytes: The decrypted plaintext.
    """
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message


def encrypt_message_chacha(chacha_key, message):
    """
    Encrypts a message using ChaCha20Poly1305 with a random nonce.

    Parameters:
        chacha_key: The key for ChaCha20Poly1305 encryption.
        message: The plaintext message to be encrypted.

    Returns:
        tuple: A tuple containing the nonce and the ciphertext.
    """
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(chacha_key)
    ciphertext = cipher.encrypt(nonce, message, None)
    return nonce, ciphertext


def decrypt_message_chacha(chacha_key, nonce, ciphertext):
    """
    Decrypts a message using ChaCha20Poly1305.

    Parameters:
        chacha_key: The key for decryption.
        nonce: The nonce used during encryption.
        ciphertext: The encrypted message.

    Returns:
        bytes: The decrypted plaintext.
    """
    cipher = ChaCha20Poly1305(chacha_key)
    decrypted_message = cipher.decrypt(nonce, ciphertext, None)
    return decrypted_message


def create_hmac(hmac_key, ciphertext):
    """
    Creates an HMAC for a given ciphertext using SHA-256.

    Parameters:
        hmac_key: The key for HMAC.
        ciphertext: The ciphertext to be authenticated.

    Returns:
        bytes: The HMAC of the ciphertext.
    """
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    return h.finalize()


def verify_hmac(hmac_key, ciphertext, mac):
    """
    Verifies an HMAC for a given ciphertext.

    Parameters:
        hmac_key: The key for HMAC.
        ciphertext: The ciphertext being verified.
        mac: The HMAC to verify against the ciphertext.

    Raises:
        InvalidSignature: If the HMAC does not match.
    """
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(mac)


def encryption_aes(aes_key, hmac_key, message):
    """
    Encrypts a message using AES, appends an HMAC for verification.

    Parameters:
        aes_key: The AES key for encryption.
        hmac_key: The HMAC key for authentication.
        message: The plaintext message to be encrypted.

    Returns:
        tuple: A tuple containing the IV, ciphertext, and HMAC of the message.
    """
    iv, ciphertext = encrypt_message_aes(aes_key, message)
    mac = create_hmac(hmac_key, ciphertext)
    return iv, ciphertext, mac


def encryption_chacha(chacha_key, hmac_key, message):
    """
    Encrypts a message using ChaCha20Poly1305, appends an HMAC for verification.

    Parameters:
        chacha_key: The key for ChaCha20Poly1305 encryption.
        hmac_key: The HMAC key for authentication.
        message: The plaintext message to be encrypted.

    Returns:
        tuple: A tuple containing the nonce, ciphertext, and HMAC of the message.
    """
    nonce, ciphertext = encrypt_message_chacha(chacha_key, message)
    mac = create_hmac(hmac_key, ciphertext)
    return nonce, ciphertext, mac
