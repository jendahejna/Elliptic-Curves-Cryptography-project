from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Protocols.ECDH import *


def derive_encryption_parameters(shared_key):
    """
    Derive AES and HMAC keys from the shared ECDH key.
    Uses HKDF with SHA-256 to generate a 64-byte output, split into two 32-byte keys.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for AES key, 32 bytes for HMAC key
        salt=None,
        info=b'ECIES using ECDH',
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_key)
    ecies_key, hmac_key = derived_key[:32], derived_key[32:]
    return ecies_key, hmac_key


def encrypt_message_aes(aes_key, message):
    """
    Encrypts a message using AES-CFB, returns the IV and ciphertext.
    Generates a random IV for each encryption.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv, ciphertext


def decrypt_message_aes(aes_key, iv, ciphertext):
    """
    Decrypts a message using AES-CFB.
    Requires the IV and ciphertext.
    """
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message


def encrypt_message_chacha(chacha_key, message):
    """
    Encrypts a message using ChaCha20Poly1305, returns the nonce and ciphertext.
    Generates a 12-byte nonce for each encryption.
    """
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(chacha_key)
    ciphertext = cipher.encrypt(nonce, message, None)
    return nonce, ciphertext


def decrypt_message_chacha(chacha_key, nonce, ciphertext):
    """
    Decrypts a message using ChaCha20Poly1305.
    Requires the nonce and ciphertext.
    """
    cipher = ChaCha20Poly1305(chacha_key)
    decrypted_message = cipher.decrypt(nonce, ciphertext, None)
    return decrypted_message


def create_hmac(hmac_key, ciphertext):
    """
    Creates an HMAC for the ciphertext using SHA-256.
    """
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    return h.finalize()


def verify_hmac(hmac_key, ciphertext, mac):
    """
    Verifies the HMAC of the ciphertext.
    Throws an exception if verification fails.
    """
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(mac)


def encryption_aes(aes_key, hmac_key, message):
    """
    Encrypts a message using AES and appends an HMAC for verification.
    Returns the IV, ciphertext, and MAC.
    """
    iv, ciphertext = encrypt_message_aes(aes_key, message)
    mac = create_hmac(hmac_key, ciphertext)
    return iv, ciphertext, mac


def encryption_chacha(chacha_key, hmac_key, message):
    """
    Encrypts a message using ChaCha20Poly1305 and appends an HMAC for verification.
    Returns the nonce, ciphertext, and MAC.
    """
    nonce, ciphertext = encrypt_message_chacha(chacha_key, message)
    mac = create_hmac(hmac_key, ciphertext)
    return nonce, ciphertext, mac

