from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Protocols.ECDH import *



def derive_encryption_parameters(shared_key):
    """Derive AES and HMAC keys from the shared ECDH key."""
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


#*******"
#* AES *"
#*******"
def encrypt_message_aes(aes_key, message):
    """Encrypts a message using AES-CFB and returns ciphertext and IV."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv, ciphertext



def decrypt_message_aes(aes_key, iv, ciphertext):
    """Decrypts a message using AES-CFB."""
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message



#************
#* ChaCha20 *
#************

def encrypt_message_chacha(chacha_key, message):
    """Encrypts a message using ChaCha20 and returns ciphertext and nonce."""
    nonce = os.urandom(12)  # ChaCha20 uses a 12-byte nonce
    cipher = ChaCha20Poly1305(chacha_key)
    ciphertext = cipher.encrypt(nonce, message, None)
    return nonce, ciphertext

def decrypt_message_chacha(chacha_key, nonce, ciphertext):
    """Decrypts a message using ChaCha20."""
    cipher = ChaCha20Poly1305(chacha_key)
    decrypted_message = cipher.decrypt(nonce, ciphertext, None)
    return decrypted_message

#********"
#* HMAC *"
#********"
def create_hmac(hmac_key, ciphertext):
    """Creates an HMAC for the ciphertext."""
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    return h.finalize()

def verify_hmac(hmac_key, ciphertext, mac):
    """Verifies the HMAC of the ciphertext."""
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(mac)


# Deriving encryption parameters for Alice (could use Bob's as well)



#
# Alice sends a message using aes
def encryption_aes(aes_key, hmac_key, message):
    """Encrypt a message using AES and create an HMAC for the ciphertext."""
    # Encrypt the message using AES
    iv, ciphertext = encrypt_message_aes(aes_key, message)
    # Create HMAC for the encrypted message
    mac = create_hmac(hmac_key, ciphertext)
    return iv, ciphertext, mac

#Alice sends a message using ChaCha
def encryption_chacha(chacha_key, hmac_key, message):
    nonce, ciphertext = encrypt_message_chacha(chacha_key, message)
    mac = create_hmac(hmac_key, ciphertext)
    return nonce, ciphertext,mac



