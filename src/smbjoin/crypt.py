"""
Windows LSA secrets decryption routines

Windows uses an AES256-ECB variation for the LSA secrets encryption.
The encryption key is first passed through a custom key derivation function.

This encryption scheme is used in Windows Vista and newer versions.
"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def lsa_decrypt_secret(secret: bytes, key: bytes) -> bytes:
    """
    Decrypts the LSA secret binary blob using the provided encryption key.
    """

    # Extract the 256-bit encryption salt from the secret blob
    salt = secret[28:60]

    # Extract the ciphertext from the secret blob
    ciphertext = secret[60:]

    # AES256 key derivation function: VistaKDF(key, salt)
    sha256 = SHA256.new()
    sha256.update(key)
    for _ in range(0, 1000):
        sha256.update(salt)
    aes256_key = sha256.digest()

    # AES decryption function
    aes256 = AES.new(aes256_key, AES.MODE_ECB)
    return aes256.decrypt(ciphertext)
