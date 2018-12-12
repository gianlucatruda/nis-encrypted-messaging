""" A set of tools for asymmetric (public-key) encryption and decryption.
This is for use in task 1.
"""

import random

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from crypto_tools import sign, valid_signature, valid_key, hash_as_hex


def encrypt(message: str, public_key, signing_key):
    """ Generates a signed ciphertext of a message.
    """

    # Assert that keys are of correct length and type
    assert(valid_key(public_key))
    assert(valid_key(signing_key))

    # Pad the message — 10 to 99 zeros + 7-bit binary count
    pad_len = random.randint(10, 99)
    padding = ''.join(['0' for x in range(pad_len)])
    message = message + padding + str(pad_len)
    byte_message = bytes(message, 'utf-8')
    # print("M (encr.): {} ({} bits)".format(message, len(byte_message)*8))

    # Hash the message
    h = hash_as_hex(message)

    # Sign the hash of the message (using RSA with signing key)
    signature = sign(h, signing_key)

    # Encryption (RSA 2048 with PKCS#1 OAEP standard)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(byte_message)

    # Convert ciphertext from bytestring to hex string
    ciphertext = ciphertext.hex()

    return ciphertext, signature


def decrypt(ciphertext: hex, signature: hex,
            secret_key, verification_key):
    """ Decrypts ciphertext and verifies the signature.
    """

    # Assert that keys are of correct length and type
    assert(valid_key(secret_key))
    assert(valid_key(verification_key))

    # Convert ciphertext from hex to bytes
    ciphertext = bytes.fromhex(ciphertext)

    # Do some decryption here (RSA)
    cipher = PKCS1_OAEP.new(secret_key)
    byte_message = cipher.decrypt(ciphertext)
    message = byte_message.decode('utf-8')
    # print("M (decr.):", message)

    # Strip the padding
    pad_len = int(message[-2:])
    plaintext = message[0:-(pad_len+2)]

    # Hash the plaintext
    h = hash_as_hex(message)

    # Check that the signature is valid (for hash of message)
    if valid_signature(h, signature, verification_key):
        return plaintext
    else:
        return None


if __name__ == '__main__':
    print("Testing asymmetric encryption...")

    # Create a sample message (a 256-bit key as hex)
    message = "26c3148461677bf2db374438d55624fc26c3148461677bf2db374438d55624fc"
    print("\nMessage:", message)

    # Generate two 2048-bit RSA key pairs
    encryption_key = RSA.generate(2048)
    auth_key = RSA.generate(2048)

    # Turn the first pair into the public and private keys
    public_key = encryption_key.publickey()
    private_key = encryption_key

    # Turn the second pair into the signing and verifying keys
    verification_key = auth_key.publickey()
    signing_key = auth_key

    # Encrypt the sample message to get ciphertext and signature
    ciphertext, sig = encrypt(message, public_key, signing_key)
    print("\nCiphertext:", ciphertext, "\n")
    print("\nSignature:", sig, "\n")
    # Decrypt the ciphertext and verify signature
    decrypted = decrypt(ciphertext, sig, private_key, verification_key)
    print("\nDecrypted message:", decrypted)
