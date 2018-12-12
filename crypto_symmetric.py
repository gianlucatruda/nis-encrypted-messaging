""" A set of tools for symmetric encryption and decryption.
This is for use in task 2.
"""

# Imports
import hashlib
from Crypto.Cipher import AES

def encrypt(message, secret_key):
    """ Generates a ciphertext using a message and shared secret key.
    """
    # Do checksumming (using SHA256) and append to message
    h = hashlib.sha256()
    h.update(message.encode('UTF-8'))
    message += h.hexdigest()

    # pad with ! after the checksum because AES needs multiple of 16
    new_message = message.ljust(((len(message)+15)//16)*16,'!')

    # Do encryption here (AES256)
    encryption_suite = AES.new(secret_key)
    ciphertext = encryption_suite.encrypt(new_message)

    return ciphertext.hex()

def decrypt(ciphertext, secret_key):
    """ Retrieves the message from a ciphertext using a shared secret key.
    """
    # Convert ciphertext to byte format
    ciphertext = bytes.fromhex(ciphertext)

    # Do decryption here (AES256)
    encryption_suite = AES.new(secret_key)
    message = encryption_suite.decrypt(ciphertext).decode('utf-8')

    # First remove ! padding
    while message[-1]=='!':
        message=message[:-1]

    # checksum is last 64 characters
    checksum = message[-64:]
    message = message.replace(checksum,'')
    # Make sure that the checksum matches (SHA256)
    if verify(message, checksum):
        return message
    else:
        return False


def verify(message, checksum):

    # hash everything but the padding
    verification = hashlib.sha256()
    verification.update(message.encode('UTF-8'))

    return verification.hexdigest() == checksum


def main():
    # generate key
    key = hashlib.sha256()
    key.update(b'honours is cool')
    message = "Hello World!"

    # encrypt
    cipher = encrypt(message, key.digest())
    print("Encrypted message",cipher)
    # decrypt
    mess = decrypt(cipher, key.digest())
    print("Decrypted message: ",mess)
    # check if they match
    print(mess==message)

if __name__ == '__main__':
    main()