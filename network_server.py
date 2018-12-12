from network_interface import NetworkInterface
import crypto_asymmetric
import crypto_symmetric
import crypto_tools
from crypto_tools import beautify_key_text as pretty
import sys

def main():
    interface = NetworkInterface(server=True)

    msg = interface.blocking_receive()
    print(msg)

    # Generate two new pairs of RSA keys
    my_public_key, my_private_key, my_verification_key, my_signing_key = crypto_tools.generate_key_pairs()

    # Broadcast public key and verification key
    print("\nUPDATE: Broadcasting public and verification keys")
    public_key_text = crypto_tools.key_to_hex(my_public_key)
    verification_key_text = crypto_tools.key_to_hex(my_verification_key)
    interface.send('PUBLIC_KEY:' + public_key_text +
        '!VERIFICATION_KEY:' + verification_key_text)
    print("> PUBLIC: " + pretty(public_key_text, width=75))
    print("> VERIF.: " + pretty(verification_key_text, width=75) + "\n")

    # Receive public keys from client
    msg = interface.blocking_receive()
    keys = msg.split('!VERIFICATION_KEY:')
    print("UPDATE: Received client's public and verification keys")
    client_public_key_text = keys[0][11:]
    client_public_key = crypto_tools.hex_to_key(client_public_key_text)
    client_verification_key_text = keys[1]
    client_verification_key = crypto_tools.hex_to_key(
        client_verification_key_text)
    print("> PUBLIC: " + pretty(client_public_key_text, width=75))
    print("> VERIF.: " + pretty(client_verification_key_text, width=75) + "\n")

    # Confirm ready for asymmetric encryption
    print("UPDATE: Asking client for session AES key\n")
    interface.send('ASYM')
    msg = interface.blocking_receive()
    keys = msg.split('!SIGNATURE:')
    client_ciphertext = keys[0][11:]
    client_signature = keys[1]
    print("UPDATE: Received RSA ciphertext and signature")
    print("> CIPHERTEXT: " + pretty(client_ciphertext,width=300))
    print("> SIGNATURE: " + pretty(client_signature, width=75) + "\n")

    # Decyrpt ciphertext and verify message with signature
    print("UPDATE: Decrypting message and verifying signature")
    plaintext = crypto_asymmetric.decrypt(
        client_ciphertext, client_signature,
        my_private_key, client_verification_key)
    if plaintext is None:
        print("ERROR: Signature incorrect. There may be a threat\n")
        interface.close_connection()
        sys.exit()
    else:
        print("> MESSAGE (sess. key):", pretty(plaintext, width=300)+" (verified)\n")
        aes_key = plaintext

    # Send a secret message to client using received AES key
    print("UPDATE: Sending secret message to client using AES session key")
    secret_message = "Bush did 9/11 and Harambe was an inside job."
    my_ciphertext = crypto_symmetric.encrypt(
        secret_message, bytes.fromhex(aes_key))
    print("> MESSAGE: " + pretty(secret_message, width=300))
    print("> CIPHERTEXT: " + pretty(my_ciphertext, width=300)+"\n")
    interface.send(my_ciphertext)

    # Receive hash of message from client through same AES scheme
    print("UPDATE: Receiving hash of message for integrity check")
    ciphertext = interface.blocking_receive()
    print("> CIPHERTEXT:", pretty(ciphertext, width=300) + "\n")
    plaintext = crypto_symmetric.decrypt(ciphertext, bytes.fromhex(aes_key))
    print("UPDATE: AES message decrypted")
    print("> MESSAGE (hash):", pretty(plaintext, width=300) + "\n")

    # Check that received hash matches hash of sent message
    h = crypto_tools.hash_as_hex(secret_message)
    if h == plaintext:
        print("UPDATE: Verified. Client received the secret message successfully\n")
        interface.send("VERIFIED")
    else:
        print("UPDATE: Verification failed. There may be a security risk\n")
        interface.send("FAILED")

    # Close the connection
    interface.close_connection()
    print("UPDATE: Connection closed")
    print("-------------------------\n\n")


if __name__ == '__main__':
    main()
