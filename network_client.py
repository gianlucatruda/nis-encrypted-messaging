import sys

from network_interface import NetworkInterface
import crypto_asymmetric
import crypto_symmetric
import crypto_tools
from crypto_tools import beautify_key_text as pretty


def main():
    interface = NetworkInterface(server=False)

    # Initiate connection and receive public keys from server
    interface.send('Connection...')
    msg = interface.blocking_receive()
    print("\nUPDATE: Received server's public keys")
    keys = msg.split('!VERIFICATION_KEY:')
    server_public_key_text = keys[0][11:]
    server_public_key = crypto_tools.hex_to_key(server_public_key_text)
    server_verification_key_text = keys[1]
    server_verification_key = crypto_tools.hex_to_key(
        server_verification_key_text)
    print("> PUBLIC:"+pretty(server_public_key_text, width=75))
    print("> VERIF.:"+pretty(server_verification_key_text, width=75)+"\n")

    # Generate two new pairs of RSA keys
    my_public_key, my_private_key, my_verification_key, my_signing_key = crypto_tools.generate_key_pairs()

    # Share public keys with server
    print("UPDATE: Broadcasting public and verification keys")
    public_key_text = my_public_key.exportKey(format='DER').hex()
    verification_key_text = my_verification_key.exportKey(format='DER').hex()
    interface.send('PUBLIC_KEY:' + public_key_text +
                   '!VERIFICATION_KEY:' + verification_key_text)
    print("> PUBLIC:"+pretty(public_key_text, width=75))
    print("> VERIF.:"+pretty(verification_key_text, width=75)+"\n")

    # Confirm server ready for asymmetric encryption
    msg = interface.blocking_receive()
    if msg != "ASYM":
        print("ERROR: Server not ready for asymmetric encryption\n")
        interface.close_connection()
        sys.exit()

    # Generate a new AES session key
    aes_key = crypto_tools.generate_aes_key()
    print("UPDATE: Secret AES key generated")
    print("> KEY:", aes_key+"\n")
    ciphertext, signature = crypto_asymmetric.encrypt(
        aes_key, server_public_key, my_signing_key)

    # Send AES session key via RSA channel
    print('UPDATE: Transmitting AES key via RSA')
    interface.send("CIPHERTEXT:" + ciphertext + "!SIGNATURE:" + signature)
    print("> CIPHERTEXT:", pretty(ciphertext, width=300) + "\n")

    # Get ciphertext (AES)
    print("UPDATE: Receiving message from server")
    ciphertext = interface.blocking_receive()
    print("> CIPHERTEXT:", pretty(ciphertext, width=300)+"\n")
    plaintext = crypto_symmetric.decrypt(ciphertext, bytes.fromhex(aes_key))
    if plaintext is None:
        print("ERROR: Server's message was not verified! There may be interference\n")
        interface.close_connection()
        sys.exit()
    else:
        print("UPDATE: Secret message decrypted and checksum verified")
        print("> MESSAGE:", pretty(plaintext,width=300)+"\n")

    # Create verification of received message by hashing
    h = crypto_tools.hash_as_hex(plaintext)

    # Send hash of message back to server so they can confirm correct.
    print("UPDATE: Confirmation integrity with server")
    secret_message = h
    print("> HASH: " + pretty(h, width=75))
    my_ciphertext = crypto_symmetric.encrypt(
        secret_message, bytes.fromhex(aes_key))
    print("> CIPHERTEXT: "+pretty(my_ciphertext, width=300))
    interface.send(my_ciphertext)

    # Await confirmation that message matches
    msg = interface.blocking_receive()
    print("> CONFIRMATION:", msg+"\n")
    if msg == "VERIFIED":
        print("UPDATE: Server verified message integrity\n")
    else:
        print("UPDATE: Message verification failed. There may be a threat\n")

    # Close connection
    interface.close_connection()
    print("UPDATE: Connection closed")
    print("-------------------------\n\n")

if __name__ == '__main__':
    main()
