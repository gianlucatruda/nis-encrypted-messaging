""" A set of tools for digital signatures and key validation.
This is for use in tasks 1 and 2.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import random
from Crypto.Hash import SHA256
import os


def sign(message: str, signing_key):
	""" Hashes message, signs hash with private key, returns signature.

	:param message: the message to encrypt as a utf-8 string.
	:param signing_key: the key to digitally sign the message-padding pair.
	It must be a pycrypto PublicKey.RSA type, 2048-bit.
	:return: a hexadecimal encoding of ciphertext.
	"""

	# Assert that keys are of correct length and type
	assert (valid_key(signing_key))

	# Generate hash of message (SHA)
	h = SHA256.new(bytes(message, 'utf-8'))
	# Sign the message using the signing key and hash
	signer = PKCS1_v1_5.new(signing_key)
	signature = signer.sign(h)

	# Convert signature form byte string to hex
	signature = signature.hex()

	return signature


def valid_signature(message: str, signature: hex, verification_key):
	""" Verifies a digital signature using the peer's public signing key.

	:param message: the plaintext message as a string.
	:param signature: a hexadecimal signature to validate.
	:param verification_key: the key to verify the signature.
	It must be a pycrypto PublicKey.RSA type, 2048-bit.
	:return: a boolean. True if signature is valid, else False.
	"""

	# Assert that keys are of correct length and type
	assert (valid_key(verification_key))

	# Convert signature from hex string to byte string
	signature = bytes.fromhex(signature)

	# Hash the message
	h = SHA256.new(bytes(message, 'utf-8'))

	# Verify the message
	verifier = PKCS1_v1_5.new(verification_key)

	return True if verifier.verify(h, signature) else False


def valid_key(key, standard='RSA2048'):
	""" Checks validity (length and type) of a key object.

	:param key: some encryption key object.
	:param standard: an optional string that describes the standard.
	Default is RSA2048.
	:return: a boolean. True if key is of correct length and type, else False.
	"""

	standard = standard.lower()
	if standard != "rsa2048":
		print(
			"Error validating key: Unsupported standard '{}'".format(standard))
		return False
	else:
		if key.size() == 2047 and type(key) is RSA._RSAobj:
			return True
		else:
			print("Error: You're using the wrong type or length of key.")
			return False

def generate_key_pairs():
	""" Generates two pairs of RSA2048 keys and returns as 4-tuple.

	:return public, private, verification, signing
	"""

	# Generate public and private keys
	pair1 = RSA.generate(2048)
	public_key = pair1.publickey()
	private_key = pair1

	# Generate signing and verifying keys
	pair2 = RSA.generate(2048)
	verification_key = pair2.publickey()
	signing_key = pair2

	return public_key, private_key, verification_key, signing_key

def hex_to_key(hex_key :str):
	""" Converts strings of hexadecimal into an RSA key object
	"""
	binary_key = bytes.fromhex(hex_key)
	out_key = RSA.importKey(binary_key)

	return out_key

def key_to_hex(key):
	""" Converts RSA key object to hexidecimal string.
	"""

	assert(valid_key(key))
	return key.exportKey(format='DER').hex()

def generate_aes_key(bits=256):
	""" Generates a new AES key and returns as hex string.
	"""
	return os.urandom(32).hex()

def hash_as_hex(plaintext :str):
	""" Generates SHA256 hash of given string and returns hex string.
	"""
	data = plaintext.encode()
	h = SHA256.new(data)
	return h.hexdigest()

def beautify_key_text(key_text :str, width=80):
	""" Converts long encryption key text better-looking string.
	"""
	if len(key_text) > width:
		return key_text[0:(width//2) - 2] + "..." + key_text[-(width//2) + 1:]
	else:
		return key_text

if __name__ == '__main__':
	print("testing tools...")
	k, a, b, c = generate_key_pairs()
	print(beautify_key_text(key_to_hex(k)))
