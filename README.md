# Secure Messaging with Symmetric and Asymmetric Encryption

A demonstration of security principles for peer-to-peer communications of sensitive content. Read the [full whitepaper](https://github.com/gianlucatruda/nis-encrypted-messaging/whitepaper.pdf).

## Environment

* Python 3.6
* [pycrypto](https://pypi.org/project/pycrypto/)

## Overview

### Networking module

The networking module ```network_interface.py``` performs all network communication between the client and the server. 

### Cryptographic modules
Three modules implement the required cryptographic methods. 


* ```crypto_asymmetric.py``` - Provides encryption and decryption methods implementing RSA.
* ```crypto_symmetric.py``` - Provides encryption and decryption methods implementing AES. 
* ```crypto_tools.py``` - Provides utility support and helper functions to the other two crypto modules, including digital signatures and verification.

## Task 1 - Asymmetric Cryptography

_"You are required to code and report on an application that can distribute symmetric keys using asymmetric cryptography."_

Overall, each peer will have two sets of public-private key pairs. The first set is for typical RSA encryption. The second is creating and verifying digital signatures.

The client and server establish a connection, receive each other's public keys and then commence secure communication using RSA encryption. They use this to distribute a shared, 256-bit AES session key (used in Task 2). 

* RSA-2048 (for actually sending the message)
* Digital signing (for source authentication)
* Padding of message (to prevent 'short message' attack)

## Task 2 - Symmetric Cryptography

_"You are required to code and report on an application that can encrypt a message with only a symmetric key."_

Once the shared session key is distributed (in Task 1), encrypted communication takes place using AES encryption. 

* AES-256 (for the encryption/decryption)
* SHA-256 (for checksumming)
* Authenticity is implicit due to session key signing performed in Task 1 


## Installation
 
After downloading and unzipping the project files, ensure that Python 3.6 is installed. On Linux, this can be done by executing:

```bash
sudo apt-get install python3.6
``` 

Next, install the PyCrypto dependency. This is most easily done using pip package manager:

```bash
python3.6 -m pip install pycrypto
```

Alternatively, it can be manually downloaded [here](https://pypi.org/project/pycrypto/#files).


## Usage

**Task 1** and **Task 2** are demonstrated sequentially in a single pair of programs.

The demo requires two terminal windows to be open, and is best experienced when both terminals are visible at the same time. 

Start the **server** application in one of the two terminals by running:

```bash
python3.6 network_server.py
```

If this starts correctly, you should see ``` Listening to localhost on port 1302 ``` as the server waits for a connection.

In the other terminal, run the **client** by executing:

```bash
python3.6 network_client.py
```

When this runs, the client and server should connect and communication should be displayed. 

For demonstration purposes, a plethora of debug statements are printed to the terminal which show and describe each stage in the process of communication. In practice, this would be hidden from the end-users.

## Contributors

* [Gianluca Truda](https://github.com/gianlucatruda)
* [Luke Neville](https://github.com/Nevter)
* [Zak Toyer](https://github.com/zed925)
* [Robbie Barnhoorn](https://github.com/RobbieBarnhoorn)

## Disclaimer

This software is for demonstration purposes only and should not be used in production code, as security is not guaranteed. The creators accept no liability whatsoever.
