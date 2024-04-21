# Description

The application created simulates secure peer2peer communication between Alice and Bob. Each of these clients can be both sender and receiver. The secure data exchange application allows users to exchange data securely using cryptography over elliptic curves (ECDH). The application provides functions for data signing (ECDSA, EdDSA) and message encryption over elliptic curves (ECIES). It allows to create secure peer-to-peer connections and uses various cryptographic algorithms to ensure data security and integrity.

All cryptographic keys used are stored in the Keys folder. Keys that are not to be disclosed are then stored encrypted. The entire application records all important events in an organized manner. The entire application has been designed to run on localhost.

The application can be used to transfer files by entering the sendFile command, or it can also transfer encrypted messages.

### File description

In this project are created two peers: ```Alice.py``` and ```Bob.py```, both located at ```/PeerToPeer``` folder.

Both peers use protocols located at ```/Protocols``` folder - files ```ECDH.py```, ```ECIES.py``` and file ```signature.py```, which contains ECDSA and EdDSA protocols for digital signature of messages and files.

During the communication, keys of each peer are generated and stored at ```/Keys``` folder, which contains ECDH public and shared key and ECDSA and EdDSA private and public keys of Alice and Bob at ```/Keys/Signature``` folder, where private keys are encrypted and protected by user password.

Progress of whole communication by each peer is stored at ```/PeerToPeer/Logs``` in ```alice_peer.log``` and ```bob_peer.log```.

Whole documentation is generated automatically and stored at ```index.html```.

https://github.com/jendahejna/Elliptic-Curves-Cryptography-project.git

# Requirements
1. Python 3.11+
2. Libraries specified in Requirements file

# How to run
1. Start 1st peer (e.g., ```Alice.py```, ```Bob.py```) in ```/PeerToPeer``` folder.
2. Start 2nd peer (e.g., ```Alice.py```, ```Bob.py```) in ```/PeerToPeer``` folder.
3. Choose the elliptic curve for ECDH key generation.
4. Choose the algorithm for digital signature.
5. Choose the encryption method for ECIES.
6. Choose the new file password for file encryption.
7. Send messages or files using sendFile command.

# Project authors
- Jan Hejna, 221545 
- Daniel Kluka, 203251 
- Jan Rezek, 227374 
- Michal Rosa, 221012

### Documentation authors 
- Daniel Kluka, 203251 
- Michal Rosa, 221012

### README.md author and date
- Daniel Kluka, 203251
- 21.4.2024


