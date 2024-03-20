# Secure Socket Communication with ECC Key Exchange

## Overview

This Python script provides a proof of concept for establishing secure communication between a client and server over a socket connection.  

This script leverages Elliptic Curve Cryptography (ECC) for key exchange and Advanced Encryption Standard (AES) for encryption, ensuring confidentiality and integrity of data exchanged.

## Usage

1. Clone the repository (or just download the PoC script):
   ```bash
   git clone https://github.com/h-alice/python-ecc-keyexchange.git
   ```
2. Navigate to the project directory:
   ```bash
    cd python-ecc-keyexchange
    ```
3. Install the required dependencies:
    ```bash
    # The project is only dependent on the `pycryptodome` library.
    pip install pycryptodome
    ```
4. Run the server script:
    ```bash
    python server.py
    ```
5. Run the client script:
    ```bash
    python client.py
    ```

## Note
The procedure is designed for [Telepy](https://github.com/NatLee/telepy).   
If you want to use it in your own project, you may modify the script to fit your needs.