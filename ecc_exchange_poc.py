"""
2024 Lazy Labs. 

The script provides a proof of concept for secure client initialization over an insecure socket connection.
It establishes a secure channel by exchanging public keys and generating a shared secret. 

Upon connection, the client and server exchange greetings, initiate key exchange, and execute commands securely. 
Messages are encrypted using AES with the shared secret, ensuring data confidentiality. 
For future use, the method can be extended to include sending SSH private keys, certificates, and other sensitive data.

Usage:
    python ecc_exchange_poc.py [client|server]

The script is tested with python 3.11 on MacBook Pro M2.

Requirements:
    pycryptodome
    
"""
import asyncio
import functools
import os
import subprocess
import sys  # For command line arguments.

from Crypto.PublicKey import ECC              # Ellieptic Curve Cryptography algorithm.
from Crypto.Cipher import AES                 # Advanced Encryption Standard algorithm.
from Crypto.Hash import SHA256                # Secure Hash Algorithm 256-bit.
from Crypto.Protocol.DH import key_agreement  # Diffie-Hellman key agreement procedure.
from Crypto.Protocol.KDF import HKDF          # Key Derivation Function.

# Partial function for HKDF with predefined parameters
predefined_kdf = functools.partial(HKDF,
                         key_len=32,
                         salt=b'telepy:',
                         hashmod=SHA256,
                         num_keys=1,
                         context=b'Telepy client authentication')

async def send_message(message: bytes, writer: asyncio.StreamWriter, aes_key=None) -> int:
    """
    Asynchronously send a message over a stream writer.

    Parameters:
        message (bytes): The message to send.
        writer (asyncio.StreamWriter): The stream writer to use for sending.
        aes_key (bytes, optional): The AES key for encryption. If provided, the payload will be encrypted.

    Returns:
        int: The number of bytes written (including the length of the payload).
    """
    written = 0

    if aes_key:  # Routine for sending AES parameters and encrypted payload.
        cipher = AES.new(aes_key, AES.MODE_GCM)
        nonce = cipher.nonce
        message, tag = cipher.encrypt_and_digest(message)

        # Send nonce, message, and tag
        written += await send_message(nonce, writer)
        written += await send_message(message, writer)
        written += await send_message(tag, writer)
        return written
    
    else:  # Normal routine for sending message.
        payload_length = len(message).to_bytes(4, byteorder='big')
        writer.write(payload_length)
        await writer.drain()
        writer.write(message)
        await writer.drain()
        written += len(message) + 4  # Additional 4 bytes for the length of the payload.
        return written

async def receive_message(reader: asyncio.StreamReader, aes_key=None) -> bytes:
    """
    Asynchronously receive a message from a stream reader.

    Parameters:
        reader (asyncio.StreamReader): The stream reader to use for receiving.
        aes_key (bytes, optional): The AES key for decryption. If provided, the payload is expected to be encrypted and will be decrypted.

    Returns:
        bytes: The received message.
    """
    if aes_key:  # Routine for receiving AES parameters and encrypted payload.
        # Receive nonce, encrypted payload, and tag
        nonce = await receive_message(reader)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        encrypted_payload = await receive_message(reader)
        tag = await receive_message(reader)

        payload = cipher.decrypt_and_verify(encrypted_payload, tag)

        return payload
    else:  # Normal routine for receiving message.
        payload_length = await reader.read(4)
        payload = await reader.readexactly(int.from_bytes(payload_length, byteorder='big'))
        return payload

async def server_side_client_init(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, aes_key: bytes) -> bool:
    """
    Securely initialize the client.
    The method is for server-side.

    NOTE: This method is just a demonstration of the client initialization.
          User should implement their own initialization sequence.

    Parameters:
        reader (asyncio.StreamReader): The stream reader to use for receiving.
        writer (asyncio.StreamWriter): The stream writer to use for sending.
        aes_key (bytes): The AES key for encryption/decryption.

    Returns:
        bool: True if initialization succeeds, False otherwise.
    """
    # Sending command prompt action to the client.
    command1 = f'echo "This is client id:{os.urandom(16).hex()} ready for initializtion."'  # Random client id.
    command2 = f'ls -la'
    command3 = "who -u"

    await send_message(command1.encode(), writer, aes_key)  # Send command 1.

    # Await client done signal.
    signal = await receive_message(reader, aes_key)
    if signal != b'done':
        print("[-] Invalid signal received, expected 'done'.")
        return False  # Terminate the sequence.

    await send_message(command2.encode(), writer, aes_key)  # Send command 2.

    # Await client done signal.
    signal = await receive_message(reader, aes_key)
    if signal != b'done':
        print("[-] Invalid signal received, expected 'done'.")
        return False  # Terminate the sequence.
    
    output = await receive_message(reader, aes_key)  # Receive output of command 2.
    print(f"[+] Output of command 2:\n{output.decode()}")

    await send_message(command3.encode(), writer, aes_key)  # Send command 3.

    # Await client done signal.
    signal = await receive_message(reader, aes_key)
    if signal != b'done':
        print("[-] Invalid signal received, expected 'done'.")
        return False  # Terminate the sequence.
    
    output = await receive_message(reader, aes_key)  # Receive output of command 3.
    print(f"[+] Output of command 3:\n{output.decode()}")

    return True

async def client_side_client_init(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, aes_key: bytes) -> bool:
    """
    Securely initialize the client.
    The method is for client-side.
    NOTE: This method is just a demonstration of the client initialization.
          User should implement their own initialization sequence.

    Parameters:
        reader (asyncio.StreamReader): The stream reader to use for receiving.
        writer (asyncio.StreamWriter): The stream writer to use for sending.
        aes_key (bytes): The AES key for encryption/decryption.

    Returns:
        bool: True if initialization succeeds, False otherwise.
    """
    # Receive command 1.
    command1 = await receive_message(reader, aes_key)
    os.system(command1.decode())  # Execute command 1.

    # Send done signal.
    await send_message(b'done', writer, aes_key)

    # Receive command 2.
    command2 = await receive_message(reader, aes_key)
    output = subprocess.check_output(command2.decode(), shell=True)

    # Send done signal.
    await send_message(b'done', writer, aes_key)
    await send_message(output, writer, aes_key)  # Send output of command 2.

    # Receive command 3.
    command3 = await receive_message(reader, aes_key)
    output = subprocess.check_output(command3.decode(), shell=True)

    # Send done signal.
    await send_message(b'done', writer, aes_key)
    await send_message(output, writer, aes_key)  # Send output of command 3.

    return True

async def handle_client(reader, writer):
    """
    Asynchronously handle a client connection.

    Parameters:
        reader: The stream reader to use for receiving.
        writer: The stream writer to use for sending.
    """

    print("[.] New connection.")
    message = await receive_message(reader)

    if message == b'telepy client hello':

        # Send server hello.
        await send_message(b'telepy server hello', writer)

        print(f"[+] Client hello received, initialize key exchange sequence.")

        # Step 1: Generate server's private key and public key.
        #         The public key will be sent to the client.
        server_priv = ECC.generate(curve='ed25519')
        server_pub = server_priv.public_key()

        written = await send_message(server_pub.export_key(format='DER'), writer)
        print(f"[.] Server public key sent, {written} bytes written.")

        # Step 2: Receive client's public key.
        client_pub_key = await receive_message(reader)
        client_pub_key = ECC.import_key(client_pub_key)
        print(f"[+] Client public key received.")

        # Step 3: Generate shared secret.
        session_key = key_agreement(static_priv=server_priv, static_pub=client_pub_key, kdf=predefined_kdf)
        print(f"[+] Shared secret generated {session_key.hex()}")

        # From now on, the session key will be used for encryption and decryption.
        # All data will be encrypted using the session key.
        # Super secure!!!

        await server_side_client_init(reader, writer, session_key)

        print("[+] All done! Closing the connection.")

    else:
        # Close the connection.
        print("[-] Invalid client hello, closing the connection.")
        writer.close()

    print("Closing the connection")
    writer.close()

async def client():
    """
    Run the client.
    """
    reader, writer = await asyncio.open_connection('127.0.0.1', 9487)

    print('[.] Sending: telepy client hello.')

    await send_message(b'telepy client hello', writer)

    print('[.] Waiting for server hello')
    message = await receive_message(reader)

    if message == b'telepy server hello':
        print(f'[+] Received server hello, initialize key exchange sequence.')

        server_pub_key = await receive_message(reader)
        server_pub_key = ECC.import_key(server_pub_key)
        print('[+] Server public key received')

        client_priv = ECC.generate(curve='ed25519')  # Generate client's private key.
        client_pub = client_priv.public_key()  # Generate client's public key.

        # Step 2: Send client's public key to the server.
        print(f'[.] Sending client public key to the server.')
        await send_message(client_pub.export_key(format='DER'), writer)

        # Step 3: Generate shared secret.
        session_key = key_agreement(static_priv=client_priv, static_pub=server_pub_key, kdf=predefined_kdf)
        print(f"[+] Shared secret generated {session_key.hex()}")

        await client_side_client_init(reader, writer, session_key)
        print("[+] All done! Closing the connection.")
        writer.close()  # Gracefully close the connection.

    else:
        print('[x] Invalid server hello, closing the connection.')
        writer.close()

    print('Closing the connection')
    writer.close()

async def server():
    """
    Run the server.
    """
    server = await asyncio.start_server(
        handle_client, '127.0.0.1', 9487)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ecc_exchange_poc.py [client|server]")
        sys.exit(1)
    if sys.argv[1] == "client":
        asyncio.run(client())
    elif sys.argv[1] == "server":
        asyncio.run(server())
