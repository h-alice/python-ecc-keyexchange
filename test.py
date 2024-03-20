"""
2024 Lazy Labs. 

The script provides a proof of concept for secure client initialization over an insecure socket connection.
It establishes a secure channel by exchanging public keys and generating a shared secret. 

This script is identical to the ecc_exchange_poc.py script, but it demonstrates the use of the secure_raw_socket package for simplified implementation.
For more information, see the description of the ecc_exchange_poc.py script.

Usage:
    python test.py [client|server]

The script is tested with python 3.11 on MacBook Pro M2.

Requirements:
    pycryptodome
    
"""
import asyncio
import os
import subprocess
import sys  # For command line arguments.

from secure_raw_socket import send_payload, receive_payload
from secure_raw_socket.ecc_key_exange import server_side_key_exchange, client_side_key_exchange


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

    await send_payload(command1.encode(), writer, aes_key)  # Send command 1.

    # Await client done signal.
    signal = await receive_payload(reader, aes_key)
    if signal != b'done':
        print("[-] Invalid signal received, expected 'done'.")
        return False  # Terminate the sequence.

    await send_payload(command2.encode(), writer, aes_key)  # Send command 2.

    # Await client done signal.
    signal = await receive_payload(reader, aes_key)
    if signal != b'done':
        print("[-] Invalid signal received, expected 'done'.")
        return False  # Terminate the sequence.
    
    output = await receive_payload(reader, aes_key)  # Receive output of command 2.
    print(f"[+] Output of command 2:\n{output.decode()}")

    await send_payload(command3.encode(), writer, aes_key)  # Send command 3.

    # Await client done signal.
    signal = await receive_payload(reader, aes_key)
    if signal != b'done':
        print("[-] Invalid signal received, expected 'done'.")
        return False  # Terminate the sequence.
    
    output = await receive_payload(reader, aes_key)  # Receive output of command 3.
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
    command1 = await receive_payload(reader, aes_key)
    os.system(command1.decode())  # Execute command 1.

    # Send done signal.
    await send_payload(b'done', writer, aes_key)

    # Receive command 2.
    command2 = await receive_payload(reader, aes_key)
    output = subprocess.check_output(command2.decode(), shell=True)

    # Send done signal.
    await send_payload(b'done', writer, aes_key)
    await send_payload(output, writer, aes_key)  # Send output of command 2.

    # Receive command 3.
    command3 = await receive_payload(reader, aes_key)
    output = subprocess.check_output(command3.decode(), shell=True)

    # Send done signal.
    await send_payload(b'done', writer, aes_key)
    await send_payload(output, writer, aes_key)  # Send output of command 3.

    return True

async def handle_client(reader, writer):
    """
    Asynchronously handle a client connection.

    Parameters:
        reader: The stream reader to use for receiving.
        writer: The stream writer to use for sending.
    """

    print("[.] New connection.")
    message = await receive_payload(reader)

    if message == b'telepy client hello':

        # Send server hello.
        await send_payload(b'telepy server hello', writer)

        print(f"[+] Client hello received, initialize key exchange sequence.")

        session_key = await server_side_key_exchange(reader, writer)  # Perform key exchange.

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

    await send_payload(b'telepy client hello', writer)

    print('[.] Waiting for server hello')
    message = await receive_payload(reader)

    if message == b'telepy server hello':
        print(f'[+] Received server hello, initialize key exchange sequence.')

        session_key = await client_side_key_exchange(reader, writer)  # Perform key exchange.
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
