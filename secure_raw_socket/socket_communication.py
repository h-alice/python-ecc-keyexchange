import asyncio
from Crypto.Cipher import AES                 # Advanced Encryption Standard algorithm.


async def send_payload(message: bytes, writer: asyncio.StreamWriter, aes_key=None) -> int:
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
        written += await send_payload(nonce, writer)
        written += await send_payload(message, writer)
        written += await send_payload(tag, writer)
        return written
    
    else:  # Normal routine for sending message.
        payload_length = len(message).to_bytes(4, byteorder='big')
        writer.write(payload_length)
        await writer.drain()
        writer.write(message)
        await writer.drain()
        written += len(message) + 4  # Additional 4 bytes for the length of the payload.
        return written

async def receive_payload(reader: asyncio.StreamReader, aes_key=None) -> bytes:
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
        nonce = await receive_payload(reader)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        encrypted_payload = await receive_payload(reader)
        tag = await receive_payload(reader)

        payload = cipher.decrypt_and_verify(encrypted_payload, tag)

        return payload
    else:  # Normal routine for receiving message.
        payload_length = await reader.read(4)
        payload = await reader.readexactly(int.from_bytes(payload_length, byteorder='big'))
        return payload