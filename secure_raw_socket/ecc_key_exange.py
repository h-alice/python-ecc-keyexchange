import asyncio
import functools
from Crypto.PublicKey import ECC              # Ellieptic Curve Cryptography algorithm.
from Crypto.Cipher import AES                 # Advanced Encryption Standard algorithm.
from Crypto.Hash import SHA256                # Secure Hash Algorithm 256-bit.
from Crypto.Protocol.DH import key_agreement  # Diffie-Hellman key agreement procedure.
from Crypto.Protocol.KDF import HKDF          # Key Derivation Function.

import logging

from .socket_communication import send_payload, receive_payload

logger = logging.getLogger(__name__)


PREDEFINED_KDF = functools.partial(HKDF,
                         key_len=32,
                         salt=b'telepy:',
                         hashmod=SHA256,
                         num_keys=1,
                         context=b'Telepy client authentication')

async def server_side_key_exchange(reader:asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    """
    Asynchronously perform the server side of the key exchange.

    Parameters:
        reader (asyncio.StreamReader): The stream reader to use for receiving.
        writer (asyncio.StreamWriter): The stream writer to use for sending.

    Returns:
        bytes: The shared secret key.
    """
    logger.info('[+] Starting server side key exchange sequence.')

    # Step 1: Generate server's private key and public key.
    #         The public key will be sent to the client.
    server_priv = ECC.generate(curve='ed25519')
    server_pub = server_priv.public_key()

    written = await send_payload(server_pub.export_key(format='DER'), writer)
    logger.debug(f"[.] Server public key sent, {written} bytes written.")

    # Step 2: Receive client's public key.
    client_pub_key = await receive_payload(reader)
    client_pub_key = ECC.import_key(client_pub_key)
    logger.debug(f"[+] Client public key received.")

    # Step 3: Generate shared secret.
    session_key = key_agreement(static_priv=server_priv, static_pub=client_pub_key, kdf=PREDEFINED_KDF)
    logger.info(f"[+] Shared secret generated, key exange complete.")

    return session_key

async def client_side_key_exchange(reader:asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    """
    Asynchronously perform the client side of the key exchange.

    Parameters:
        reader (asyncio.StreamReader): The stream reader to use for receiving.
        writer (asyncio.StreamWriter): The stream writer to use for sending.
    """
    logger.info(f'[+] Received server hello, initialize key exchange sequence.')
    logger.debug("[.] Waiting server public key.")


    # Step 1: Receive server's public key.
    server_pub_key = await receive_payload(reader)
    server_pub_key = ECC.import_key(server_pub_key)
    logger.debug('[+] Server public key received')

    client_priv = ECC.generate(curve='ed25519')  # Generate client's private key.
    client_pub = client_priv.public_key()  # Generate client's public key.

    # Step 2: Send client's public key to the server.
    logger.debug(f'[.] Sending client public key to the server.')
    await send_payload(client_pub.export_key(format='DER'), writer)

    # Step 3: Generate shared secret.
    session_key = key_agreement(static_priv=client_priv, static_pub=server_pub_key, kdf=PREDEFINED_KDF)
    logger.info(f"[+] Shared secret generated, key exange complete.")

    return session_key