# -*- coding: utf8 -*-

# pyWalletConnect : Encrypted Tunnel
# Copyright (C) 2021-2022 BitLogiK

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have receive a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


"""EncryptedTunnel for pyWalletConnect"""


from json import loads
from os import urandom

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# ---- Crypto primitives


AES_BLOCK_SIZE = 16
AES_BLOCK_SIZE_BITS = AES_BLOCK_SIZE << 3


def msg_digest(msg, halgo):
    """Base secure hash standard function."""
    digest = hashes.Hash(halgo)
    digest.update(msg)
    return digest.finalize()


def sha2_256(msg):
    """Compute SHA256."""
    return msg_digest(msg, hashes.SHA256())


def sha2_512(msg):
    """Compute SHA512."""
    return msg_digest(msg, hashes.SHA512())


def hmac_sha256(key, message):
    """Compute a Hash-based Message Authentication Code
    using the SHA256 hash function.
    """
    hmac256 = hmac.HMAC(key, hashes.SHA256())
    hmac256.update(message)
    return hmac256.finalize()


def check_hmac(message, mac, key):
    """Verify the HMAC signature."""
    hmac256 = hmac.HMAC(key, hashes.SHA256())
    hmac256.update(message)
    # Can throw cryptography.exceptions.InvalidSignature
    hmac256.verify(mac)


def pad_data(databin):
    """Add a PCKS7 message padding for AES."""
    padder = PKCS7(AES_BLOCK_SIZE_BITS).padder()
    return padder.update(databin) + padder.finalize()


def unpad_data(databin_padded):
    """Remove a PCKS7 padding from the message for AES."""
    remover = PKCS7(AES_BLOCK_SIZE_BITS).unpadder()
    # Can throw ValueError if the padding is incorrect
    return remover.update(databin_padded) + remover.finalize()


def encrypt_aes(key, message):
    """Encrypt a message with a key using AES-CBC."""
    init_vector = urandom(AES_BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
    encryptor = cipher.encryptor()
    enc_data = encryptor.update(pad_data(message)) + encryptor.finalize()
    return (enc_data, init_vector)


def decrypt_aes(key, init_vector, message):
    """Decrypt a message with a key using AES-CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
    decryptor = cipher.decryptor()
    clear_txt = decryptor.update(message) + decryptor.finalize()
    return unpad_data(clear_txt)


# ---- Encrypted channel class


class EncryptedTunnel:
    """Provide an encryption tunnel for WalletConnect v1 messages."""

    def __init__(self, key):
        """Start a tunnel with an AES key."""
        self.key = key

    def encrypt_payload(self, message):
        """Encrypt a bytes message into a payload object."""
        enc_msg_iv = encrypt_aes(self.key, message)
        mac_data = hmac_sha256(self.key, enc_msg_iv[0] + enc_msg_iv[1]).hex()
        payload_obj = {
            "data": enc_msg_iv[0].hex(),
            "hmac": mac_data,
            "iv": enc_msg_iv[1].hex(),
        }
        return payload_obj

    def decrypt_payload(self, fullpayload_obj):
        """Decrypt a payload object into a bytes message."""
        payload_obj = loads(fullpayload_obj["payload"])
        msg_bin = bytes.fromhex(payload_obj["data"])
        mac_sig = bytes.fromhex(payload_obj["hmac"])
        init_vector = bytes.fromhex(payload_obj["iv"])
        check_hmac(msg_bin + init_vector, mac_sig, self.key)
        return decrypt_aes(self.key, init_vector, msg_bin)


class EncryptedTunnelv2:
    """Provide an encryption tunnel for WalletConnect v2 messages."""

    def __init__(self, pubkey, enc_key, mac_key):
        """Start a v2 tunnel."""
        self.enckey = enc_key
        self.mackey = mac_key
        self.pubkey = pubkey

    def encrypt_payload(self, message_str, encod="utf8"):
        """Encrypt a string or bytes message into a hex message.
        If encod is None or "", the message is read as binary bytes.
        iv, publicKey, mac and cipherText
        """
        if encod:
            message = message_str.encode(encod)
        else:
            message = message_str
        enc_msg_iv = encrypt_aes(self.enckey, message)
        mac_data = hmac_sha256(
            self.mackey, enc_msg_iv[1] + self.pubkey + enc_msg_iv[0]
        ).hex()
        return enc_msg_iv[1].hex() + self.pubkey.hex() + mac_data + enc_msg_iv[0].hex()

    def decrypt_payload(self, fullpayload_hex):
        """Decrypt a payload object into a bytes message."""
        init_vector = bytes.fromhex(fullpayload_hex[:32])
        pubkey = bytes.fromhex(fullpayload_hex[32:96])
        mac_sig = bytes.fromhex(fullpayload_hex[96:160])
        enc_msg = bytes.fromhex(fullpayload_hex[160:])
        check_hmac(init_vector + pubkey + enc_msg, mac_sig, self.mackey)
        return decrypt_aes(self.enckey, init_vector, enc_msg).decode("utf8")


# ---- Asymmetric key pair class for v2


class KeyAgreement:
    """X25519 key pair."""

    def __init__(self):
        """Generate an X25519 key pair."""
        self.key = X25519PrivateKey.generate()
        self.shared_key = None

    def get_pubkey(self):
        """Give the local public key."""
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def compute_shared_key(self, peer_key_hex):
        """Compute shared key from the peer proposer public key."""
        peer_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_key_hex))
        self.shared_key = self.key.exchange(peer_public_key)

    def derive_enc_key(self):
        """uses a SHA512 hash of the shared key
        using the first 32bytes for encryption
        and the last 32 bytes for authentication.
        """
        hashk = sha2_512(self.shared_key)
        return hashk[:32], hashk[32:]

    def derive_topic(self):
        """Topic for the next sequence."""
        return sha2_256(self.shared_key).hex()
