# -*- coding: utf8 -*-

# pyWalletConnect : Encrypted Tunnel
# Copyright (C) 2021 BitLogiK

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

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# ---- Crypto primitives


AES_BLOCK_SIZE = 16
AES_BLOCK_SIZE_BITS = AES_BLOCK_SIZE << 3


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
    """Provide an encryption tunnel for WalletConnect messages."""

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
