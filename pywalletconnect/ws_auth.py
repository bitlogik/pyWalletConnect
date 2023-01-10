# -*- coding: utf8 -*-

# pyWalletConnect  -  Web auth generator for v2 relay
# Copyright (C) 2023 BitLogiK

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import base64
from secrets import token_hex
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser

from .base58 import bin_to_base58


# WalletConnect central relay authorization needed.
# But keys are genereted on the fly, so not really an auth.


def b64enc(data):
    """Encode in web-base64 without any padding."""
    e = base64.urlsafe_b64encode(data).decode("ascii")
    return e.rstrip("=")


def gen_ws_auth():
    pv_key = Ed25519PrivateKey.generate()

    pubkey_bytes = pv_key.public_key().public_bytes(
        ser.Encoding.Raw, ser.PublicFormat.Raw
    )

    iss = "did:key:z" + bin_to_base58(b"\xED\x01" + pubkey_bytes)

    # {"alg":"EdDSA","typ":"JWT"}
    header = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
    current_time = int(time.time()) - 60
    datas = f'{{"iss":"{iss}","sub":"{token_hex(32)}","aud":"wss://relay.walletconnect.com","iat":{current_time},"exp":{current_time + 86400}}}'
    data = f"{header}{b64enc(datas.encode('ascii'))}"
    return f"{data}.{b64enc(pv_key.sign(data.encode('ascii')))}"
