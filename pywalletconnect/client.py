# -*- coding: utf8 -*-

# pyWalletConnect : WalletConnect wallet client
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


"""WalletConnect wallet client for pyWalletConnect"""


from urllib.parse import unquote
from json import loads
from logging import getLogger
from re import compile as regex_compile
from threading import Timer
from time import sleep
from uuid import uuid4

from .websocket import WebSocketClient, CYCLES_TIMEOUT, UNIT_WAITING_TIME
from .enc_tunnel import EncryptedTunnel
from .json_rpc import json_encode, json_rpc_pack_response, json_rpc_unpack
from .version import VERSION

# ---- WalletConnect settings


wallet_metadata = {
    "description": f"pyWalletConnect v{VERSION} by BitLogiK",
    "url": "https://github.com/bitlogik/pyWalletConnect",
    "icons": [""],
    "name": "pyWalletConnect",
}

WC_AES_KEY_SIZE = 32  # WCv1 uses 256 bits AES key

logger = getLogger(__name__)


class WCClientException(Exception):
    """Exception from the WalletConnect client."""


class WCClientInvalidOption(Exception):
    """Exception from the WebSocket client when decoding URI input."""


class WCClient:
    """WalletConnect wallet client connected to a relay with WebSocket."""

    wc_uri_pattern = regex_compile(r"^wc:(.+)@(\d)\?bridge=(.+)&key=(.+)$")

    def __init__(self, ws_url, topic, symkey):
        """Create a WalletConnect client from parameters.
        Call open_session immediately after to get the session request info.
        """
        # Chain ID is managed outside the walletconnect classes
        # Shall be managed by the user / webapp
        logger.debug("Opening a WalletConnect client with %s", ws_url)
        self.relay_url = ws_url
        try:
            self.websock = WebSocketClient(ws_url)
            self.data_queue = self.websock.received_messages
        except Exception as exc:
            logger.error(
                "Error during device initialization : %s", str(exc), exc_info=exc
            )
            raise WCClientException(exc) from exc
        self.wallet_id = str(uuid4())
        self.enc_channel = EncryptedTunnel(symkey)
        self.app_peer_id = None
        self.subscribe(topic)

    def close(self):
        """Close the WebSocket connection when deleting the object."""
        logger.debug("Closing WalletConnect link.")
        self.websock.close()

    @classmethod
    def from_wc_uri(cls, wc_uri_str):
        """Create a WalletConnect client from wc URI"""
        found = WCClient.wc_uri_pattern.findall(wc_uri_str)
        if not found:
            raise WCClientInvalidOption("Bad wc URI provided\nMust be : wc:xxxx...")
        wc_data = found[0]
        if len(wc_data) != 4:
            raise WCClientInvalidOption("Bad data received in URI")
        handshake_topic = wc_data[0]
        wc_ver = wc_data[1]
        bridge_url = unquote(wc_data[2])
        if len(wc_data[3]) % 2 != 0 or len(wc_data[3]) // 2 != WC_AES_KEY_SIZE:
            raise WCClientInvalidOption("Bad key data format in URI")
        sym_key = bytes.fromhex(wc_data[3])
        if wc_ver != "1":
            raise WCClientInvalidOption("Bad WalletConnect version. Only supports v1.")
        logger.debug(
            "wc URI provided decoded successfully, "
            "now starting the WalletConnect client"
        )
        return cls(bridge_url, handshake_topic, sym_key)

    def get_relay_url(self):
        """Give the URL of the WebSocket relay bridge."""
        return self.relay_url

    def reconnect(self):
        """Reconnect to relay host when disconnected"""
        # Internal use, needs websock deleted (None)
        try:
            self.websock = WebSocketClient(self.relay_url)
            self.data_queue = self.websock.received_messages
        except Exception as exc:
            logger.error("Error during reconnection : %s", str(exc), exc_info=exc)
            raise WCClientException(exc) from exc
        self.subscribe(self.wallet_id)
        logger.debug("WebSocket reconnected")

    def write(self, data_dict):
        """Send a data_object to the WalletConnect relay.
        Usually : { topic: 'xxxx', type: 'pub/sub', payload: 'xxxx' }
        """
        # Wait asynchronously for reconnection
        # Be sure to call get_data/get_message periodically to trigger auto-reconnect
        if not hasattr(self.websock, "ssocket"):
            # Will call itself after 250 ms
            timer_newwrite = Timer(0.25, self.write, [data_dict])
            timer_newwrite.daemon = True
            timer_newwrite.start()
            return
        raw_data = json_encode(data_dict)
        logger.debug("WalletConnect message sending to relay : %s", raw_data)
        self.websock.write_message(raw_data)

    def get_data(self):
        """Read the first data available in the receive queue messages.
        Non-blocking, so return None if no data has been received.
        """
        # Check if socket was disconnected
        if not hasattr(self.websock, "ssocket"):
            logger.debug("Reconnecting WebSocket")
            self.reconnect()
        logger.debug("Get Data, full messages queue : %s", str(self.data_queue))
        if len(self.data_queue) > 0:
            rcvd_message = self.data_queue.pop()
            logger.debug("A message pop from the queue : %s", rcvd_message)
            if rcvd_message and rcvd_message.startswith('{"'):
                request_received = self.enc_channel.decrypt_payload(loads(rcvd_message))
                logger.debug("Request message decrypted : %s", request_received)
                return request_received
        return None

    def get_message(self):
        """
        Like get data but filter the messages and fully decode them.
        Return : (id, method, params) or (None, "", [])
        Use like a pump : call get_message() until empty response,
        because it reads a message from the receiving bucket.
        Non-blocking, so returns (None, "", []) if no data has been received.
        """
        rcvd_data = self.get_data()
        if rcvd_data and isinstance(rcvd_data, bytes) and rcvd_data.startswith(b'{"'):
            # return (id, method, params)
            msg_ready = json_rpc_unpack(rcvd_data)
            logger.debug("Get data, WalletConnect message available : %s", msg_ready)
        else:
            msg_ready = (None, "", [])
        return msg_ready

    def reply(self, req_id, result):
        """Send a RPC response to the webapp through the relay."""
        payload_bin = json_rpc_pack_response(req_id, result)
        datafull = {
            "topic": self.app_peer_id,
            "type": "pub",
            "payload": json_encode(self.enc_channel.encrypt_payload(payload_bin)),
        }
        logger.debug(
            "--> WalletConnect Replying id[%i] : result=%s\nRaw message: %s",
            req_id,
            result,
            payload_bin,
        )
        self.write(datafull)

    def subscribe(self, peer_uuid):
        """Start listening to a given peer."""
        logger.debug("Sending a subscription request for %s.", peer_uuid)
        data = {"topic": peer_uuid, "type": "sub", "payload": ""}
        self.write(data)

    def open_session(self):
        """Start a WalletConnect session : read session request message.
        Return : (message RPC ID, chain ID, peerMeta data object).
        Or throw WalletConnectClientException("sessionRequest timeout")
        after GLOBAL_TIMEOUT seconds.
        """
        self.subscribe(self.wallet_id)

        # Waiting for sessionRequest
        logger.debug("Waiting for WalletConnect sessionRequest.")
        cyclew = 0
        while cyclew < CYCLES_TIMEOUT:
            sleep(UNIT_WAITING_TIME)
            read_data = self.get_data()
            if read_data:
                logger.debug("<-- WalletConnect message read : %s", read_data)
                msg_id, method, query_params = json_rpc_unpack(read_data)
                logger.debug(
                    "RPC Call id=%i : method=%s params=%s", msg_id, method, query_params
                )
                if method == "wc_sessionRequest":
                    break
            cyclew += 1
        if cyclew == CYCLES_TIMEOUT:
            self.close()
            raise WCClientException("sessionRequest timeout")

        logger.debug(" -- Session Request received : %s", query_params[0])
        self.app_peer_id = query_params[0]["peerId"]
        app_chain_id = query_params[0]["chainId"]
        return msg_id, app_chain_id, query_params[0]["peerMeta"]

    def reply_session_request(self, msg_id, chain_id, account_address):
        """Send the sessionRequest result."""
        session_request_result = {
            "peerId": self.wallet_id,
            "peerMeta": wallet_metadata,
            "approved": True,
            "chainId": chain_id,
            "accounts": [account_address],
        }
        logger.debug("Replying the sessionRequest.")
        self.reply(msg_id, session_request_result)
