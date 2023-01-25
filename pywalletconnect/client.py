# -*- coding: utf8 -*-

# pyWalletConnect : WalletConnect wallet client
# Copyright (C) 2021-2023 BitLogiK

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


from logging import getLogger
from re import compile as regex_compile
from threading import Timer
from time import sleep, time

from .websocket import WebSocketClient
from .json_rpc import (
    json_encode,
    rpc_query,
)
from .version import VERSION

# ---- WalletConnect settings


logger = getLogger(__name__)


class WCClientException(Exception):
    """Exception from the WalletConnect client."""


class WCClientInvalidOption(Exception):
    """Exception from the WebSocket client when decoding URI input."""


class WCClient:
    """WalletConnect wallet v1 and v2 base client."""

    wc_uri_pattern = regex_compile(r"^wc:(.+)@(\d)\?(.+)$")
    project_id = ""
    origin_domain = ""
    wallet_metadata = {
        "description": f"pyWalletConnect v{VERSION} by BitLogiK",
        "url": "https://github.com/bitlogik/pyWalletConnect",
        "icons": [
            "https://raw.githubusercontent.com/bitlogik/pyWalletConnect/master/logo.png"
        ],
        "name": "pyWalletConnect",
    }

    def __init__(self):
        self.relay_url = ""
        self.wallet_id = ""
        self.app_peer_id = None
        self.enc_channel = None
        self.websock = None
        self.data_queue = None

    def __del__(self):
        """Dying gasp and clean close"""
        self.close()

    @classmethod
    def set_wallet_metadata(cls, wallet_metadata):
        """Can override the default wallet metadata."""
        cls.wallet_metadata = wallet_metadata

    @classmethod
    def set_project_id(cls, project_id):
        """Set the project id, mandatory for v2, using the central official relay."""
        cls.project_id = project_id

    @classmethod
    def set_origin(cls, origin):
        """Set the Oring header in WS start request."""
        cls.origin_domain = origin

    def close(self):
        """Close the WebSocket connection when deleting the object."""
        logger.debug("Closing WalletConnect link.")
        if isinstance(self, WCv1Client):
            # Auto disconnect if v1 and still connected
            if hasattr(self.websock, "ssocket") and self.app_peer_id is not None:
                logger.debug("WCv1 session close automatic message.")
                close_param = {"approved": False, "chainId": 0, "accounts": []}
                close_msg = rpc_query("wc_sessionUpdate", [close_param])
                close_msg["id"] = int(time() * 100)
                payload_bin = json_encode(close_msg).encode("utf8")
                payload_enc = self.enc_channel.encrypt_payload(payload_bin)
                datafull = {
                    "topic": self.app_peer_id,
                    "type": "pub",
                    "payload": json_encode(payload_enc),
                }
                logger.debug("Sending a WCv1 close message.")
                self.write(datafull)
                sleep(0.15)
                logger.debug("WCv1 close message sent.")
        if isinstance(self, WCv2Client) and self.wallet_id:

            try:
                sess_delete = rpc_query(
                    "wc_sessionDelete", {"code": 6000, "message": "User disconnected"}
                )
                msgsessdel = self.topics[self.wallet_id][
                    "secure_channel"
                ].encrypt_payload(json_encode(sess_delete))
                logger.debug("Delete session message.")
                self.publish(self.wallet_id, msgsessdel, "Session deletion")
            except Exception:
                pass

            self.wallet_id = ""

        if self.websock is not None:
            self.websock.close()

    @classmethod
    def from_wc_uri(cls, wc_uri_str):
        """Create a WalletConnect client from wc URI"""
        if not isinstance(wc_uri_str, str):
            raise ValueError("wc_data must be string.")
        found = WCClient.wc_uri_pattern.findall(wc_uri_str)
        if not found:
            raise WCClientInvalidOption("Bad wc URI provided\nMust be : wc:xxxx...")
        if wc_uri_str.find("@1?") >= 0:
            # v1
            return WCv1Client.from_wc1_data(found[0])
        if wc_uri_str.find("@2?") >= 0:
            # Is it a V2 ?
            if wc_uri_str.find("publicKey=") >= 0:
                # v2 early waku
                return WCv2ClientLegacy.from_wc2_uri(wc_uri_str)
            if wc_uri_str.find("symKey=") >= 0:
                # latest v2 irn
                return WCv2Client.from_wc2_uri(wc_uri_str)
        raise WCClientInvalidOption(
            "Only WalletConnect v1 and v2 are supported for now"
        )

    def get_relay_url(self):
        """Give the URL of the WebSocket relay bridge."""
        return self.relay_url.split("?")[0]

    def reconnect(self):
        """Reconnect to relay host when disconnected"""
        # Internal use, needs websock deleted (None)
        try:
            self.websock = WebSocketClient(self.relay_url, self.origin_domain)
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


from .client_v1 import WCv1Client
from .client_v2waku import WCv2ClientLegacy
from .client_v2irn import WCv2Client
