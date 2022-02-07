# -*- coding: utf8 -*-

# pyWalletConnect : WalletConnect wallet client
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


"""WalletConnect wallet client for pyWalletConnect"""


from urllib.parse import urlparse, parse_qs
from json import loads
from logging import getLogger
from re import compile as regex_compile
from threading import Timer
from time import sleep, time
from uuid import uuid4

from .websocket import WebSocketClient, CYCLES_TIMEOUT, UNIT_WAITING_TIME
from .enc_tunnel import EncryptedTunnel, EncryptedTunnelv2, KeyAgreement
from .json_rpc import (
    json_encode,
    json_rpc_pack_response,
    json_rpc_unpack,
    rpc_query,
    json_rpc_unpack_response,
)
from .version import VERSION

# ---- WalletConnect settings


WC_AES_KEY_SIZE = 32  # WCv1 uses 256 bits AES key

logger = getLogger(__name__)


class WCClientException(Exception):
    """Exception from the WalletConnect client."""


class WCClientInvalidOption(Exception):
    """Exception from the WebSocket client when decoding URI input."""


class WCClient:
    """WalletConnect wallet v1 and v2 base client."""

    wc_uri_pattern = regex_compile(r"^wc:(.+)@(\d)\?(.+)$")
    project_id = ""
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
        """Set the project id, mandatory for v2, using the waku official relay."""
        cls.project_id = project_id

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
        self.websock.close()

    @classmethod
    def from_wc_uri(cls, wc_uri_str):
        """Create a WalletConnect client from wc URI"""
        found = WCClient.wc_uri_pattern.findall(wc_uri_str)
        if not found:
            raise WCClientInvalidOption("Bad wc URI provided\nMust be : wc:xxxx...")
        if wc_uri_str.find("@1?") >= 0:
            # v1
            return WCv1Client.from_wc1_data(found[0])
        if wc_uri_str.find("@2?") >= 0:
            # Is it a V2 ?
            return WCv2Client.from_wc2_uri(wc_uri_str)
        raise WCClientInvalidOption(
            "Only WalletConnect v1 and v2 are supported for now"
        )

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

    def subscribe(self, topic_id):
        """Abstract class for topic subscribe."""
        raise NotImplementedError


class WCv1Client(WCClient):
    """WalletConnect v1 wallet client connected to a relay with WebSocket."""

    def __init__(self, ws_url, topic, symkey):
        """Create a WalletConnect client from parameters.
        Call open_session immediately after to get the session request info.
        """
        # Chain ID is managed outside the walletconnect classes
        # Shall be managed by the user / webapp
        super().__init__()
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

    @classmethod
    def from_wc1_data(cls, wc_data):
        """Create a WalletConnect client from wc v1 URI"""
        if len(wc_data) != 3:
            raise WCClientInvalidOption("Bad data received in URI WC v1")
        handshake_topic = wc_data[0]
        wc_ver = wc_data[1]
        query_string = parse_qs(wc_data[2])
        if query_string.get("bridge") is None:
            raise WCClientInvalidOption("No bridge option in URI")
        bridge_url = query_string["bridge"][0]
        if query_string.get("key") is None:
            raise WCClientInvalidOption("No key option in URI")
        symkey_hex = query_string["key"][0]
        if len(symkey_hex) % 2 != 0 or len(symkey_hex) // 2 != WC_AES_KEY_SIZE:
            raise WCClientInvalidOption("Bad key data format in URI")
        try:
            sym_key = bytes.fromhex(symkey_hex)
        except ValueError as exc:
            raise WCClientInvalidOption("Bad hex key data format in URI") from exc
        if wc_ver != "1":
            raise WCClientInvalidOption("Bad WalletConnect version. Only supports v1.")
        logger.debug(
            "wc URI provided decoded successfully, "
            "now starting the WalletConnect client"
        )
        return cls(bridge_url, handshake_topic, sym_key)

    def get_data(self):
        """Read the first data available in the receive queue messages.
        Non-blocking, so return None if no data has been received.
        """
        # Check if socket was disconnected
        if not hasattr(self.websock, "ssocket"):
            logger.debug("Reconnecting WebSocket")
            self.reconnect()
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

    def subscribe(self, topic_id):
        """Start listening to a given peer."""
        logger.debug("Sending a subscription request for %s.", topic_id)
        data = {"topic": topic_id, "type": "sub", "payload": ""}
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

    def reject_session_request(self, msg_id):
        """Send the sessionRequest rejection."""
        session_request_reject = {
            "peerId": self.wallet_id,
            "peerMeta": self.wallet_metadata,
            "approved": False,
        }
        logger.debug("Denying the sessionRequest.")
        self.reply(msg_id, session_request_reject)

    def reply_session_request(self, msg_id, chain_id, account_address):
        """Send the sessionRequest result."""
        session_request_result = {
            "peerId": self.wallet_id,
            "peerMeta": self.wallet_metadata,
            "approved": True,
            "chainId": chain_id,
            "accounts": [account_address],
        }
        logger.debug("Approving the sessionRequest.")
        self.reply(msg_id, session_request_result)


class WCv2Client(WCClient):
    """WalletConnect v2 wallet client connected to a relay with WebSocket."""

    host_relay = "relay.walletconnect.com"

    def __init__(self, ws_url, topic, pubkey):
        """Create a WalletConnect v2 client from parameters.
        Call open_session immediately after to get the session request info.
        """
        # Chain ID is managed outside the walletconnect classes
        # Shall be managed by the user / webapp
        super().__init__()
        logger.debug("Opening a WalletConnect v2 client with %s", ws_url)
        try:
            self.websock = WebSocketClient(ws_url)
            self.data_queue = self.websock.received_messages
        except Exception as exc:
            logger.error(
                "Error during device initialization : %s", str(exc), exc_info=exc
            )
            raise WCClientException(exc) from exc
        logger.debug("wc v2 URI and project id accepted")
        # Key for Pairing
        self.peer_pubkey = pubkey
        self.proposal_topic = topic
        # Keep track of subcriptions topics for each id
        self.subscriptions = {}

    @classmethod
    def from_wc2_uri(cls, wc_uri_str):
        """Create a WalletConnect client from wc v2 URI"""
        logger.debug("URI WC version 2 decoding")
        # wc URI already filtered for v2 if called from WCClient.from_wc_uri
        urla = urlparse(wc_uri_str)
        query_string = parse_qs(urla.query)
        if urla.scheme != "wc":
            raise WCClientInvalidOption("Bad wc URI provided\nMust be : wc:xxxx...")
        if urla.path[-2:] != "@2":
            raise WCClientInvalidOption("Bad v2 data received in URI")
        handshake_topic = urla.path[:-2]
        try:
            int(handshake_topic, 16)
        except ValueError as exc:
            raise WCClientInvalidOption("Invalid hex topic in wc v2 URI") from exc
        if query_string.get("publicKey") is None or len(query_string["publicKey"]) == 0:
            raise WCClientInvalidOption("publickey not found in wc v2 URI")
        pub_key = query_string["publicKey"][0]
        if len(pub_key) != 64:
            raise WCClientInvalidOption("Invalid publickey in wc v2 URI")
        try:
            int(pub_key, 16)
        except ValueError as exc:
            raise WCClientInvalidOption("Invalid hex publickey in wc v2 URI") from exc
        logger.debug(
            "wc v2 URI provided decoded successfully, "
            "now starting the WalletConnect client"
        )
        if not cls.project_id:
            raise WCClientInvalidOption(
                "v2 walletConnect must been set up with WCClient.set_project_id(id)"
            )
        wsurl = (
            f"https://{cls.host_relay}/?env=desktop&projectId={cls.project_id}"
            "&protocol=wc&version=2"
        )
        return cls(wsurl, handshake_topic, pub_key)

    def get_json_response(self):
        """Read the first data object available in the receive queue messages.
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
                try:
                    request_received = json_rpc_unpack_response(rcvd_message)
                    logger.debug("Result received : %s", request_received)
                    return request_received
                except Exception:
                    # if RPC query, re-insert in queue
                    self.data_queue.insert(0, rcvd_message)
        return None

    def get_data(self):
        """Read the first data available in the receive queue messages.
        Non-blocking, so return None if no data has been received.
        """
        # Check if socket was disconnected
        if not hasattr(self.websock, "ssocket"):
            logger.debug("Reconnecting WebSocket")
            self.reconnect()
        if len(self.data_queue) > 0:
            rcvd_message = self.data_queue.pop()
            logger.debug("A message pop from the queue : %s", rcvd_message)
            if rcvd_message and rcvd_message.startswith('{"'):
                msg_sub = json_rpc_unpack(rcvd_message)
                if msg_sub[1] == "waku_subscription":
                    # Filter if we are actually subscribed to this topic
                    if msg_sub[2]["id"] in self.subscriptions.values():
                        request_received = self.enc_channel.decrypt_payload(
                            msg_sub[2]["data"]["message"]
                        )
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
        Return empty method and params for wc_sessionPing, pings are reponded here
        at this level. So filter get_message calls with 'id is None', means no more
        message left.
        """
        rcvd_data = self.get_data()
        if rcvd_data and isinstance(rcvd_data, str) and rcvd_data.startswith('{"'):
            # return (id, method, params)
            logger.debug("Request query decoded : %s", rcvd_data)
            req = json_rpc_unpack(rcvd_data)
            # Auto session ping reply
            if req[1] == "wc_sessionPing":
                self.reply(req[0], True)
                return (req[0], "", [])
            return req
        return (None, "", [])

    def wait_for_response(self, resp_type):
        """Wait for a JSON-RPC response."""
        # Waiting for publish ack
        logger.debug("Waiting for %s ack.", resp_type)
        cyclew = 0
        while cyclew < CYCLES_TIMEOUT:
            sleep(UNIT_WAITING_TIME)
            read_data = self.get_json_response()
            if read_data:
                logger.debug("<-- WalletConnect response read : %s", read_data)
                return read_data
            cyclew += 1
        if cyclew == CYCLES_TIMEOUT:
            self.close()
            raise WCClientException(f"{resp_type} timeout")

    def reply(self, req_id, result):
        """Send a RPC response to the webapp through the relay."""
        payload_bin = json_rpc_pack_response(req_id, result)
        msgbp = self.enc_channel.encrypt_payload(payload_bin, None)
        logger.debug("Sending result reply.")
        self.publish(self.wallet_id, msgbp, "Sending result")

    def subscribe(self, topic_id):
        """Start listening to a given topic."""
        logger.debug("Sending a subscription request for %s.", topic_id)
        data = rpc_query("waku_subscribe", {"topic": topic_id})
        self.write(data)
        subscription_id = self.wait_for_response("Topic subcription")
        self.subscriptions[topic_id] = subscription_id

    def unsubscribe(self, topic_id):
        """Stop listening to a given topic."""
        logger.debug("Sending an unsubscribe request for %s.", topic_id)
        data = rpc_query(
            "waku_unsubscribe", {"topic": topic_id, "id": self.subscriptions[topic_id]}
        )
        self.write(data)
        self.wait_for_response("Topic leaving")
        del self.subscriptions[topic_id]

    def publish(self, topic, message, log_msg=""):
        """Send a message into a topic id channel."""
        logger.debug("Sending a publish request for %s.", topic)
        data = rpc_query(
            "waku_publish", {"topic": topic, "message": message, "ttl": 86400}
        )
        self.write(data)
        self.wait_for_response(log_msg)

    def open_session(self):
        """Start a WalletConnect session : read session request message.
        Return : (message RPC ID, chain ID, peerMeta data object).
        Or throw WalletConnectClientException("sessionRequest timeout")
        after GLOBAL_TIMEOUT seconds.
        """
        # Pairing Keys
        keyassym = KeyAgreement()
        pubkey = keyassym.get_pubkey()
        keyassym.compute_shared_key(self.peer_pubkey)
        chat_topic = keyassym.derive_topic()
        keys = keyassym.derive_enc_key()
        self.enc_channel = EncryptedTunnelv2(pubkey, keys[0], keys[1])
        # Current topic for reconnect method and session unsub
        self.wallet_id = chat_topic
        self.subscribe(chat_topic)
        now_epoch = int(time())
        respo = rpc_query(
            "wc_pairingApprove",
            {
                "relay": {"protocol": "waku"},
                "responder": {"publicKey": pubkey.hex()},
                "expiry": now_epoch + 14400,
                "state": {"metadata": self.wallet_metadata},
            },
        )
        msgb = json_encode(respo).encode("utf8").hex()
        self.publish(self.proposal_topic, msgb, "Pairing Approve")

        # Waiting for settlement
        logger.debug("Waiting for WalletConnect settlement.")
        cyclew = 0
        while cyclew < CYCLES_TIMEOUT:
            sleep(UNIT_WAITING_TIME)
            read_data = self.get_message()
            if read_data[0] is not None:
                logger.debug("<-- WalletConnect message read : %s", read_data)
                logger.debug("RPC result=%s", read_data)
                if read_data[1] == "wc_pairingPayload":
                    logger.debug("pairing payload received")
                    if read_data[2]["request"]["method"] == "wc_sessionPropose":
                        logger.debug("session propose received")
                        iparams = read_data[2]["request"]["params"]
                        if (
                            iparams["signal"]["method"] == "pairing"
                            and iparams["signal"]["params"]["topic"] == chat_topic
                        ):
                            logger.debug("chat topic checked")
                            self.peer_pubkey = iparams["proposer"]["publicKey"]
                            pairing_rpc_id = iparams["topic"]
                            peer_meta = iparams["proposer"]["metadata"]
                            chain_id = iparams["permissions"]["blockchain"]["chains"]
                break
            cyclew += 1
        if cyclew == CYCLES_TIMEOUT:
            self.close()
            raise WCClientException("settlement timeout")

        return pairing_rpc_id, chain_id, peer_meta

    def reject_session_request(self, msg_id):
        """Send the sessionRequest rejection."""
        # msg_id is the topic id
        respo_neg = rpc_query(
            "wc_sessionReject",
            {
                "reason": {"code": 1601, "message": "User rejected the session."},
            },
        )
        msgbn = self.enc_channel.encrypt_payload(json_encode(respo_neg))
        logger.debug("Replying the session rejection.")
        self.publish(msg_id, msgbn, "Session rejection")
        # Should be published on an old topic ?
        pair_delete = rpc_query(
            "wc_pairingDelete",
            {
                "reason": {"code": 1605, "message": "Pairing deleted"},
            },
        )
        msgbp = self.enc_channel.encrypt_payload(json_encode(pair_delete))
        logger.debug("Sending pairing deletion.")
        self.publish(msg_id, msgbp, "Pairing deletion")

    def reply_session_request(self, msg_id, chain_id, account_address):
        """Send the sessionRequest approval."""
        # msg_id is the topic id

        # New session key
        keyassym = KeyAgreement()
        pubkey = keyassym.get_pubkey()

        now_epoch = int(time())
        respo = rpc_query(
            "wc_sessionApprove",
            {
                "relay": {"protocol": "waku"},
                "responder": {
                    "publicKey": pubkey.hex(),
                    "metadata": self.wallet_metadata,
                },
                "expiry": now_epoch + 14400,
                "state": {"accounts": [f"eip155:{chain_id}:{account_address}"]},
            },
        )
        msgb = self.enc_channel.encrypt_payload(json_encode(respo))
        logger.debug("Approving the session proposal.")

        # Recompute keys and topic for the session
        keyassym.compute_shared_key(self.peer_pubkey)
        session_topic = keyassym.derive_topic()
        keys = keyassym.derive_enc_key()

        # Unsubscribe the old propose pairing topic
        self.unsubscribe(self.wallet_id)
        # For reconnect method
        self.wallet_id = session_topic

        # Enforce new keys
        self.enc_channel = EncryptedTunnelv2(pubkey, keys[0], keys[1])

        # Subscribe to the session topic
        self.subscribe(session_topic)

        # Finally send the session approve
        self.publish(msg_id, msgb, "Session approval")
