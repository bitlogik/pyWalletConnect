from urllib.parse import parse_qs
from json import loads
from logging import getLogger
from time import sleep
from uuid import uuid4

from .websocket import WebSocketClient, CYCLES_TIMEOUT, UNIT_WAITING_TIME
from .enc_tunnel import (
    EncryptedTunnel,
)
from .json_rpc import (
    json_encode,
    json_rpc_pack_response,
    json_rpc_unpack,
)

from .client import WCClient, WCClientException, WCClientInvalidOption

logger = getLogger(__name__)


WC_AES_KEY_SIZE = 32  # WCv1 uses 256 bits AES key


class WCv1Client(WCClient):
    """WalletConnect v1 wallet client connected to a relay with WebSocket."""

    def __init__(self, ws_url, topic, symkey):
        """Create a WalletConnect client from parameters.
        Call open_session immediately after to get the session request info.
        """
        # Chain ID is managed outside the walletconnect classes
        # Shall be managed by the user / webapp
        super().__init__()
        logger.debug("Opening a WalletConnect v1 client with %s", ws_url)
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
        if not self.data_queue.empty():
            rcvd_message = self.data_queue.get()
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
        if not isinstance(chain_id, int):
            raise ValueError("chain_id argument must be integer.")
        if not isinstance(account_address, str):
            raise ValueError("account_address argument must be string.")
        session_request_result = {
            "peerId": self.wallet_id,
            "peerMeta": self.wallet_metadata,
            "approved": True,
            "chainId": chain_id,
            "accounts": [account_address],
        }
        logger.debug("Approving the sessionRequest.")
        self.reply(msg_id, session_request_result)
