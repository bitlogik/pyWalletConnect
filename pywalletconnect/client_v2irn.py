from urllib.parse import urlparse, parse_qs
from logging import getLogger
from time import sleep, time

from .websocket import WebSocketClient, CYCLES_TIMEOUT, UNIT_WAITING_TIME
from .enc_tunnel import (
    EncryptedEnvelope,
    KeyAgreement,
)
from .json_rpc import (
    json_encode,
    json_rpc_pack_response,
    json_rpc_unpack,
    rpc_query,
    json_rpc_unpack_response,
)
from .ws_auth import gen_ws_auth

from .client import WCClient, WCClientException, WCClientInvalidOption


logger = getLogger(__name__)


class WCv2Client(WCClient):
    """WalletConnectv2 wallet client connected to a central relay with WebSocket."""

    host_relay = "relay.walletconnect.com"

    def __init__(self, ws_url, topic, symkey):
        """Create a WalletConnect v2 client from parameters.
        Call open_session immediately after to get the session request info.
        """
        # Chain ID is managed outside the walletconnect classes
        # Shall be managed by the user / webapp
        super().__init__()
        logger.debug("Opening a WalletConnect v2 client with %s", ws_url)
        self.relay_url = ws_url
        try:
            self.websock = WebSocketClient(ws_url, self.origin_domain)
            self.data_queue = self.websock.received_messages
        except Exception as exc:
            logger.error(
                "Error during device initialization : %s", str(exc), exc_info=exc
            )
            raise WCClientException(exc) from exc
        logger.debug("wc v2 URI and project id accepted")
        # Key for Pairing
        self.local_keypair = None
        self.peer_pubkey = None
        self.proposal_topic = topic
        # Keep track of subcriptions and key for topics
        # has "subscription_id" and "secure_channel" keys
        self.topics = {topic: {"secure_channel": EncryptedEnvelope(symkey)}}

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
        if query_string.get("symKey") is None or len(query_string["symKey"]) == 0:
            raise WCClientInvalidOption("symkey not found in wc v2 URI")
        sym_key_hex = query_string["symKey"][0]
        if len(sym_key_hex) != 64:
            raise WCClientInvalidOption("Invalid symkey in wc v2 URI")
        try:
            int(sym_key_hex, 16)
        except ValueError as exc:
            raise WCClientInvalidOption("Invalid hex symkey in wc v2 URI") from exc
        logger.debug(
            "wc v2 URI provided decoded successfully, "
            "now starting the WalletConnect client"
        )
        if not cls.project_id:
            raise WCClientInvalidOption(
                "v2 walletConnect must been set up with WCClient.set_project_id(id)"
            )
        wsurl = (
            f"https://{cls.host_relay}/?auth={gen_ws_auth()}&projectId={cls.project_id}&ua=wc-2/python-1/desktop/pyWalletConnect"
            f""
        )
        return cls(wsurl, handshake_topic, bytes.fromhex(sym_key_hex))

    def get_json_response(self):
        """Read the first data object available in the receive queue messages.
        Non-blocking, so return None if no data has been received.
        """
        # Check if socket was disconnected
        if not hasattr(self.websock, "ssocket"):
            logger.debug("Reconnecting WebSocket")
            self.reconnect()
        if not self.data_queue.empty():
            rcvd_message = self.data_queue.get()
            logger.debug("A JSON message in the queue : %s", rcvd_message)
            if rcvd_message and rcvd_message.startswith('{"'):
                try:
                    request_received = json_rpc_unpack_response(rcvd_message)
                    logger.debug("Result JSON response received : %s", request_received)
                    return request_received
                except Exception:
                    # Not a response message, reinsert in queue
                    self.data_queue.put(rcvd_message)
        return None

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
                msg_sub = json_rpc_unpack(rcvd_message)
                if msg_sub[1] == "irn_subscription":
                    # Filter if we are actually subscribed to this topic
                    if msg_sub[2]["data"]["topic"] in self.topics.keys():
                        request_received = self.topics[msg_sub[2]["data"]["topic"]][
                            "secure_channel"
                        ].decrypt_payload(msg_sub[2]["data"]["message"])
                        logger.debug(
                            "Request message decrypted from topic %s : %s",
                            msg_sub[2]["data"]["topic"],
                            request_received,
                        )

                        # send back ack
                        payload_bin = json_rpc_pack_response(msg_sub[0], True)
                        logger.debug("Sending result reply.")
                        self.websock.write_message(payload_bin)
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
                self._reply(self.wallet_id, req[0], True)
                return (req[0], "", [])
            return req
        return (None, "", [])

    def wait_for_response(self, resp_type):
        """Wait for a JSON-RPC response."""
        # Waiting for query ack (publish, subscribe, unsubscribe)
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
        """Send a RPC response to the current topic to the webapp through the relay."""
        self._reply(self.wallet_id, req_id, result)

    def _reply(self, topic, req_id, result):
        """Send a RPC response to the webapp through the relay."""
        payload_bin = json_rpc_pack_response(req_id, result)
        msgbp = self.topics[topic]["secure_channel"].encrypt_payload(payload_bin, None)
        logger.debug("Sending result reply.")
        self.publish(topic, msgbp, "Sending result")

    def subscribe(self, topic_id):
        """Start listening to a given topic."""
        logger.debug("Sending a subscription request for %s.", topic_id)
        data = rpc_query("irn_subscribe", {"topic": topic_id})
        self.write(data)
        subscription_id = self.wait_for_response("Topic subcription")
        # Need to have already the secure_channel setup for this topic
        self.topics[topic_id]["subscription_id"] = subscription_id

    def unsubscribe(self, topic_id):
        """Stop listening to a given topic."""
        logger.debug("Sending an unsubscribe request for %s.", topic_id)
        data = rpc_query(
            "irn_unsubscribe",
            {"topic": topic_id, "id": self.topics[topic_id]["subscription_id"]},
        )
        self.write(data)
        self.wait_for_response("Topic leaving")
        del self.topics[topic_id]

    def publish(self, topic, message, log_msg=""):
        """Send a message into a topic id channel."""
        logger.debug("Sending a publish request for %s.", topic)
        data = rpc_query(
            "irn_publish", {"topic": topic, "message": message, "ttl": 86400}
        )
        self.write(data)
        self.wait_for_response(log_msg)

    def open_session(self):
        """Start a WalletConnect session : read session proposal message.
        Not the session approval, but a warmup for the WalletConnect link.
        Return : (message RPC ID, chain ID, peerMeta data object).
        Or throw WalletConnectClientException("sessionRequest timeout")
        after GLOBAL_TIMEOUT seconds.
        """
        self.subscribe(self.proposal_topic)

        logger.debug("Waiting for WalletConnect session proposal.")
        cyclew = 0
        while cyclew < CYCLES_TIMEOUT:
            sleep(UNIT_WAITING_TIME)
            read_data = self.get_message()
            if read_data[0] is not None:
                logger.debug("<-- WalletConnect message read : %s", read_data)
                logger.debug("RPC result=%s", read_data)
                if read_data[1] == "wc_sessionPropose":
                    logger.debug("Session proposal payload received")
                    if read_data[2]["relays"][0]["protocol"] != "irn":
                        raise WCClientException(
                            "Session propose incompatible protocol."
                        )
                    self.peer_pubkey = read_data[2]["proposer"]["publicKey"]
                    if read_data[2]["requiredNamespaces"].get("eip155") is None:
                        raise WCClientException(
                            "Only compatible with EIP155 namespaces."
                        )
                    self.proposed_methods = read_data[2]["requiredNamespaces"][
                        "eip155"
                    ]["methods"]
                    self.proposed_events = read_data[2]["requiredNamespaces"]["eip155"][
                        "events"
                    ]
                    peer_meta = read_data[2]["proposer"]["metadata"]
                    chain_id = read_data[2]["requiredNamespaces"]["eip155"]["chains"][
                        0
                    ].split(":")[-1]
                    logger.debug("OK continue : Session proposal payload received")
                    break
            cyclew += 1
        if cyclew == CYCLES_TIMEOUT:
            self.close()
            raise WCClientException("No session proposal received.")

        return read_data[0], chain_id, peer_meta

    def reject_session_request(self, msg_id):
        """Send the sessionRequest rejection."""

        respo_neg = json_rpc_pack_response(
            msg_id,
            {
                "error": {"code": 5000, "message": "User rejected the session."},
            },
        )
        msgbn = self.topics[self.proposal_topic]["secure_channel"].encrypt_payload(
            respo_neg, None
        )
        logger.debug("Replying the session rejection.")
        self.publish(self.proposal_topic, msgbn, "Session rejection")

    def reply_session_request(self, msg_id, chain_id, account_address):
        """Send the sessionRequest approval."""

        # Pairing Keys
        self.local_keypair = KeyAgreement()
        pubkey = self.local_keypair.get_pubkey()
        self.local_keypair.compute_shared_key(self.peer_pubkey)
        # Derive further the derived key with HKDF
        self.local_keypair.hkdf_derive_enc_key()
        chat_topic = self.local_keypair.derive_topic()

        # Current topic for reconnect method and session unsub
        self.wallet_id = self.proposal_topic
        self._reply(
            self.proposal_topic,
            msg_id,
            {
                "relay": {
                    "protocol": "irn",
                },
                "responderPublicKey": pubkey.hex(),
            },
        )

        # Unsubscribe the old propose pairing topic
        # self.unsubscribe(self.proposal_topic)

        self.wallet_id = chat_topic

        now_epoch = int(time())
        respo = rpc_query(
            "wc_sessionSettle",
            {
                "relay": {
                    "protocol": "irn",
                },
                "controller": {
                    "publicKey": pubkey.hex(),
                    "metadata": self.wallet_metadata,
                },
                "namespaces": {
                    "eip155": {
                        "accounts": [f"eip155:{chain_id}:{account_address}"],
                        "methods": self.proposed_methods,
                        "events": self.proposed_events,
                    }
                },
                "expiry": now_epoch + 14400,
            },
        )

        chat_enc_channel = EncryptedEnvelope(self.local_keypair.shared_key)
        self.topics[chat_topic] = {"secure_channel": chat_enc_channel}
        msgb = chat_enc_channel.encrypt_payload(json_encode(respo))
        logger.debug("Approving the session proposal.")

        self.subscribe(chat_topic)

        logger.debug("Waiting for session on new topic.")
        cyclew = 0
        while cyclew < CYCLES_TIMEOUT:
            sleep(UNIT_WAITING_TIME)
            read_data = self.get_data()
            if read_data:
                logger.debug("<-- WalletConnect response read : %s", read_data)
                break
            cyclew += 1
        if cyclew == CYCLES_TIMEOUT:
            self.close()
            raise WCClientException("session ack timeout")

        # Finally send the session approve
        self.publish(self.wallet_id, msgb, "sessionSettle post")

        logger.debug("Waiting for sessionSettle post ack.")
        cyclew = 0
        while cyclew < CYCLES_TIMEOUT:
            sleep(UNIT_WAITING_TIME)
            read_data = self.get_data()
            if read_data:
                logger.debug("<-- WalletConnect response read : %s", read_data)
                break
            cyclew += 1
        if cyclew == CYCLES_TIMEOUT:
            self.close()
            raise WCClientException("sessionSettle post ack timeout")
