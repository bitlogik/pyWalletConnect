
# pyWalletConnect

![pyWalletConnect logo](logo.png)

### A WalletConnect implementation for wallets in Python

A Python3 library to link a wallet with a WalletConnect web3 app. This library connects a Python wallet with a web3 app online, using the WalletConnect standard.

Thanks to WalletConnect, a Dapp is able to send JSON-RPC call requests to be handled by the wallet, remotely signing transactions or messages. Using WalletConnect, the wallet is a JSON-RPC service that the dapp can query through an encrypted tunnel and an online relay. This library is built for the wallet part, which establishes a link with the dapp and receives requests.

pyWalletConnect manages automatically on its own all the WalletConnect stack :

```
WalletConnect
    |
Topics mgmt
    |
 JSON-RPC
    |
EncryptedTunnel
    |
 WebSocket
    |
   HTTP
    |
   TLS
    |
  Socket
```

## Installation and requirements

Works with Python >= 3.7.

### Installation of this library

Easiest way :  
`python3 -m pip install pyWalletConnect`  

From sources, download and run in this directory :  
`python3 -m pip  install .`

### Use

Instanciate with `pywalletconnect.WCClient.from_wc_uri`, then use methods functions of this object.

Basic example :

```python
from pywalletconnect import WCClient, WCClientInvalidOption
# Input the wc URI
string_uri = input("Input the WalletConnect URI : ")
WCClient.set_wallet_metadata(WALLET_METADATA)  # Optional, else identify pyWalletConnect as wallet
WCClient.set_project_id(WALLETCONNECT_PROJECT_ID)  # Required for v2
WCClient.set_origin(WALLETCONNECT_ORIGIN_DOMAIN)  # Optional for v2
try:
    wallet_dapp = WCClient.from_wc_uri(string_uri)
except WCClientInvalidOption as exc:
    # In case error in the wc URI provided
    if hasattr(wallet_dapp, "wc_client"):
        wallet_dapp.close()
    raise InvalidOption(exc)
# Wait for the sessionRequest info
# Can throw WCClientException "sessionRequest timeout"
req_id, req_chain_id, request_info = wallet_dapp.open_session()
if req_chain_id != account.chainID:
    # Chain id mismatch
    wallet_dapp.close()
    raise InvalidOption("Chain ID from Dapp is not the same as the wallet.")
# Display to the user request details provided by the Dapp.
user_ok = input(f"WalletConnect link request from : {request_info['name']}. Approve? [y/N]")
if user_ok.lower() == "y":
    # User approved
    wallet_dapp.reply_session_request(req_id, account.chainID, account.address)
    # Now the session with the Dapp is opened
    <...>
else:
    # User rejected
    wclient.reject_session_request(req_id)
    wallet_dapp.close()
    raise UserInteration("user rejected the dapp connection request.")
```

There's a basic minimal working CLI demo at: https://gist.github.com/bitlogik/89b41bb60443c041704f82bcd9b43901

pyWalletConnect maintains a TLS WebSocket opened with the host relay. It builds an internal pool of received request messages from the dapp.

Once the session is opened, you can read the pending messages received from the Dapp from time to time. And then your wallet app can process these requests, and send back the reply.

Use a daemon thread timer for example, to call the `get_message()` method in a short time frequency. 3-6 seconds is an acceptable delay. This can also be performed in a blocking *for* loop with a sleeping time. Then process the Dapp queries for further user wallet actions.

Remember to keep track of the request id, as it is needed for `.reply(req_id, result)` ultimately when sending the processing result back to the dapp service. One way is to provide the id in argument in your processing methods. Also this can be done with global or shared parameters.

When a WCClient object (created from a WC link) is closed or deleted, it will automatically send to the dapp a closing session message.

```python

def process_sendtransaction(call_id, tx):
    # Processing the RPC query eth_sendTransaction
    # Collect the user approval about the tx query
    < Accept (tx) ? >
    if approved :
        # Build and sign the provided transaction
        <...>
        # Broadcast the tx
        # Provide the transaction id as result
        return "0x..." # Tx id

def watch_messages():
    # Watch for messages received.
    # For WalletConnect calls reading.
    # Read all the message requests received from the dapp.
    # Then dispatch to the wallet service handlers.
    # get_message gives (id, method, params) or (None, "", [])
    wc_message = wallet_dapp.get_message()
    # Loop in the waiting messages pool, until depleted
    while wc_message[0] is not None:
        # Read a WalletConnect call message available
        id_request = wc_message[0]
        method = wc_message[1]
        parameters = wc_message[2]
        if method == "wc_sessionRequest" or method == "wc_sessionPayload":
            # Read if v2 and convert to v1 format
            if parameters.get("request"):
                method = parameters["request"].get("method")
                parameters = parameters["request"].get("params")
        if "wc_sessionUpdate" == method:
            if parameters[0].get("approved") is False:
                raise Exception("Disconnected by the Dapp.")
        #  v2 disconnect
        if "wc_sessionDelete" == method:
            raise Exception("Disconnected by the Dapp.")
        # Dispatch query processing
        elif "eth_signTypedData" == method:
            result = process_signtypeddata(id_request, parameters[1])
            wallet_dapp.reply(call_id, result)
        elif "eth_sendTransaction" == method:
            approve_ask = input("Approve (y/N)?: ").lower()
            if approve_ask == 'y':
                result = process_sendtransaction(id_request, parameters[0])
                wallet_dapp.reply(call_id, result)
            else:
                wallet_dapp.reply_error(call_id, "User rejected request.", 4001)
        elif "eth_sign" == method:
            approve_ask = input("Approve (y/N)?: ").lower()
            if approve_ask == 'y':
                result = process_signtransaction(parameters[1])
                wallet_dapp.reply(call_id, result)
            else:
                wallet_dapp.reject(call_id)
        <...>
        # Next loop
        wc_message = wallet_dapp.get_message()


# GUI timer repeated or threading daemon
# Will call watch_messages every 4 seconds
apptimer = Timer(4000)
# Call watch_messages when expires periodically
apptimer.notify = watch_messages

```

See also the [RPC methods in WalletConnect](https://docs.walletconnect.org/v/1.0/json-rpc-api-methods/ethereum) to know more about the expected result regarding a specific RPC call.

## Interface methods of WCClient

`WCClient.set_wallet_metadata( wallet_metadata )`  
Class method to set the wallet metadata as object (v2). See [the WalletConnect standard for the format details](https://docs.walletconnect.com/2.0/specs/clients/core/pairing/data-structures#metadata).  
Optional. If not provided, when v2, it sends the default pyWalletConnect metadata as wallet identification.

`WCClient.set_wallet_namespace( wallet_namespace )`  
Class method to set the wallet [namespace](https://docs.walletconnect.com/2.0/advanced/glossary#namespaces), i.e. supported chain collection.  
Only for v2, optional. Defaults to 'eip155' aka EVM-based chains.

`WCClient.set_project_id( project_id )`  
Class method to set the WalletConnect project id. This is mandatory to use a project id when  
using WC v2 with the official central bridge relay.

`WCClient.set_origin( origin_domain )`  
Class method to set the origin of the first HTTP query for websocket. Only for v2, optional.

`WCClient.from_wc_uri( wc_uri_str )`  
Create a WalletConnect wallet client from a wc v1 or v2 URI. (class method constructor)  
*wc_uri_str* : the wc full EIP1328 URI provided by the Dapp.  
You need to call *open_session* immediately after to get the session request info.

`.close()`  
Send a session close message, and close the underlying WebSocket connection.

`.get_relay_url()`  
Give the page address of the WebSocket relay bridge.

`.get_message()`  
Get a RPC call message from the internal waiting list. pyWalletConnect maintains an internal pool of received request messages from the dapp. And this get_message method pops out a message in a FIFO manner : the first method call provides the oldest (first) received message. It can be used like a pump : call *get_message()* until an empty response. Because it reads a message from the receiving bucket one by one.  
This needs to be called periodically because this triggers the auto reconnection (When the WebSocket is abruptly disconnected by the relay).  
Return : (RPCid, method, params) or (None, "", []) when no data were received since the last call (or from the initial session connection).  
Non-blocking, so always returns immediately when there's no message, and returns (None, "", []).  
When a v2 ping *wc_sessionPing* is received, it is automatically replied when getting it with get_message. In this case, the *get_message* method returns an empty method and no params. So filter *get_message* calls with 'id is None', means no more message left.

`.reply( req_id, result_str )`  
Send a RPC response to the webapp (through the relay).  
*req_id* is the JSON-RPC id of the corresponding query request, where the result belongs to. One must kept track this id from the get_message, up to this reply. So a reply result is given back with its associated call query id.  
*result_str* is the result field to provide in the RPC result response.

`.reject( req_id, error_code=5002 )`  
Inform the webapp that this request was rejected by the user.  
*req_id* is the JSON-RPC id of the corresponding query request.  
*error_code* is a rejection code to send to webapp (default 5002).  

`.reply_error( req_id, message, error_code )`  
Send a RPC error to the webapp (through the relay).  
*req_id* is the JSON-RPC id of the corresponding query request.  
*message* is a string providing a short description of the error.  
*error_code* is a number that indicates the error type that occurred. See [the WalletConnect standard Error Codes](https://docs.walletconnect.com/2.0/specs/clients/sign/error-codes).   

`.open_session()`  
Start a WalletConnect session : wait for the session call request message.  
Must be called right after a WCClient creation.  
Returns : (message RPCid, chain ID, peerMeta data object).  
Or throws WalletConnectClientException("sessionRequest timeout")
after 8 seconds and no sessionRequest received.

`reply_session_request( msg_id, chain_id, account_address )`  
Send a session approval message, when user approved the connection session request in the wallet.  
*msg_id* is the RPC id of the session approval request.
*chain_id* is the integer ideitifying the blockchain.
*account_address* is a string of the address of the wallet account ("0x...").

`.reject_session_request( req_id )`  
Send a session rejection message to the dapp (through the relay).
*req_id* is the RPC id of the session approval request.


## License

Copyright (C) 2021-2023  BitLogiK SAS

This program is free software: you can redistribute it and/or modify  
it under the terms of the GNU General Public License as published by  
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,  
but WITHOUT ANY WARRANTY; without even the implied warranty of  
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
See the GNU General Public License for more details.


## Support

Open an issue in the Github repository for help about its use.
