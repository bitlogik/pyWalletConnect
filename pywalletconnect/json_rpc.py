# -*- coding: utf8 -*-

# pyWalletConnect : JSON RPC
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


"""JSON RPC for pyWalletConnect"""


from json import dumps, loads


# ---- Helpers about messages encoding


def json_encode(dataobj):
    """Compact JSON encoding."""
    return dumps(dataobj, separators=(",", ":"))


# ---- JSON RPC functions to pack/unpack

# The wallet is a JSON-RPC service in the WalletConnect standard


def json_rpc_pack_response(idmsg, result_obj):
    """Build a JSON-RPC response."""
    request_obj = {
        "jsonrpc": "2.0",
        "id": idmsg,
        "result": result_obj,
    }
    return json_encode(request_obj).encode("utf8")


def json_rpc_unpack(buffer):
    """Decode a JSON-RPC call query : id, method, params."""
    try:
        resp_obj = loads(buffer)
    except Exception as exc:
        raise Exception(f"Error : not JSON response : {buffer}") from exc
    if resp_obj["jsonrpc"] != "2.0":
        raise Exception(f"Server is not JSONRPC 2.0 but {resp_obj.jsonrpc}")
    if "error" in resp_obj:
        raise Exception(resp_obj["error"]["message"])
    return resp_obj["id"], resp_obj["method"], resp_obj["params"]
