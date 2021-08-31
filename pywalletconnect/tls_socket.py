# -*- coding: utf8 -*-

# pyWalletConnect : TLS socket
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


"""TLS socket for pyWalletConnect"""

from logging import getLogger
from ssl import create_default_context, SSLWantReadError
from socket import create_connection


RECEIVING_BUFFER_SIZE = 8192


logger = getLogger(__name__)


class TLSsocket:
    """TLS socket client with a host, push and read data."""

    def __init__(self, domain, port):
        """Open a TLS connection with a host domain:port."""
        context = create_default_context()
        sock = create_connection((domain, port))
        self.conn = context.wrap_socket(sock, server_hostname=domain)
        logger.debug("Socket connected")
        self.conn.settimeout(0)

    def __del__(self):
        """Close the socket when deleting the object."""
        self.close()

    def close(self):
        """Close the socket."""
        if self.conn is not None:
            logger.debug("Closing socket")
            self.conn.close()
            self.conn = None

    def send(self, data_buffer):
        """Send data to the host."""
        self.conn.sendall(data_buffer)

    def receive(self):
        """Read data from the host.
        Non-blocking reception.
        If no data received from host since last read, return empty bytes.
        """
        try:
            datar = self.conn.recv(RECEIVING_BUFFER_SIZE)
            if datar == b"":
                logger.debug("Socket disconnected")
                self.close()
            return datar
        except SSLWantReadError:
            # No data available
            return b""
