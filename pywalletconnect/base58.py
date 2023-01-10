# -*- coding: utf8 -*-

# pyWalletConnect  -  base58 encoder
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


BASE58 = 58
b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def bin_to_base58(bin_data):
    base58 = ""
    int_data = int.from_bytes(bin_data, "big")
    while int_data >= BASE58:
        base58 = b58chars[int_data % BASE58] + base58
        int_data = int_data // BASE58
    base58 = b58chars[int_data % BASE58] + base58
    for charval in bin_data:
        if charval == 0:
            base58 = "1" + base58
        else:
            break
    return base58
