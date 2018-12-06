#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# protocol.py - Bitcoin protocol access for Bitnodes.
#
# Copyright (c) Addy Yeow Chin Heng <ayeowch@gmail.com>
#
# Modified by open-nodes project for python3 compatibility
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
Bitcoin protocol access for Bitnodes.
Reference: https://en.bitcoin.it/wiki/Protocol_specification

-------------------------------------------------------------------------------
                     PACKET STRUCTURE FOR BITCOIN PROTOCOL
                           protocol version >= 70001
-------------------------------------------------------------------------------
[---MESSAGE---]
[ 4] MAGIC_NUMBER               (\xF9\xBE\xB4\xD9)                  uint32_t
[12] COMMAND                                                        char[12]
[ 4] LENGTH                     <I (len(payload))                   uint32_t
[ 4] CHECKSUM                   (sha256(sha256(payload))[:4])       uint32_t
[..] PAYLOAD                    see below

    [---VERSION_PAYLOAD---]
    [ 4] VERSION                <i                                  int32_t
    [ 8] SERVICES               <Q                                  uint64_t
    [ 8] TIMESTAMP              <q                                  int64_t
    [26] ADDR_RECV
        [ 8] SERVICES           <Q                                  uint64_t
        [16] IP_ADDR
            [12] IPV6           (\x00 * 10 + \xFF * 2)              char[12]
            [ 4] IPV4                                               char[4]
        [ 2] PORT               >H                                  uint16_t
    [26] ADDR_FROM
        [ 8] SERVICES           <Q                                  uint64_t
        [16] IP_ADDR
            [12] IPV6           (\x00 * 10 + \xFF * 2)              char[12]
            [ 4] IPV4                                               char[4]
        [ 2] PORT               >H                                  uint16_t
    [ 8] NONCE                  <Q (random.getrandbits(64))         uint64_t
    [..] USER_AGENT             variable string
    [ 4] HEIGHT                 <i                                  int32_t
    [ 1] RELAY                  <? (since version >= 70001)         bool

    [---ADDR_PAYLOAD---]
    [..] COUNT                  variable integer
    [..] ADDR_LIST              multiple of COUNT (max 1000)
        [ 4] TIMESTAMP          <I                                  uint32_t
        [ 8] SERVICES           <Q                                  uint64_t
        [16] IP_ADDR
            [12] IPV6           (\x00 * 10 + \xFF * 2)              char[12]
            [ 4] IPV4                                               char[4]
        [ 2] PORT               >H                                  uint16_t

    [---PING_PAYLOAD---]
    [ 8] NONCE                  <Q (random.getrandbits(64))         uint64_t

    [---PONG_PAYLOAD---]
    [ 8] NONCE                  <Q (nonce from ping)                uint64_t

    [---INV_PAYLOAD---]
    [..] COUNT                  variable integer
    [..] INVENTORY              multiple of COUNT (max 50000)
        [ 4] TYPE               <I (0=error, 1=tx, 2=block)         uint32_t
        [32] HASH                                                   char[32]

    [---TX_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] TX_IN_COUNT            variable integer
    [..] TX_IN                  multiple of TX_IN_COUNT
        [32] PREV_OUT_HASH                                          char[32]
        [ 4] PREV_OUT_INDEX     <I (zero-based)                     uint32_t
        [..] SCRIPT_LENGTH      variable integer
        [..] SCRIPT             variable string
        [ 4] SEQUENCE           <I                                  uint32_t
    [..] TX_OUT_COUNT           variable integer
    [..] TX_OUT                 multiple of TX_OUT_COUNT
        [ 8] VALUE              <q                                  int64_t
        [..] SCRIPT_LENGTH      variable integer
        [..] SCRIPT             variable string
    [ 4] LOCK_TIME              <I                                  uint32_t

    [---BLOCK_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [32] PREV_BLOCK_HASH                                            char[32]
    [32] MERKLE_ROOT                                                char[32]
    [ 4] TIMESTAMP              <I                                  uint32_t
    [ 4] BITS                   <I                                  uint32_t
    [ 4] NONCE                  <I                                  uint32_t
    [..] TX_COUNT               variable integer
    [..] TX                     multiple of TX_COUNT
        [..] TX                 see TX_PAYLOAD

    [---GETBLOCKS_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] COUNT                  variable integer
    [..] BLOCK_HASHES           multiple of COUNT
        [32] BLOCK_HASH                                             char[32]
    [32] LAST_BLOCK_HASH                                            char[32]

    [---GETHEADERS_PAYLOAD---]
    [ 4] VERSION                <I                                  uint32_t
    [..] COUNT                  variable integer
    [..] BLOCK_HASHES           multiple of COUNT
        [32] BLOCK_HASH                                             char[32]
    [32] LAST_BLOCK_HASH                                            char[32]

    [---HEADERS_PAYLOAD---]
    [..] COUNT                  variable integer (max 2000)
    [..] HEADERS                multiple of COUNT
        [ 4] VERSION            <I                                  uint32_t
        [32] PREV_BLOCK_HASH                                        char[32]
        [32] MERKLE_ROOT                                            char[32]
        [ 4] TIMESTAMP          <I                                  uint32_t
        [ 4] BITS               <I                                  uint32_t
        [ 4] NONCE              <I                                  uint32_t
        [..] TX_COUNT           variable integer (always 0)
-------------------------------------------------------------------------------
"""

import hashlib
import random
import socket
import socks
import struct
import sys
import time
from base64 import b32decode, b32encode
from binascii import hexlify, unhexlify
from collections import deque
from io import SEEK_CUR, BytesIO
from operator import itemgetter

# MAGIC_NUMBER = "\xF9\xBE\xB4\xD9"
# PORT = 8333
# MIN_PROTOCOL_VERSION = 70001
# PROTOCOL_VERSION = 70015
# FROM_SERVICES = 0
# TO_SERVICES = 1  # NODE_NETWORK
# USER_AGENT = "/bitnodes.earn.com:0.1/"
# HEIGHT = 478000
# RELAY = 0  # set to 1 to receive all txs
import logging

SOCKET_BUFSIZE = 8192
SOCKET_TIMEOUT = 30
HEADER_LEN = 24

ONION_PREFIX = b"\xFD\x87\xD8\x7E\xEB\x43"  # ipv6 prefix for .onion address


class ProtocolError(Exception):
    pass


class ConnectionError(Exception):
    pass


class HeaderTooShortError(ProtocolError):
    pass


class InvalidMagicNumberError(ProtocolError):
    pass


class PayloadTooShortError(ProtocolError):
    pass


class InvalidPayloadChecksum(ProtocolError):
    pass


class IncompatibleClientError(ProtocolError):
    pass


class ReadError(ProtocolError):
    pass


class ProxyRequired(ConnectionError):
    pass


class RemoteHostClosedConnection(ConnectionError):
    pass


def sha256(data):
    return hashlib.sha256(data).digest()


def unpack(fmt, string):
    # Wraps problematic struct.unpack() in a try statement
    try:
        return struct.unpack(fmt, string)[0]
    except struct.error as err:
        raise ReadError(err)


def create_connection(address, timeout=SOCKET_TIMEOUT, source_address=None,
                      proxy=None):
    if address[0].endswith(".onion") and proxy is None:
        raise ProxyRequired(
            "tor proxy is required to connect to .onion address")
    if proxy:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy[0], proxy[1])
        sock = socks.socksocket()
        sock.settimeout(timeout)
        try:
            sock.connect(address)
        except socks.ProxyError as err:
            raise ConnectionError(err)
        return sock
    if ":" in address[0] and source_address and ":" not in source_address[0]:
        source_address = None
    return socket.create_connection(address, timeout=timeout,
                                    source_address=source_address)


class Serializer(object):
    def __init__(self, **conf):
        self.magic_number = conf.get('magic_number')
        self.protocol_version = conf.get('protocol_version')
        self.to_services = conf.get('to_services')
        self.from_services = conf.get('from_services')
        self.user_agent = conf.get('user_agent')
        self.height = conf.get('height')
        self.min_protocol_version = conf.get("min_protocol_version")
        if self.height is None:
            self.height = 0
        self.relay = conf.get('relay')
        # This is set prior to throwing PayloadTooShortError exception to
        # allow caller to fetch more data over the network.
        self.required_len = 0

    def serialize_msg(self, **kwargs):
        command = kwargs['command']
        msg = [
            self.magic_number,
            command + b"\x00" * (12 - len(command)),
        ]

        payload = b""
        if command == b"version":
            to_addr = (self.to_services,) + kwargs['to_addr']
            from_addr = (self.from_services,) + kwargs['from_addr']
            payload = self.serialize_version_payload(to_addr, from_addr)
        elif command == b"ping" or command == b"pong":
            nonce = kwargs['nonce']
            payload = self.serialize_ping_payload(nonce)
        elif command == b"addr":
            addr_list = kwargs['addr_list']
            payload = self.serialize_addr_payload(addr_list)
        elif command == b"inv" or command == b"getdata":
            inventory = kwargs['inventory']
            payload = self.serialize_inv_payload(inventory)
        elif command == b"getblocks" or command == b"getheaders":
            block_hashes = kwargs['block_hashes']
            last_block_hash = kwargs['last_block_hash']
            payload = self.serialize_getblocks_payload(block_hashes,
                                                       last_block_hash)
        elif command == b"headers":
            headers = kwargs['headers']
            payload = self.serialize_block_headers_payload(headers)

        msg.extend([
            struct.pack("<I", len(payload)),
            sha256(sha256(payload))[:4],
            payload,
        ])
        return b''.join(msg)

    def deserialize_msg(self, data):
        msg = {}

        data_len = len(data)
        if data_len < HEADER_LEN:
            raise HeaderTooShortError("got {} of {} bytes".format(
                data_len, HEADER_LEN))

        data = BytesIO(data)
        header = data.read(HEADER_LEN)
        msg.update(self.deserialize_header(header))

        if (data_len - HEADER_LEN) < msg['length']:
            self.required_len = HEADER_LEN + msg['length']
            raise PayloadTooShortError("got {} of {} bytes".format(
                data_len, HEADER_LEN + msg['length']))

        payload = data.read(msg['length'])
        computed_checksum = sha256(sha256(payload))[:4]
        if computed_checksum != msg['checksum']:
            raise InvalidPayloadChecksum("{} != {}".format(
                hexlify(computed_checksum), hexlify(msg['checksum'])))

        if msg['command'] == b"version":
            msg.update(self.deserialize_version_payload(payload))
        elif msg['command'] == b"ping" or msg['command'] == b"pong":
            msg.update(self.deserialize_ping_payload(payload))
        elif msg['command'] == b"addr":
            msg.update(self.deserialize_addr_payload(payload))
        elif msg['command'] == b"inv":
            msg.update(self.deserialize_inv_payload(payload))
        elif msg['command'] == b"tx":
            msg.update(self.deserialize_tx_payload(payload))
        elif msg['command'] == b"block":
            msg.update(self.deserialize_block_payload(payload))
        elif msg['command'] == b"headers":
            msg.update(self.deserialize_block_headers_payload(payload))

        return (msg, data.read())

    def deserialize_header(self, data):
        msg = {}
        data = BytesIO(data)

        msg['magic_number'] = data.read(4)
        if msg['magic_number'] != self.magic_number:
            raise InvalidMagicNumberError("{} != {}".format(hexlify(msg['magic_number']), hexlify(self.magic_number)))

        msg['command'] = data.read(12).strip(b"\x00")
        msg['length'] = struct.unpack("<I", data.read(4))[0]
        msg['checksum'] = data.read(4)

        return msg

    def serialize_version_payload(self, to_addr, from_addr):
        payload = [
            struct.pack("<i", self.protocol_version),
            struct.pack("<Q", self.from_services),
            struct.pack("<q", int(time.time())),
            self.serialize_network_address(to_addr),
            self.serialize_network_address(from_addr),
            struct.pack("<Q", random.getrandbits(64)),
            self.serialize_string(self.user_agent),
            struct.pack("<i", self.height),
            struct.pack("<?", self.relay),
        ]

        return b''.join(payload)

    def deserialize_version_payload(self, data):
        msg = {}
        data = BytesIO(data)

        msg['version'] = unpack("<i", data.read(4))
        if msg['version'] < self.min_protocol_version:
            raise IncompatibleClientError("{} < {}".format(
                msg['version'], self.min_protocol_version))

        msg['services'] = unpack("<Q", data.read(8))
        msg['timestamp'] = unpack("<q", data.read(8))

        msg['to_addr'] = self.deserialize_network_address(data)
        msg['from_addr'] = self.deserialize_network_address(data)

        msg['nonce'] = unpack("<Q", data.read(8))

        msg['user_agent'] = self.deserialize_string(data)

        msg['height'] = unpack("<i", data.read(4))

        try:
            msg['relay'] = struct.unpack("<?", data.read(1))[0]
        except struct.error:
            msg['relay'] = False

        return msg

    def serialize_ping_payload(self, nonce):
        payload = [
            struct.pack("<Q", nonce),
        ]
        return b''.join(payload)

    def deserialize_ping_payload(self, data):
        data = BytesIO(data)
        nonce = unpack("<Q", data.read(8))
        msg = {
            'nonce': nonce,
        }
        return msg

    def serialize_addr_payload(self, addr_list):
        payload = [
            self.serialize_int(len(addr_list)),
        ]
        payload.extend(
            [self.serialize_network_address(addr) for addr in addr_list])
        return b''.join(payload)

    def deserialize_addr_payload(self, data):
        msg = {}
        data = BytesIO(data)

        msg['count'] = self.deserialize_int(data)
        msg['addr_list'] = []
        for _ in range(msg['count']):
            network_address = self.deserialize_network_address(
                data, has_timestamp=True)
            msg['addr_list'].append(network_address)

        return msg

    def serialize_inv_payload(self, inventory):
        payload = [
            self.serialize_int(len(inventory)),
        ]
        payload.extend(
            [self.serialize_inventory(item) for item in inventory])
        return b''.join(payload)

    def deserialize_inv_payload(self, data):
        msg = {
            'timestamp': int(time.time() * 1000),  # milliseconds
        }
        data = BytesIO(data)

        msg['count'] = self.deserialize_int(data)
        msg['inventory'] = []
        for _ in range(msg['count']):
            inventory = self.deserialize_inventory(data)
            msg['inventory'].append(inventory)

        return msg

    def serialize_tx_payload(self, tx):
        payload = [
            struct.pack("<I", tx['version']),
            self.serialize_int(tx['tx_in_count']),
            b''.join([
                self.serialize_tx_in(tx_in) for tx_in in tx['tx_in']
            ]),
            self.serialize_int(tx['tx_out_count']),
            b''.join([
                self.serialize_tx_out(tx_out) for tx_out in tx['tx_out']
            ]),
            struct.pack("<I", tx['lock_time']),
        ]
        return b''.join(payload)

    def deserialize_tx_payload(self, data):
        msg = {}
        if isinstance(data, bytes):
            data = BytesIO(data)

        msg['version'] = unpack("<I", data.read(4))

        # Check for BIP144 marker
        marker = data.read(1)
        if marker == '\x00':  # BIP144 marker is set
            flags = data.read(1)
        else:
            flags = '\x00'
            data.seek(-1, SEEK_CUR)

        msg['tx_in_count'] = self.deserialize_int(data)
        msg['tx_in'] = []
        for _ in range(msg['tx_in_count']):
            tx_in = self.deserialize_tx_in(data)
            msg['tx_in'].append(tx_in)

        msg['tx_out_count'] = self.deserialize_int(data)
        msg['tx_out'] = []
        for _ in range(msg['tx_out_count']):
            tx_out = self.deserialize_tx_out(data)
            msg['tx_out'].append(tx_out)

        if flags != '\x00':
            for in_num in range(msg['tx_in_count']):
                msg['tx_in'][in_num].update({
                    'wits': self.deserialize_string_vector(data),
                })

        msg['lock_time'] = unpack("<I", data.read(4))

        # Calculate hash from the entire payload
        payload = self.serialize_tx_payload(msg)
        msg['tx_hash'] = hexlify(sha256(sha256(payload))[::-1])

        return msg

    def deserialize_block_payload(self, data):
        msg = {}

        # Calculate hash from: version (4 bytes) + prev_block_hash (32 bytes) +
        # merkle_root (32 bytes) + timestamp (4 bytes) + bits (4 bytes) +
        # nonce (4 bytes) = 80 bytes
        msg['block_hash'] = hexlify(sha256(sha256(data[:80]))[::-1])

        data = BytesIO(data)

        msg['version'] = struct.unpack("<I", data.read(4))[0]

        # BE (big-endian) -> LE (little-endian)
        msg['prev_block_hash'] = hexlify(data.read(32)[::-1])

        # BE -> LE
        msg['merkle_root'] = hexlify(data.read(32)[::-1])

        msg['timestamp'] = struct.unpack("<I", data.read(4))[0]
        msg['bits'] = struct.unpack("<I", data.read(4))[0]
        msg['nonce'] = struct.unpack("<I", data.read(4))[0]

        msg['tx_count'] = self.deserialize_int(data)
        msg['tx'] = []
        for _ in range(msg['tx_count']):
            tx_payload = self.deserialize_tx_payload(data)
            msg['tx'].append(tx_payload)

        return msg

    def serialize_getblocks_payload(self, block_hashes, last_block_hash):
        payload = [
            struct.pack("<i", self.protocol_version),
            self.serialize_int(len(block_hashes)),
            ''.join(
                [unhexlify(block_hash)[::-1] for block_hash in block_hashes]),
            unhexlify(last_block_hash)[::-1],  # LE -> BE
        ]
        return b''.join(payload)

    def serialize_block_headers_payload(self, headers):
        payload = [
            self.serialize_int(len(headers)),
        ]
        payload.extend(
            [self.serialize_block_header(header) for header in headers])
        return b''.join(payload)

    def deserialize_block_headers_payload(self, data):
        msg = {}
        data = BytesIO(data)

        msg['count'] = self.deserialize_int(data)
        msg['headers'] = []
        for _ in range(msg['count']):
            header = self.deserialize_block_header(data)
            msg['headers'].append(header)

        return msg

    def serialize_network_address(self, addr):
        network_address = []
        if len(addr) == 4:
            (timestamp, services, ip_address, port) = addr
            network_address.append(struct.pack("<I", timestamp))
        else:
            (services, ip_address, port) = addr
        network_address.append(struct.pack("<Q", services))
        if ip_address.endswith(".onion"):
            # convert .onion address to its ipv6 equivalent (6 + 10 bytes)
            network_address.append(
                ONION_PREFIX + b32decode(ip_address[:-6].encode(), True))
        elif "." in ip_address:
            # unused (12 bytes) + ipv4 (4 bytes) = ipv4-mapped ipv6 address
            unused = b"\x00" * 10 + b"\xFF" * 2
            network_address.append(
                unused + socket.inet_pton(socket.AF_INET, ip_address))
        else:
            # ipv6 (16 bytes)
            network_address.append(
                socket.inet_pton(socket.AF_INET6, ip_address))
        network_address.append(struct.pack(">H", port))
        return b''.join(network_address)

    def deserialize_network_address(self, data, has_timestamp=False):
        timestamp = None
        if has_timestamp:
            timestamp = unpack("<I", data.read(4))

        services = unpack("<Q", data.read(8))

        _ipv6 = data.read(12)
        _ipv4 = data.read(4)
        port = unpack(">H", data.read(2))
        _ipv6 += _ipv4

        ipv4 = ""
        ipv6 = ""
        onion = ""

        if _ipv6[:6] == ONION_PREFIX:
            onion = b32encode(_ipv6[6:]).lower().decode("utf8") + ".onion"  # use .onion
        else:
            ipv6 = socket.inet_ntop(socket.AF_INET6, _ipv6)
            ipv4 = socket.inet_ntop(socket.AF_INET, _ipv4)
            if ipv4 in ipv6:
                ipv6 = ""  # use ipv4
            else:
                ipv4 = ""  # use ipv6

        return {
            'timestamp': timestamp,
            'services': services,
            'ipv4': ipv4,
            'ipv6': ipv6,
            'onion': onion,
            'port': port,
        }

    def serialize_inventory(self, item):
        (inv_type, inv_hash) = item
        payload = [
            struct.pack("<I", inv_type),
            unhexlify(inv_hash)[::-1],  # LE -> BE
        ]
        return b''.join(payload)

    def deserialize_inventory(self, data):
        inv_type = unpack("<I", data.read(4))
        inv_hash = data.read(32)[::-1]  # BE -> LE
        return {
            'type': inv_type,
            'hash': hexlify(inv_hash),
        }

    def serialize_tx_in(self, tx_in):
        payload = [
            unhexlify(tx_in['prev_out_hash'])[::-1],  # LE -> BE
            struct.pack("<I", tx_in['prev_out_index']),
            self.serialize_int(tx_in['script_length']),
            tx_in['script'],
            struct.pack("<I", tx_in['sequence']),
        ]
        return b''.join(payload)


    def deserialize_tx_in(self, data):
        prev_out_hash = data.read(32)[::-1]  # BE -> LE
        prev_out_index = struct.unpack("<I", data.read(4))[0]
        script_length = self.deserialize_int(data)
        script = data.read(script_length)
        sequence = unpack("<I", data.read(4))
        return {
            'prev_out_hash': hexlify(prev_out_hash),
            'prev_out_index': prev_out_index,
            'script_length': script_length,
            'script': script,
            'sequence': sequence,
        }

    def serialize_tx_out(self, tx_out):
        payload = [
            struct.pack("<q", tx_out['value']),
            self.serialize_int(tx_out['script_length']),
            tx_out['script'],
        ]
        return b''.join(payload)

    def deserialize_tx_out(self, data):
        value = struct.unpack("<q", data.read(8))[0]
        script_length = self.deserialize_int(data)
        script = data.read(script_length)
        return {
            'value': value,
            'script_length': script_length,
            'script': script,
        }

    def serialize_block_header(self, header):
        payload = [
            struct.pack("<I", header['version']),
            unhexlify(header['prev_block_hash'])[::-1],  # LE -> BE
            unhexlify(header['merkle_root'])[::-1],  # LE -> BE
            struct.pack("<I", header['timestamp']),
            struct.pack("<I", header['bits']),
            struct.pack("<I", header['nonce']),
            self.serialize_int(0),
        ]
        return ''.join(payload)

    def deserialize_block_header(self, data):
        header = data.read(80)
        block_hash = sha256(sha256(header))[::-1]  # BE -> LE
        header = BytesIO(header)
        version = struct.unpack("<i", header.read(4))[0]
        prev_block_hash = header.read(32)[::-1]  # BE -> LE
        merkle_root = header.read(32)[::-1]  # BE -> LE
        timestamp = struct.unpack("<I", header.read(4))[0]
        bits = struct.unpack("<I", header.read(4))[0]
        nonce = struct.unpack("<I", header.read(4))[0]
        tx_count = self.deserialize_int(data)
        return {
            'block_hash': hexlify(block_hash),
            'version': version,
            'prev_block_hash': hexlify(prev_block_hash),
            'merkle_root': hexlify(merkle_root),
            'timestamp': timestamp,
            'bits': bits,
            'nonce': nonce,
            'tx_count': tx_count,
        }

    def serialize_string_vector(self, data):
        payload = [
                      self.serialize_int(len(data)),
                  ] + [self.serialize_string(item) for item in data]
        return ''.join(payload)

    def deserialize_string_vector(self, data):
        items = []
        count = self.deserialize_int(data)
        for _ in range(count):
            items.append(self.deserialize_string(data))
        return items

    def serialize_string(self, data):
        if isinstance(data, bytes):
            pass
        else:
            data = data.encode()
        length = len(data)
        if length < 0xFD:
            out = chr(length).encode() + data
            return out
        elif length <= 0xFFFF:
            out = chr(0xFD).encode() + struct.pack("<H", length) + data
            return out
        elif length <= 0xFFFFFFFF:
            out = chr(0xFE).encode() + struct.pack("<I", length) + data
            return out
        out = chr(0xFF).encode() + struct.pack("<Q", length) + data
        return out

    def deserialize_string(self, data):
        length = self.deserialize_int(data)
        return data.read(length)

    def serialize_int(self, length):
        if length < 0xFD:
            return chr(length).encode()
        elif length <= 0xFFFF:
            return chr(0xFD).encode() + struct.pack("<H", length)
        elif length <= 0xFFFFFFFF:
            return chr(0xFE).encode() + struct.pack("<I", length)
        return chr(0xFF).encode() + struct.pack("<Q", length)

    def deserialize_int(self, data):
        length = unpack("<B", data.read(1))
        if length == 0xFD:
            length = unpack("<H", data.read(2))
        elif length == 0xFE:
            length = unpack("<I", data.read(4))
        elif length == 0xFF:
            length = unpack("<Q", data.read(8))
        return length


class Connection(object):
    def __init__(self, to_addr, from_addr=("0.0.0.0", 0), **conf):
        self.to_addr = to_addr
        self.from_addr = from_addr
        self.serializer = Serializer(**conf)
        self.socket_timeout = conf.get('socket_timeout', SOCKET_TIMEOUT)
        self.proxy = conf.get('proxy', None)
        self.socket = None
        self.bps = deque([], maxlen=128)  # bps samples for this connection

    def open(self):
        self.socket = create_connection(self.to_addr,
                                        timeout=self.socket_timeout,
                                        source_address=self.from_addr,
                                        proxy=self.proxy)


    def close(self):
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            finally:
                self.socket.close()

    def send(self, data):
        self.socket.sendall(data)

    def recv(self, length=0):
        start_t = time.time()
        if length > 0:
            chunks = []
            while length > 0:
                chunk = self.socket.recv(SOCKET_BUFSIZE)
                if not chunk:
                    raise RemoteHostClosedConnection("{} closed connection".format(self.to_addr))
                chunks.append(chunk)
                length -= len(chunk)
            data = b''.join(chunks)
        else:
            data = self.socket.recv(SOCKET_BUFSIZE)
            if not data:
                raise RemoteHostClosedConnection("{} closed connection".format(self.to_addr))
        if len(data) > SOCKET_BUFSIZE:
            end_t = time.time()
            self.bps.append((len(data) * 8) / (end_t - start_t))
        return data

    def get_messages(self, length=0, commands=None):
        msgs = []
        data = self.recv(length=length)
        while len(data) > 0:
            time.sleep(0.0001)
            try:
                (msg, data) = self.serializer.deserialize_msg(data)
            except PayloadTooShortError:
                data += self.recv(
                    length=self.serializer.required_len - len(data))
                (msg, data) = self.serializer.deserialize_msg(data)
            if msg.get('command') == b"ping":
                self.pong(msg['nonce'])  # respond to ping immediately
            elif msg.get('command') == b"version":
                self.verack()  # respond to version immediately
            msgs.append(msg)
        if len(msgs) > 0 and commands:
            msgs[:] = [m for m in msgs if m.get('command') in commands]
        return msgs

    def set_min_version(self, version):
        self.serializer.protocol_version = min(
            self.serializer.protocol_version,
            version.get(b'version', self.serializer.protocol_version))

    def handshake(self):
        # [version] >>>
        msg = self.serializer.serialize_msg(
            command=b"version", to_addr=self.to_addr, from_addr=self.from_addr)
        self.send(msg)

        # <<< [version 124 bytes] [verack 24 bytes]
        time.sleep(1)
        msgs = self.get_messages(length=148, commands=[b"version", b"verack"])
        if len(msgs) > 0:
            msgs[:] = sorted(msgs, key=itemgetter('command'), reverse=True)
            self.set_min_version(msgs[0])
        return msgs

    def verack(self):
        # [verack] >>>
        msg = self.serializer.serialize_msg(command=b"verack")
        self.send(msg)

    def getaddr(self, block=True):
        # [getaddr] >>>
        msg = self.serializer.serialize_msg(command=b"getaddr")
        self.send(msg)

        # Caller should call get_messages separately.
        if not block:
            return None

        # <<< [addr]..
        time.sleep(3)
        msgs = self.get_messages(commands=[b"addr"])
        return msgs

    def getpeerinfo(self, block=True):
        # [getaddr] >>>
        msg = self.serializer.serialize_msg(command=b"getpeerinfo")
        self.send(msg)

        # Caller should call get_messages separately.
        if not block:
            return None

        # <<< [addr]..
        msgs = self.get_messages(commands=[b"getpeerinfo"])
        return msgs

    def addr(self, addr_list):
        # addr_list = [(TIMESTAMP, SERVICES, "IP_ADDRESS", PORT),]
        # [addr] >>>
        msg = self.serializer.serialize_msg(
            command=b"addr", addr_list=addr_list)
        self.send(msg)

    def ping(self, nonce=None):
        if nonce is None:
            nonce = random.getrandbits(64)

        # [ping] >>>
        msg = self.serializer.serialize_msg(command=b"ping", nonce=nonce)
        self.send(msg)

    def pong(self, nonce):
        # [pong] >>>
        msg = self.serializer.serialize_msg(command=b"pong", nonce=nonce)
        self.send(msg)

    def inv(self, inventory):
        # inventory = [(INV_TYPE, "INV_HASH"),]
        # [inv] >>>
        msg = self.serializer.serialize_msg(
            command=b"inv", inventory=inventory)
        self.send(msg)

    def getdata(self, inventory):
        # inventory = [(INV_TYPE, "INV_HASH"),]
        # [getdata] >>>
        msg = self.serializer.serialize_msg(
            command=b"getdata", inventory=inventory)
        self.send(msg)

        # <<< [tx] [block]..
        time.sleep(1)
        msgs = self.get_messages(commands=[b"tx", b"block"])
        return msgs

    def getblocks(self, block_hashes, last_block_hash=None):
        if last_block_hash is None:
            last_block_hash = "0" * 64

        # block_hashes = ["BLOCK_HASH",]
        # [getblocks] >>>
        msg = self.serializer.serialize_msg(command=b"getblocks",
                                            block_hashes=block_hashes,
                                            last_block_hash=last_block_hash)
        self.send(msg)

        # <<< [inv]..
        time.sleep(1)
        msgs = self.get_messages(commands=[b"inv"])
        return msgs

    def getheaders(self, block_hashes, last_block_hash=None):
        if last_block_hash is None:
            last_block_hash = "0" * 64

        # block_hashes = ["BLOCK_HASH",]
        # [getheaders] >>>
        msg = self.serializer.serialize_msg(command=b"getheaders",
                                            block_hashes=block_hashes,
                                            last_block_hash=last_block_hash)
        self.send(msg)

        # <<< [headers]..
        time.sleep(1)
        msgs = self.get_messages(commands=[b"headers"])
        return msgs

    def headers(self, headers):
        # headers = [{
        #   'version': VERSION,
        #   'prev_block_hash': PREV_BLOCK_HASH,
        #   'merkle_root': MERKLE_ROOT,
        #   'timestamp': TIMESTAMP,
        #   'bits': BITS,
        #   'nonce': NONCE
        # },]
        # [headers] >>>
        msg = self.serializer.serialize_msg(command=b"headers", headers=headers)
        self.send(msg)

class Keepalive(object):
    """
    Implements keepalive mechanic to keep the specified connection with a node.
    """
    def __init__(self, conn, keepalive_time):
        self.conn = conn
        self.keepalive_time = keepalive_time

    def keepalive(self, addr=False):
        st = time.time()
        last_ping = time.time() - 10
        addrs = []
        while time.time() - st < self.keepalive_time:
            if time.time() - last_ping > 9:
                try:
                    self.ping()
                    last_ping = time.time()
                except socket.error as err:
                    logging.debug("keepalive failed %s", err)
                    break
            time.sleep(0.3)
            try:
                if addr:
                    new = self.conn.get_messages(commands=[b'addr'])
                    addrs += new
                else:
                    self.conn.get_messages()
            except socket.timeout:
                pass
            except (ProtocolError, ConnectionError, socket.error) as err:
                logging.debug("getmsg failed %s", err)
                break
        return addrs

    def ping(self):
        """
        Sends a ping message. Ping time is stored in Redis for round-trip time
        (RTT) calculation.
        """
        nonce = random.getrandbits(64)
        try:
            self.conn.ping(nonce=nonce)
        except socket.error:
            raise
        self.last_ping = time.time()
