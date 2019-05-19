# -*- coding: utf-8 -*-
# 15/12/26
# create by: snower

import struct
import socket
import hashlib
from protocol import Protocol,ProtocolParseEndError
import config

ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3

from xstream.crypto import ALG_KEY_IV_LEN
from xstream.crypto import rand_string
from xstream.crypto import get_evp

def EVP_BytesToKey(password, key_len, iv_len):
    m = []
    i = 0
    while len(''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = ''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    return (key, iv)

class Crypto(object):
    def __init__(self, key, alg='aes_256_cfb'):
        self._key=key.encode("utf-8") if isinstance(key, unicode) else key
        self._alg=alg

        self.iv_sent = False
        self._iv = rand_string(ALG_KEY_IV_LEN.get(self._alg)[1])
        self._encipher = self.get_cipher(1, self._iv)
        self.decipher = None

    def get_cipher(self, op, iv):
        key, _ = EVP_BytesToKey(self._key, ALG_KEY_IV_LEN.get(self._alg)[0], ALG_KEY_IV_LEN.get(self._alg)[1])
        return get_evp(self._alg, key, iv, op)

    def encrypt(self, buf):
        if self.iv_sent:
            return self._encipher.update(buf)
        else:
            self.iv_sent = True
            return self._iv + self._encipher.update(buf)

    def decrypt(self, buf):
        if self.decipher is None:
            decipher_iv_len = ALG_KEY_IV_LEN.get(self._alg)[1]
            decipher_iv = buf[:decipher_iv_len]
            self.decipher = self.get_cipher(0, decipher_iv)
            buf = buf[decipher_iv_len:]
            if len(buf) == 0:
                return buf
        return self.decipher.update(buf)

class SSProtocol(Protocol):
    def __init__(self, *args, **kwargs):
        super(SSProtocol, self).__init__(*args, **kwargs)

        self._crypto = Crypto(config.SSKEY, config.SSMETHOD.replace("-", "_"))

    def parse_header(self, data):
        addrtype = ord(data[0])
        if addrtype == ADDRTYPE_IPV4:
            if len(data) >= 7:
                dest_addr = socket.inet_ntoa(data[1:5])
                dest_port = struct.unpack('>H', data[5:7])[0]
                header_length = 7
            else:
                raise Exception('header is too short')
        elif addrtype == ADDRTYPE_HOST:
            if len(data) > 2:
                addrlen = ord(data[1])
                if len(data) >= 2 + addrlen:
                    dest_addr = data[2:2 + addrlen]
                    dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                              addrlen])[0]
                    header_length = 4 + addrlen
                else:
                    raise Exception('header is too short')
            else:
                raise Exception('header is too short')
        elif addrtype == ADDRTYPE_IPV6:
            if len(data) >= 19:
                dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
                dest_port = struct.unpack('>H', data[17:19])[0]
                header_length = 19
            else:
                raise Exception('header is too short')
        else:
            raise Exception('unsupported addrtype %d, maybe wrong password' %
                         addrtype)
        if dest_addr is None:
            return None
        return addrtype, dest_addr, dest_port, header_length

    def parse(self, data):
        data = self._crypto.decrypt(data)
        _, self.remote_addr, self.remote_port, header_length = self.parse_header(data)
        raise ProtocolParseEndError(data[header_length:])

    def unpack_udp(self, data):
        crypto = Crypto(config.SSKEY, config.SSMETHOD.replace("-", "_"))
        data = crypto.decrypt(data)
        addr_type = ord(data[0])
        if addr_type == 1:
            remote_addr = socket.inet_ntoa(data[1:5])
            remote_port = data[5:7]
            header_length = 7
        elif addr_type == 4:
            remote_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            remote_port = data[17:19]
            header_length = 19
        elif addr_type == 3:
            addr_len = ord(data[1])
            remote_addr = data[2:2 + addr_len]
            remote_port = data[2 + addr_len:2 + addr_len + 2]
            header_length = 2 + addr_len + 2
        else:
            raise Exception(data)
        remote_port, = struct.unpack('>H', remote_port)
        return remote_addr, remote_port, data[header_length:]

    def pack_udp(self, remote_addr, remote_port, data):
        crypto = Crypto(config.SSKEY, config.SSMETHOD.replace("-", "_"))
        data = "".join([struct.pack(">B", 1), socket.inet_aton(remote_addr), struct.pack(">H", remote_port), data])
        return crypto.encrypt(data)