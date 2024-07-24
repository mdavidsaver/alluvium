# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3

import io
import logging
import struct
import socket
import time
from enum import IntEnum

_log = logging.getLogger(__name__)

# weird hardware alert!
# sub-command "length" byte actually only encodes length in the lower nibble.
# these 4 bites map into a 9 bit length
LMASK = 0b100000111
# in the actual transaction length.  eg. 0b00001101 -> 0b100000101 = 261

# Note: the high bit (7) in the "length" selects SPI (clear) or
# ICAPE2 (set) on xc7 series.
class Dest(IntEnum):
    SPI    = 0x00
    ICAPE2 = 0x80

class SPIClient:
    def __init__(self, ep=(None, None), timeout=1.0):
        self.timeout = timeout
        host, port = ep
        self.host = host or '127.0.0.1'
        self.port = port or 804

        self.S = socket.socket(socket.AF_INET,
                               socket.SOCK_DGRAM)
        self.S.connect((self.host, self.port))
        self.S.settimeout(0.5)
        _log.debug('UDP "connect" to %s:%d', self.host, self.port)

        if self.timeout>0:
            self.S.settimeout(self.timeout)

    def close(self):
        self.S.close()

    def __enter__(self):
        return self
    def __exit__(self,A,B,C):
        self.close()

    @property
    def dest(self):
        return f'{self.host}:{self.port}'

    def tr(self, ops: [bytes], dest=Dest.SPI) -> [bytes]:
        """operate([b'\x90\x00\x00', b'\x9f\x00']) -> [b'\xff\xff\x15', b'\xff\x15']

           SPI bus transactions
        """
        # offset of first byte in reply
        off = 2
        # slice objects for each op into request or reply body
        repl_slices : [slice] = []
        reqs : [bytes] = []
        for op in ops:
            L = len(op)
            if (L&LMASK)!=L:
                raise ValueError(f"Operation len {L} can not be represented.")
            L = (L&256)>>5 | (L&7) # see LMASK comment above.
            off += 1 # skip past byte count
            msg = bytes((dest|L,)) + op
            repl_slices.append(slice(off, off+len(op)))
            off += len(op)
            reqs.append(msg)

        # actual initiate request
        req = b'\x52\x01' + b''.join(reqs)
        # poll for completion
        poke= b'\x52\x00' + b'\0'*(len(req)-2)
        assert len(req)==off, (off, req)

        _log.debug('REQ  -> %r', req)
        self.S.send(req)

        T0 = time.monotonic()
        while True:
            if self.timeout>0 and (time.monotonic() - T0)>=self.timeout:
                raise TimeoutError('Timeout waiting for completion')

            repl = self.S.recv(len(req))
            _log.debug('RECV <- %r', repl)
            if len(repl)!=len(req) or repl[0]!=0x51:
                _log.warning('Ignore malformed reply: %r', repl)
                continue

            sts = repl[1]
            if sts==3: # incomplete?  must poll for completion?
                time.sleep(0.001) # Zzzzzz
                _log.debug('POKE -> %r', poke)
                self.S.send(poke)

            elif sts==1: # done?
                _log.debug('Done')
                break

            else:
                raise RuntimeError(f'Unsupported reply status {sts} : {repl!r}')

        return [repl[sl] for sl in repl_slices]

    def open(self, mode='rb'):
        raw = FlashFile(self, mode)
        if mode=='rb':
            return io.BufferedReader(raw, buffer_size=4096)
        else:
            raise ValueError(f'Unsupported mode={mode}')

class FlashFile(io.RawIOBase):
    def __init__(self, cli: SPIClient, mode: str, capacity=16*1024*1024):
        super().__init__()
        self._mode, self._cli, self._pos, self._cap = mode, cli, 0, capacity

    def seekable(self):
        return True

    def seek(self, pos: int, whence: int=0):
        if whence==0:
            pass
        elif whence==1:
            pos = self._pos + pos
        elif whence==2:
            pos = self._cap + pos
        self._pos = pos = min(pos, self._cap)
        return pos

    def readable(self):
        return 'r' in self._mode

    def readinto(self, buf: bytearray):
        start, count = self._pos, min(len(buf), self._cap - self._pos)

        rsize = 256
        for i in range(0, count, rsize):
            n = min(rsize, count-i)

            addr = struct.pack('>I', start+i)
            if addr[0]==0:
                cmd = b''.join([b'\x03', addr[1:], b'\0'*rsize])
                skip = 4
            else:
                cmd = b''.join([b'\x13', addr, b'\0'*rsize])
                skip = 5

            repl, = self._cli.tr([cmd])
            inp = repl[skip:skip+n]
            assert len(inp)==n, (len(inp), n)
            buf[i:i+n] = inp

        self._pos += count
        return count
