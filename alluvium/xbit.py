# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3
"""
Xilinx bit file header parser
"""

import logging

from dataclasses import dataclass
from struct import unpack

_log = logging.getLogger(__name__)

# http://www.fpga-faq.com/FAQ_Pages/0026_Tell_me_about_bit_files.htm
# treat initial
_prefix = b'\x00\x09\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00' + b'\x00\x01\x61'

def xbit_size(inp: bytes) -> int:
    """Read .bit header
    """

# Tags with 2 byte length
_bits2 = {
    0x62: 'part',
    0x63: 'date',
    0x64: 'time',
}

@dataclass
class XBit:
    design: str = None
    part: str = None
    date: str = None
    time: str = None
    size: int = None # bit stream length
    file_size: int = None # total length of header and all TLV

    @classmethod
    def parse(klass, inp: 'io.RawIOBase') -> 'XBit':
        ret = klass()

        start = inp.tell()

        # first part consists of LLLL VV...
        # treat first two as fixed
        pref = inp.read(len(_prefix))
        if pref!=_prefix:
            raise RuntimeError(f'Malformed .bit header {pref!r}')

        # design name
        L, = unpack('>H', inp.read(2))
        ret.design = inp.read(L).rstrip(b'\0')

        # now tag, length, value.  With variable tag lengths (ick...)
        while True:
            T = inp.read(1)
            if not T:
                ret.file_size = inp.tell() - start
                break # EoF
            T = T[0]

            if T==0xff: # EoF in flash
                ret.file_size = inp.tell() - start -1
                break

            elif T in _bits2:
                L, = unpack('>H', inp.read(2))
                V = inp.read(L).rstrip(b'\0')
                setattr(ret, _bits2[T], V)

            elif T==0x65: # actual config payload has has 4 byte length
                L, = unpack('>I', inp.read(4))
                ret.size = L
                A = inp.tell()
                inp.seek(L, 1) # skip forward...
                B = inp.tell()
                if B-A!=L:
                    raise RuntimeError('Truncated configuration stream')

            else:
                raise RuntimeError(f'Unknown bit file tag 0x{T:02x}')

        return ret

def getargs():
    from argparse import ArgumentParser, FileType
    P = ArgumentParser()
    P.add_argument('bit', type=FileType('rb'))
    return P

def main():
    logging.basicConfig(level=logging.INFO)
    args = getargs().parse_args()

    X = XBit.parse(args.bit)

    print(X)

if __name__=='__main__':
    main()
