# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3

import struct

from ..client import SPIClient, FlashFile
from ..sim import BSPI, FlashDev
from ..xbit import XBit

from .test_xbit import dummy_bit

def test_geo():
    dev = FlashDev()

    # from bottom
    dev._cr1 = 0

    dev._sr1 = 0 # protect none
    assert dev.addr2page(0)==(0, 4096, True)
    assert dev.addr2page(4100)==(4096, 4096, True)
    assert dev.addr2page(0x800000)==(0x800000, 65536, True)

    dev._sr1 = 0b11000 # protect half
    assert dev.addr2page(0)==(0, 4096, True)
    assert dev.addr2page(4100)==(4096, 4096, True)
    assert dev.addr2page(0x800000)==(0x800000, 65536, False)

    dev._sr1 = 0b11100 # protect all
    assert dev.addr2page(0)==(0, 4096, False)
    assert dev.addr2page(4100)==(4096, 4096, False)
    assert dev.addr2page(0x800000)==(0x800000, 65536, False)

    # from top
    dev._cr1 = 0x28 # TBPROT | TBPARAM

    dev._sr1 = 0 # protect none
    assert dev.addr2page(0)==(0, 4096, True)
    assert dev.addr2page(4100)==(4096, 4096, True)
    assert dev.addr2page(0x800000)==(0x800000, 65536, True)

    dev._sr1 = 0b11000 # protect half
    assert dev.addr2page(0)==(0, 4096, False)
    assert dev.addr2page(4100)==(4096, 4096, False)
    assert dev.addr2page(0x800000)==(0x800000, 65536, True)

    dev._sr1 = 0b11100 # protect all
    assert dev.addr2page(0)==(0, 4096, False)
    assert dev.addr2page(4100)==(4096, 4096, False)
    assert dev.addr2page(0x800000)==(0x800000, 65536, False)

def test_info(bspi: SPIClient):
    info, = bspi.tr([b'\x9f\0\0\0\0\0'])
    assert info[1:]==b'\x01 \x18M\x01'

def test_id(bspi: SPIClient):
    id0, id1 = bspi.tr([b'\x90\0\0\0\0\0', b'\x90\0\0\1\0\0'])
    assert id0[4:]==b'\x01\x17'
    assert id1[4:]==b'\x17\x01'

def test_status(bspi: SPIClient):
    bspi._mem._sr1 = 0x12
    bspi._mem._sr2 = 0x34
    bspi._mem._cr1 = 0x56

    sr1, sr2, cr1 = bspi.tr([b'\x05\0', b'\x07\0', b'\x35\0'])
    assert sr1[1]==0x12
    assert sr2[1]==0x34
    assert cr1[1]==0x56

def test_wel(bspi: SPIClient):
    bspi._mem._sr1 = 0x80
    before, _x, during, _y, after = bspi.tr([b'\x05\0', b'\x06', b'\x05\0', b'\x04', b'\x05\0'])

    assert before[1]==0x80
    assert during[1]==0x82
    assert after[1]==0x80

def test_read(bspi: SPIClient):
    M = b'hello world, this is a test'
    bspi._mem.mem[:len(M)] = M

    A, B = bspi.tr([b'\x03\x00\x00\x00\x00\x00', b'\x03\x00\x00\x06\x00\x00'])

    assert A[4:]==b'he'
    assert B[4:]==b'wo'

    C, = bspi.tr([b'\x03\x00\x00\x00' + 256*b'\0'])
    C = C[4:]
    assert C== (M + b'\xff' * (256 - len(M)))

def test_bulk_erase(bspi: SPIClient):
    mem = bspi._mem.mem
    mem[0] = 0
    mem[65535] = 0
    mem[65536] = 0

    bspi.tr([b'\x06', b'\x60'])

    assert mem[0]==0
    assert mem[65535]==0
    assert mem[65536]==0

def test_param_erase(bspi: SPIClient):
    mem = bspi._mem.mem
    mem[0] = 0
    mem[4095] = 0
    mem[4096] = 0

    bspi.tr([b'\x06', b'\x20\x00\x00\x00'])

    assert mem[0]==0xff
    assert mem[4095]==0xff
    assert mem[4096]==0

def test_sector_erase(bspi: SPIClient):
    mem = bspi._mem.mem
    mem[0x7fffff] = 0
    mem[0x800000] = 0
    mem[0x80ffff] = 0
    mem[0x810000] = 0

    bspi.tr([b'\x06', b'\xd8\x80\x00\x00'])

    assert mem[0x7fffff]==0
    assert mem[0x800000]==0xff
    assert mem[0x80ffff]==0xff
    assert mem[0x810000]==0

def test_program(bspi: SPIClient):
    mem = bspi._mem.mem

    mem[0x100] = 0x42
    mem[0x101] = 0xf0

    bspi.tr([b'\x06', b'\x02\x00\x01\x01\x33\x55'])

    assert mem[0x100:0x103]==b'\x42\x30\x55'

    D = b''.join([struct.pack('>H', v) for v in range(128)])
    assert len(D)==256

    bspi.tr([b'\x06', b'\x02\x00\x05\x00' + D])

    assert mem[0x500:0x600] == D

    bspi.tr([b'\x06', b'\x02\x00\x08\x10' + D])

    assert mem[0x810:0x900] == D[:-0x10]
    assert mem[0x800:0x810] == D[-0x10:]

def test_flashfile(bspi: SPIClient):
    bspi._mem.mem[:len(dummy_bit)] = dummy_bit

    with bspi.open('rb') as F:
        assert F.tell()==0
        assert F.read(8)==b'\x00\t\x0f\xf0\x0f\xf0\x0f\xf0'
        assert F.tell()>=8

        F.seek(0)
        assert F.tell()==0

        B = XBit.parse(F)
        assert F.tell()>=len(dummy_bit)
        assert B.size==0x2e9428
        assert B.file_size==len(dummy_bit)
