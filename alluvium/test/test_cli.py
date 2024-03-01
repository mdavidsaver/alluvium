# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3

import os

from tempfile import TemporaryDirectory
from pathlib import Path

from ..client import SPIClient
from .. import getargs
from .test_xbit import dummy_bit

def test_info(bspi: SPIClient, capsys):
    args = getargs().parse_args(['unused:804', 'info'])
    args.func(bspi, args)
    out = capsys.readouterr().out
    assert 'Size: 16777216 b' in out
    assert 'ER2 : 254x 65536 b' in out

def test_status(bspi: SPIClient, capsys):
    bspi._mem._sr1 = 0b10101001
    args = getargs().parse_args(['unused:804', 'status'])
    args.func(bspi, args)
    out = capsys.readouterr().out
    assert 'SR1 0b10101001' in out

def test_clear(bspi: SPIClient):
    bspi._mem._sr1 = 0b11111111
    args = getargs().parse_args(['unused:804', 'clear'])
    args.func(bspi, args)
    assert bspi._mem._sr1 == 0b10011100

def test_erase(bspi: SPIClient):
    addr = 0x800000
    bspi._mem.mem[addr:addr+len(dummy_bit)] = dummy_bit

    args = getargs().parse_args(['unused:804', 'erase', '8M', str(len(dummy_bit))])
    args.func(bspi, args)

    assert bspi._mem.mem[addr:addr+len(dummy_bit)] == b'\xff'*len(dummy_bit)

def test_program(bspi: SPIClient):
    addr = 0x800000
    junk = b'oops, I should be erased...'
    bspi._mem.mem[addr:addr+len(junk)] = junk

    with TemporaryDirectory() as tdir:
        inp = os.path.join(tdir, 'inp.bit')
        Path(inp).write_bytes(dummy_bit)

        args = getargs().parse_args(['unused:804', 'program', '8M', inp])
        args.func(bspi, args)

    assert bspi._mem.mem[addr:addr+len(dummy_bit)] == dummy_bit

def test_read_bit(bspi: SPIClient):
    addr = 0x800000
    bspi._mem.mem[addr:addr+len(dummy_bit)] = dummy_bit

    with TemporaryDirectory() as tdir:
        out = os.path.join(tdir, 'out.bit')
        args = getargs().parse_args(['unused:804', 'read', '8M', 'bit', '--file', out])
        args.func(bspi, args)

        inp = Path(out).read_bytes()
    assert inp==dummy_bit

def test_setup(bspi: SPIClient):
    assert bspi._mem._sr1==0
    assert bspi._mem._cr1==0

    args = getargs().parse_args(['unused:804', 'setup',
                                 '--sr1', '0b10011000',
                                 '--cr1', '0b00100100',
                                 '--yes',
                                 ])
    args.func(bspi, args)

    assert bspi._mem._sr1==0b10011000
    assert bspi._mem._cr1==0b00100100
