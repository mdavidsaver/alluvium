# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3

import logging
import asyncio
import signal
import struct
import sys
from enum import IntEnum
from pathlib import Path
from struct import unpack
from random import randbytes

_log = logging.getLogger(__name__)

RDID =  b"\x01 \x18M\x01\x80R0\x80\xff\xff\xff\xff\xff\xff\xffQRY\x02\x00@\x00SFQ\x00'6\x00\x00\x06\x08\x08\x0f\x02\x02\x03\x03\x18\x02\x01\x08\x00\x02\x1f\x00\x10\x00\xfd\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffPRI13!\x02\x01\x00\x08\x00\x01\x03\x00\x00\x07\x01ALT20\x00\x10S25FL128SAG??IR0\x80\x01\xf0\x84\x08\x85(\x8adu(zd\x88\x04\n\x01\x00\x01\x8c\x06\x96\x01#\x00#\x00\x90V\x06\x0eFC\x03\x13\x0b\x0c;<kl\xbb\xbc\xeb\xec2\x03\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x02\x01P\x00\xff\xff\x00\x08\x00\x08\x00\x08\x04\x00\x02\x04Z\x01\xff\xff\x00\x08\x00\x08\x00\x08\x04\x01\x02\x04h\x02\xff\xff\x00\x08\x00\x08\x00\x08\x04\x02\x02\x05\x85\x02\xff\xff\x00\x08\xff\xff\xff\xff\xff\xff\xff\xff\x94\x01\x10\x98\x01\x00\x9a*\x05\x08FC\r\x0e\xbd\xbe\xed\xee2\x03\x04\x01\x02\x02\x01\x03B\x00\x04\x02\x02\x04\x01\x06B\x01\x04\x04\x02\x05\x01"

class Cmd(IntEnum):
    WRR   = 0x01
    PP    = 0x02
    READ  = 0x03
    WRDI  = 0x04
    RDSR1 = 0x05
    WREN  = 0x06
    RDSR2 = 0x07
    PP4   = 0x08
    READ4 = 0x13
    P4E   = 0x20
    P4E4  = 0x21
    CLSR  = 0x30
    RDCR  = 0x35
    OTPR  = 0x4b
    BE    = 0x60
    REMS  = 0x90
    RDID  = 0x9f
    RES   = 0xab # aka. release from power down
    BE_ALT= 0xc7
    SE    = 0xd8
    SE4   = 0xdc

BPmap = {n:(2**(17+n)&~0x3ffff) for n in range(8)}

class FlashDev:
    capacity: int = 0x1000000
    mem: bytearray = bytearray(b'\xff'*16*2**20)
    otp: bytearray = bytearray(b'\xff'*1024)

    def __init__(self):
        self._sr1 = 0
        self._sr2 = 0
        self._cr1 = 0
        self._wp_n = True # WP# True permits writes

        self.otp[:5] = b'hello'

        self._recompute_geometry()

    def _recompute_geometry(self):
        # emulate mixed geometry.  also encoded in RDID blob
        sizes = [4096]*32 + [65536]*254

        if self._cr1&4: # TBPARM
            sizes.reverse()

        self._geo = geo = []
        addr = 0
        for sz in sizes:
            geo.append((addr, sz))
            addr += sz

        assert addr==16*2**20

    def addr2page(self, addr:int) -> (int, int, bool): # (start, count, writable)

        for base, sz in self._geo:
            if addr>=base and addr<base+sz:
                break
        else:
            raise ValueError(f"can't map 0x{addr:x} to a page")

        tbprot = self._cr1&0
        bp = (self._sr1 & 0b11100) >> 2
        bound = BPmap[bp]

        if self._cr1&0b00100000: # from bottom
            _log.debug('BP %d bound up to %08x', bp, bound)
            wr = base+sz > bound
        else: # from top
            bound = len(self.mem)-bound
            _log.debug('BP %d bound down to %08x', bp, bound)
            wr = base < bound

        return (base, sz, wr)

    def shift(self, inp:bytes) -> bytes:
        _log.debug('SIM -> %r', inp)
        cmd, inp = inp[0], inp[1:]

        try:
            cmd = Cmd(cmd)
        except ValueError:
            _log.error('Ignore unimplemented 0x%02x', cmd)
            return b'\xff'*len(inp)

        if cmd==Cmd.RES:
            return b'\x17'*len(inp)

        elif cmd==Cmd.RDSR1:
            sr1 = self._sr1
            self._sr1 &= ~1 # simulate write completion on first poll
            return bytes([sr1])*len(inp)
        elif cmd==Cmd.RDSR2:
            return bytes([self._sr2])*len(inp)
        elif cmd==Cmd.RDCR:
            return bytes([self._cr1])*len(inp)

        elif cmd==Cmd.WRR:
            if (self._sr1&0x2)==0:
                self._sr1 |= 0b00100000 # docs say set P_ERR or E_ERR, we set P_ERR
                raise RuntimeError("Must WREN befor WRR")

            self._sr1 &= ~2

            if len(inp) not in (1, 2):
                raise RuntimeError("WRR invalid length")

            elif not self._wp_n and self._sr1&0x80:
                _log.warning('WRR prohibited')

            elif (self._cr1&2)!=0 and len(inp)==1:
                raise RuntimeError("CR1[QUAD] prevents WRR to SR1 only")

            else:
                if len(inp) in (1, 2):
                    prev = self._sr1
                    sr1 = inp[0]
                    rw_mask = 0b10011110
                    sr1 &= rw_mask # only allow writable to be set
                    self._sr1 &= ~rw_mask # clear all writable
                    self._sr1 |= sr1
                    _log.info('SR1 %02x -> %02x -> %02x', prev, inp[0], self._sr1)
                if len(inp)==2:
                    prev = self._cr1
                    cr1 = inp[1]
                    if cr1&0x10:
                        _log.warning('Setting CR1[DNU] ?!?')
                    otp_mask = 0b01111000 # can't allow to clear
                    self._cr1 &= ~otp_mask
                    self._cr1 |= cr1
                    _log.info('CR1 %02x -> %02x -> %02x', prev, inp[1], self._cr1)

                    self._recompute_geometry()

                # TODO: set WIP

            return b'\xff'*len(inp)

        elif cmd==Cmd.WREN:
            if len(inp)==0:
                self._sr1 |= 2
                _log.info('Write enable')
            else:
                _log.error('WREN too long')
            return b'\xff'*len(inp)

        elif cmd==Cmd.WRDI:
            if len(inp)==0:
                self._sr1 &= ~2
                _log.info('Write disable')
            else:
                _log.error('WRDI too long')
            return b'\xff'*len(inp)

        elif cmd==Cmd.CLSR:
            self._sr1 &= ~0b01100000
            _log.info('Clear Status')
            return b'\xff'*len(inp)

        elif cmd==Cmd.RDID:
            return RDID[:len(inp)]

        elif cmd in (Cmd.BE, Cmd.BE_ALT):
            if len(inp):
                raise RuntimeError('Bulk Erase accepts no data')

            elif (self._sr1&0x2)==0:
                self._sr1 |= 0b01000000
                raise RuntimeError("Must WREN before BE")

            elif (self._sr1&0b11100)!=0:
                self._sr1 |= 0b01000000
                raise RuntimeError("BP prevents BE")

            _log.info('Bulk Erase!')
            self.mem = '\xff'*len(self.mem)
            # TODO: set WIP

            return b''

        repl = b''

        # extract address
        if cmd in (Cmd.READ, Cmd.P4E, Cmd.SE, Cmd.REMS, Cmd.PP, Cmd.OTPR): # 3 byte address
            addr, = unpack('>I', b'\0' + inp[0:3])
            inp = inp[3:]
            repl = b'\xff'*3

        elif cmd in (Cmd.READ4, Cmd.P4E4, Cmd.SE4, Cmd.PP4): # 4 byte address
            addr, = unpack('>I', inp[:4])
            inp = inp[4:]
            repl = b'\xff'*4

        if cmd in (Cmd.OTPR,): # "fast" read skip dummy
            inp = inp[1:]
            repl = repl + b'\xff'

        if cmd==Cmd.REMS: # addr is not really an addr...
            addr &= 1
            ret = b'\x01\x17' * (1+ (len(inp)//2))
            ret = ret[addr:]
            return repl+ret[:len(inp)]

        if cmd in (Cmd.READ, Cmd.READ4): # mem read
            cnt = len(inp)
            assert addr+cnt <= len(self.mem) # wrapping not implemented...
            return repl + self.mem[addr:addr+cnt]

        if cmd==Cmd.OTPR:
            return repl + self.otp[addr:addr+len(inp)]

        # lookup erase sector info, and mutability
        base, size, writable = self.addr2page(addr)

        if cmd in (Cmd.P4E, Cmd.P4E4, Cmd.SE, Cmd.SE4):
            if (self._sr1&0x2)==0:
                self._sr1 |= 0b01000000
                raise RuntimeError("Must WREN before erase")

            self._sr1 &= ~2

            if not writable:
                self._sr1 |= 0b00100000
                _log.error('Prohibited %r erase from %08x', cmd, addr)

            elif base!=addr:
                self._sr1 |= 0b00100000
                _log.error('Unaligned %r erase from %08x', cmd, addr)

            elif (cmd in (Cmd.P4E, Cmd.P4E4) and size==4096) or \
                 (cmd in (Cmd.SE, Cmd.SE4)   and size==65536):
                _log.info('%r erase %08x %08x', cmd, base, size)
                self.mem[base:base+size] = b'\xff'*size
                # TODO: set WIP
                self._sr1 |= 1

            else:
                self._sr1 |= 0b00100000
                _log.error('Incorrect size %r erase %08x', cmd, addr)

            return repl + b'\xff'*len(inp)

        elif cmd in (Cmd.PP, Cmd.PP4):
            size = 256
            base = addr&~(size-1)
            # use writable of erase sector

            if (self._sr1&0x2)==0:
                self._sr1 |= 0b01000000
                raise RuntimeError("Must WREN before program")

            self._sr1 &= ~2

            if not writable:
                self._sr1 |= 0b01000000
                _log.error('Prohibited %r program from %08x', cmd, addr)

            else:
                _log.info('%r program %08x, %08x, %08x', cmd, addr, base, size)
                # doc. says unaligned write supported,
                # but attempt to write past page boundary wraps

                assert addr-base <= size, (addr, base, size)
                for i,v in enumerate(inp, addr-base):
                    idx = base + (i%size)
                    v &= self.mem[idx] # program can only clear bits
                    self.mem[idx] = v

            return repl + b'\xff'*len(inp)

        raise NotImplementedError()

    def icape(self, inp:bytes) -> bytes:
        """Xilinx Internal Configuration Access Port access
        """

        assert len(inp)%4==0 # expect a series of 4-byte words
        assert inp[:12]==b'\xff\xff\xff\xff\xff\xff\xff\xff\xaa\x99\x55\x66', inp[:12]

        prog = [struct.unpack('>I', inp[i:i+4])[0] for i in range(0, len(inp), 4)]
        assert prog[:3]==[0xffffffff, 0xffffffff, 0xaa995566]
        prog = prog[3:]

        while len(prog):
            inst = prog.pop(0)
            itype = (inst&0xe0000000)>>29
            opcode = (inst&0x18000000)>>27
            if itype==1: # Type 1, register op.
                reg =    (inst&0x0003e000)>>13
                cnt =    (inst&0x000003ff)>>0
                _log.info('OP=%d REG=%d CNT=%d', opcode, reg, cnt)

            elif itype==2: # Type 2, extra data for preceeding Type 1
                reg = None
                cnt =    (inst&0x07ffffff)>>0
                _log.info('OP=%d ... CNT=%d', opcode, cnt)

            else:
                raise ValueError(f'Invalid instruction 0x{inst:08x}')

            for _i in range(cnt):
                _log.info('  %08x', prog.pop(0))

        return b'\xa0'*(len(inp)-1) # never busy??

class Finger(asyncio.Protocol):
    _dev: FlashDev
    _tr: asyncio.ReadTransport
    def connection_made(self, tr):
        self._tr = tr

    def data_received(self, chs: bytes):
        if b'?' in chs or b'h' in chs:
            print('enter "w\\n" or "r\\n" to assert or clear WP#')
        elif b'r' in chs:
            self._dev._wp_n = False
            print('Clear WP# (SRWD enforced)')
        elif b'w' in chs:
            self._dev._wp_n = True
            print('Assert WP# (SRWD ignored)')

    def eof_received(self):
        pass

class BSPI(asyncio.DatagramProtocol):
    _dev: FlashDev
    _tr: asyncio.DatagramTransport
    def __init__(self):
        self._rx = None
        self.busy = False

    def connection_made(self, tr):
        self._tr = tr

    def connection_lost(self, exc):
        self._tr = None
        if exc:
            _log.error('UDP Lost %r', exc)

    def datagram_received(self, inp:bytes, addr):
        try:
            if inp[0]!=0x52:
                _log.error("Ignore unknown {inp[:10]!r}")
                return

            _log.debug('RX %r from %r', inp, addr)

            sts = 3
            rx = None

            if (inp[1]&1): # start new transaction
                if self.busy:
                    _log.error('Collision with pending transaction!')
                    self.busy = False
                    self._rx = False

                repl = []

                # process commands
                cmds = inp[2:]
                while len(cmds):
                    CL = cmds[0]
                    if CL&0b01110000:
                        _log.warning("Use of unimplemented command/length bits 0x%02x", CL)
                    dest = CL&0b10000000
                    L = (CL&0x08)<<5 | (CL&7)
                    CMD = cmds[1:1+L]
                    if len(CMD)!=L:
                        _log.error("Truncated command %r", cmds[:1+L])
                    cmds = cmds[1+L:]

                    repl.append(randbytes(2)) # in place of length and command.  client should ignore

                    try:
                        if CL&0b10000000:
                            REPL = self._dev.icape(CMD)
                        else:
                            REPL = self._dev.shift(CMD)
                        assert len(CMD)==len(REPL)+1, (CMD, REPL)
                        repl.append(REPL)
                    except:
                        _log.exception('Error handling %r', CMD)
                        repl.append(b'\xff'*len(CMD))

                self._rx = b''.join(repl)
                del repl
                self.busy = len(self._rx)

                # fall through to reply with junk

            elif (inp[1]&1)==0 and self.busy:
                sts = 1
                rx, self._rx = self._rx, None
                self.busy = False

            if rx is None or sts!=1:
                rx = randbytes(len(inp)-2) # client should ignore...

            reply = bytes([0x51, sts]) + rx
            _log.debug('TX %r', reply)
            self._tr.sendto(reply, addr)
        except:
            _log.exception('oops')

    def error_received(self, exc):
        _log.error('UDP TX Error %r', exc)

def getargs():
    def store_arg(s: str) -> (int, Path):
        loc, _sep, path = s.partition('=')
        loc = int(loc, 0)
        return (loc, Path(path))

    from . import peer
    from argparse import ArgumentParser
    P = ArgumentParser()
    P.add_argument('-v', '--verbose', action='store_const', const=logging.DEBUG,
                   dest='level', default=logging.INFO,
                   help='Make more noise')
    P.add_argument('-q', '--quiet', action='store_const', const=logging.WARNING,
                   dest='level',
                   help='Make less noise')
    P.add_argument('-B', '--bind', type=peer, default=('127.0.0.1', 8804),
                   help='Listen at this endpoint address')
    P.add_argument('-M', '--mem',
                   help='Initialize memory contents from file.')
    P.add_argument('-S' ,'--store', type=store_arg, action='append', default=[],
                   metavar='#=file',
                   help='Initialize part of memory from file.  May be repeated.')
    P.add_argument('--sr1', type=lambda v: int(v, 0), default=0)
    P.add_argument('--cr1', type=lambda v: int(v, 0), default=0)
    P.add_argument('--wp_n', type=int, default=1)
    return P

async def realmain(args):
    bus = BSPI()
    bus._dev = dev = FlashDev()

    bus._dev._sr1 = args.sr1
    bus._dev._cr1 = args.cr1
    bus._dev._wp_n = args.wp_n!=0

    if args.mem:
        init = Path(args.mem).read_bytes()
        init = init[:len(dev.mem)]
        dev.mem[:len(init)] = init

    for addr, path in args.store:
        init = path.read_bytes()
        dev.mem[addr:addr+len(init)] = init

    del init

    loop = asyncio.get_running_loop()
    SOCK, _bus = await loop.create_datagram_endpoint(lambda: bus, args.bind)
    _log.info('Listen on %r', SOCK.get_extra_info('sockname'))
    assert _bus is bus

    finger = Finger()
    finger._dev = dev
    STDIN, _finger = await loop.connect_read_pipe(lambda: finger, sys.stdin)

    done = asyncio.Event()
    loop.add_signal_handler(signal.SIGINT, done.set)
    loop.add_signal_handler(signal.SIGTERM, done.set)
    await done.wait()

def main():
    args = getargs().parse_args()
    logging.basicConfig(level=args.level)
    asyncio.run(realmain(args))

if __name__=='__main__':
    main()
