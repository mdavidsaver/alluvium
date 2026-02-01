# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3

import binascii
import logging
import struct
import socket
import sys
import time
from functools import wraps
from binascii import hexlify
import multiprocessing as MP

try:
    from os import isatty
except ImportError:
    def isatty(_fd):
        return False

from .client import SPIClient, Dest
from .xbit import XBit, maybe_bit
from .progress import Progress

if isatty(sys.stdout.fileno()):
    def HL(s: str) -> str:
        return f'\033[35;1m{s}\033[0m'
else:
    def HL(s: str) -> str:
        return s

_log = logging.getLogger(__name__)

def print_hex(inp: bytes):
    off = 0
    while len(inp):
        print(f'{off:02x} {binascii.hexlify(inp[:16])}', end=None)
        off += 16
        inp = inp[16:]

def raw_spi(cli: SPIClient, args):
    repls = cli.tr(args.op)
    for inp, out in zip(args.op, repls):
        print(f'-> {binascii.hexlify(inp)}')
        print(f'<- {binascii.hexlify(out)}')

_manu = {
    1: 'Infineon',
}

_family = {
    0x80: 'FL-S',
}

_sector_arch = {
    0: 'Uniform',
    1: '4KB param sect. w/ uniform 64KB',
}

_num_erase_regions = {
    1: '(1) Uniform',
    2: '(2) Boot',
}

_cfi_iface = {
    '\x00\x00': 'x8',
    '\x01\x00': 'x16',
    '\x02\x00': 'x8/x16',
    '\x03\x00': 'x32',
    '\x02\x01': 'Multi I/O, 3/4 byte addr',
    # ...
}

def _pow_2_n(b):
    if isinstance(b, bytes):
        b, = struct.unpack('<H', b)
    return 2**b

def _erase_region(b: bytes):
    #lower, upper = struct.unpack('<HH', b)
    #return f'{lower} -> {upper}'
    nsect, sectsz = struct.unpack('<HH', b)
    nsect = nsect+1 # 0 -> 1 sector, 0x1f -> 32 sectors
    sectsz *= 256
    return f'{nsect}x {sectsz} b'

# [("label", addr|slice, func(int|bytes) -> Any)]
_cfi_info = [
    ('Manu', 0x00, lambda b: _manu.get(b)),
    ('SArc', 0x04, lambda b: _sector_arch.get(b)),
    ('Faml', 0x05, lambda b: _family.get(b)),
    ('Modl', slice(0x06, 0x08), lambda b: b),
    ('Size', 0x27, lambda b: f'{2**b} b'),
    ('IF  ', slice(0x28, 0x2a), lambda b: _cfi_iface.get(b)),
    ('PGSz', slice(0x2a, 0x2c), _pow_2_n),
    ('#ER ', 0x2c, lambda b: _num_erase_regions.get(b)),
    ('ER1 ', slice(0x2d, 0x31), _erase_region),
    ('ER2 ', slice(0x31, 0x35), _erase_region),
    ('ER3 ', slice(0x35, 0x39), _erase_region),
    ('ER4 ', slice(0x39, 0x3d), _erase_region),
    ('ER5 ', slice(0x3d, 0x41), _erase_region),
]

def flash_info(cli: SPIClient, args):
    # read ID-CFI address space
    info, = cli.tr([b'\x9f\0\0\0\0\0'])
    info = info[1:] # ignore junk shifted with command

    # offset 3 is "number of bytes to follow" in ID-CFI
    if info[3] ==0:
        size = 512
    else:
        # for Infineon S25FL128S
        # [3] == 0x4d -> 0x50 is the last valid byte, so 0x51 is total size
        size = 0x3 + info[3] + 1

    _log.debug('ID-CFI size %d b', size)

    # LMASK limitations...
    rsize = 260

    info, = cli.tr([b'\x9f' + rsize*b'\0'])

    info = info[1:1+size] # ignore junk shifted with command
    assert len(info)==size
    print_hex(info)

    for lbl, off, render in _cfi_info:
        try:
            v = info[off]
        except IndexError:
            continue
        else:
            if v==b'':
                continue
            try:
                pretty = render(v) or v
            except Exception as e:
                _log.exception(f"Error rendering {lbl} with {v!r}")
            else:
                print(f'{lbl}: {pretty}')

_sr1 = [
    'SRWD  ',
    'P_ERR ',
    'E_ERR ',
    'BP2   ',
    'BP1   ',
    'BP0   ',
    'WEL   ',
    'WIP   ',
]
_sr2 = [
    None,
    None,
    None,
    None,
    None,
    None,
    'ES   ',
    'PS   ',
]
_cr1 = [
    'LC1   ',
    'LC0   ',
    'TBPROT',
    'DNU',
    'BPNV  ',
    'TBPARM',
    'QUAD  ',
    'FREEZE',
]

def flash_status(cli: SPIClient, args):
    # TODO: check for Infineon.  (how common to other vendors?)
    sr1, sr2, cr1 = cli.tr([b'\x05\0', b'\x07\0', b'\x35\0'])

    sr1, sr2, cr1 = sr1[1], sr2[1], cr1[1]
    for lbl, bits, val in (
        ('SR1', _sr1, sr1),
        ('SR2', _sr2, sr2),
        ('CR1', _cr1, cr1),
        ):
        cur = []
        bval = list(f'{val:08b}') # 0x14 -> ['0', '0', '0', '1', '0', '1', '0', '0']
        for bt, bl in zip(bval, bits):
            if bl is None:
                continue
            elif bt=='1':
                cur.append(HL(bl.upper()))
            else:
                cur.append(bl.lower())
        cur = ', '.join(cur)
        print(f'{lbl} 0b{val:08b} [{cur}]')

def flash_clear_status(cli: SPIClient, args):
    print('Before')
    flash_status(cli, args)
    cli.tr([b'\x30', b'\x04']) # CLSR, WRDI
    print('After')
    flash_status(cli, args)

def flash_setup(cli: SPIClient, args):
    sr1, cr1 = args.sr1, args.cr1

    if args.marble_init:
        if sr1 is not None or cr1 is not None:
            sys.error('--marble-init may not be used with --sr1 or --cr1')
            sys.exit(1)
        # SRWD - Prevent CR1/SR1 when WP# pulled down
        # BP2 | BP1 - Write protect half of address space
        sr1 = 0b10011000 # SRWD | BP2 | BR1
        # TBPARM - move 4kb sectors to top (high) addreses
        # TBPROT - apply Block Protect from bottom (low) addresses
        cr1 = 0b00100100 # TBPROT | TBPARM

    cmd = struct.pack('BB', 0x01, sr1)
    if cr1 is not None:
        if not args.yes:
            print('Warning: CR1 includes one-time programmable bits.  Re-run with --yes if you really want to write')
            sys.exit(1)
        cmd = cmd + struct.pack('B', cr1)

    print('Before')
    flash_status(cli, args)
    cli.tr([b'\x06', cmd])
    print('After')
    flash_status(cli, args)

def flash_reset(cli: SPIClient, args):
    cli.tr([b'0xf0'])

def flash_read(cli: SPIClient, args):
    base, count, out = args.base, args.size, args.file

    if args.space=='otp':
        assert base<1024 and base+count<=1024

    elif count=='bit':
        with cli.open('rb') as FF:
            FF.seek(base)
            XB = XBit.parse(FF)
            count = XB.file_size
            _log.info('Found %d bytes : %s', count, XB.design)

    end = base + count - 1

    out = open(out, 'wb') if out and out!='-' else sys.stdout.buffer

    _log.debug('Will read [0x%08x, 0x%08x]', base, end)

    # last read will be longer than necessary.
    rsize = 256 # conform to LMASK limitation

    with Progress(base+count) as progress:
        for start in range(base, base+count, rsize):
            addr = struct.pack('>I', start)
            if args.space=='otp':
                cmd = b'\x4b' + addr[1:] + b'\0'
            elif addr[0]==0:
                cmd = b'\x03' + addr[1:]
            else:
                cmd = b'\x13' + addr

            val, = cli.tr([cmd + rsize*b'\0'])
            val = val[len(cmd):][:count]

            out.write(val)
            count -= len(val)

            progress.update(start+rsize)

    out.close()

    sys.stderr.write(f'Read complete {cli.dest}\r\n')

def flash_verify(cli: SPIClient, args):
    base, count, inp = args.base, args.size, args.file
    inp = maybe_bit(open(inp, 'rb') if inp and inp!='-' else sys.stdin.buffer)

    if count is None:
        inp.seek(0, 2) # jump to end
        count = inp.tell()
        inp.seek(0, 0) # jump to start

    end = base + count - 1

    cmd = b'\x13' if end>0xffffff else b'\x03' # assume 4 byte address support for > 16MB access

    # last read will be longer than necessary.
    rsize = 256 # conform to LMASK limitation

    ok = True

    with Progress(base+count) as progress:
        for start in range(base, base+count, rsize):

            ref = inp.read(rsize)
            if not len(ref):
                break

            addr = struct.pack('>I', start)
            if cmd==b'\x03':
                assert addr[0]==0
                addr = addr[1:]

            act, = cli.tr([cmd + addr + rsize*b'\0'])
            act = act[len(cmd)+len(addr):][:len(ref)]

            if ref!=act:
                print(' mis-match!', file=sys.stderr)
                print('-', hexlify(ref))
                print('+', hexlify(act))
                ok = False

            progress.update(start+rsize)

    inp.close()

    if not ok:
        print('Fail')
        sys.exit(1)
    else:
        print('Match')

def handleBP(func):
    """Ensure previous errors are cleared and handle --force
    """
    @wraps(func)
    def wrapper(cli: SPIClient, args):
        sr1, = cli.tr([b'\x05\x00'])
        if sr1[1]&0b01100000:
            _log.error('Clear previous error and retry. (0x%02x)', sr1[1])
            sys.exit(1)
        bpmask = 0b00011100
        bp = sr1[1]&bpmask
        if args.force and bp!=0:
            _log.info('Disable Block Protection.  0x%02x', bp)
            orig = sr1[1]
            _wren, _wrr, sr1 = cli.tr([b'\x06', struct.pack('>BB', 1, orig&~bpmask), b'\x05\x00'])
            if sr1[1]&bpmask:
                raise RuntimeError('Unable to disable Block Protection.  Check WP#  (%02x)', sr1[1])

        try:
            return func(cli, args)
        finally:
             if args.force and bp!=0:
                _log.info('Restore Block Protection.  0x%02x', bp)
                sr1, = cli.tr([b'\x05\x00'])
                sr1 = (sr1[1]&~bpmask) | bp
                _wren, _wrr, sr1 = cli.tr([b'\x06', struct.pack('>BB', 1, sr1), b'\x05\x00'])
                _log.info('Restored Block Protection')

    return wrapper

@handleBP
def flash_bulk_erase(cli: SPIClient, args):
    _wren, _be, sr1 = cli.tr([b'\x06', b'\x60', b'\x05\x00'])
    if sr1[1]&0b01100000:
        flash_status(cli, args)
        _log.error("Erase fails!")
        sys.exit(1)

    while sr1[1]&1: # WIP
        time.sleep(0.001)
        sr1, = cli.tr([b'\x05\x00'])

    print('Erased')

@handleBP
def flash_erase(cli: SPIClient, args):
    # probe sector geometry

    # LMASK limitations...
    rsize = 260
    info, = cli.tr([b'\x9f' + rsize*b'\0'])
    info = info[1:]

    cr1, = cli.tr([b'\x35\x00'])
    cr1 = cr1[1]

    # sanity check
    assert info[0x10:0x13]==b'QRY'
    # may be catch violation of assumptions about erase geometry
    assert (info[0x00], info[0x05])==(0x01, 0x80) # Infineon, FL-S

    size = 2**info[0x27]
    assert size==16*2**20, size
    nregions = info[0x2c]
    _log.debug('Found %d regions', nregions)

    sizes = []

    for n in range(0x2d, 0x2d+ 4*nregions, 4):
        nsect, sectsz = struct.unpack('<HH', info[n:n+4])
        _log.debug('Region %d x %d', nsect+1, sectsz*256)
        sizes += (nsect+1)*[sectsz*256]

    assert sum(sizes)==size, (sum(sizes), size)

    if cr1&4: # TBPARM
        sizes.reverse()

    geo = []
    addr = 0
    for sz in sizes:
        geo.append((addr, sz))
        addr += sz
    assert addr==size

    base, count = args.base, args.size
    _log.debug('Request erase [%08x, %08x)', base, base+count)

    # erase all regions overlapping with requested range
    #
    # |--1--|--2--|--3--|--4--|--5--| addr[n] -> addr[n]+sz[n]
    #       |-----------|             base    -> base+count
    #          |-----------|          base    -> base+count
    #             |-----------|       base    -> base+count
    #  non-overlapping regions
    # 1 - addr[1]+sz[1] <= base
    # 5 - addr[5]       >= base+count
    #
    # not (addr+sz <= base or addr>= base+count)
    # == addr+sz > base and addr<base+count
    todo = [(addr, sz) for addr, sz in geo if addr+sz > base and addr<base+count]

    with Progress(todo[-1][0]) as progress:
        for addr, sz in todo:
            progress.update(addr)

            addr = struct.pack('>I', addr)
            if addr[0]==0:
                addr = addr[1:]
                if sz==4096:
                    cmd = b'\x20'
                else:
                    cmd = b'\xd8'
            else:
                if sz==4096:
                    cmd = b'\x21'
                else:
                    cmd = b'\xdc'

            cmds = [b'\x06', cmd + addr, b'\x05\x00']
            if args.no_act:
                print(cmds)
                sr1 = b'\0\0'
            else:
                _wren, _erase, sr1 = cli.tr([b'\x06', cmd + addr, b'\x05\x00'])

            if sr1[1]&0b01100000:
                flash_status(cli, args)
                _log.error("Erase fails!")
                sys.exit(1)

            while sr1[1]&1: # WIP
                time.sleep(0.001)
                sr1, = cli.tr([b'\x05\x00'])

    sys.stdout.write(f'Erase complete {cli.dest}\n')

@handleBP
def flash_program(cli: SPIClient, args):
    base, file = args.base, args.file

    psize = 256

    fp = maybe_bit(open(file, 'rb'))

    fp.seek(0, 2) # jump to end
    args.size = size = fp.tell()
    fp.seek(0, 0)

    if not args.no_erase:
        flash_erase(cli, args)

    with Progress(base+size) as progress:
        while size:
            sys.stdout.write(f'\r{base:08x}')
            cnt = psize - base%psize # byte to write to this page

            inp = fp.read(cnt)
            if not inp:
                break
            cnt = len(inp)
            pad = b'\xff'*(psize-cnt) # must pad due to LMASK limitation

            addr = struct.pack('>I', base)
            if addr[0]==0:
                cmd = b''.join([b'\x02', addr[1:], inp, pad])
            else:
                cmd = b''.join([b'\x12', addr, inp, pad])

            if args.no_act:
                print(cmd)
                sr1 = b'\0\0'
            else:
                _wren, _pp, sr1 = cli.tr([b'\x06', cmd, b'\x05\x00'])

            if sr1[1]&0b01100000:
                flash_status(cli, args)
                raise RuntimeError("Program fails!")

            while sr1[1]&1: # WIP
                time.sleep(0.001)
                sr1, = cli.tr([b'\x05\x00'])

            base += cnt
            size -= cnt
            progress.update(base)

    sys.stdout.write(f'Programming complete {cli.dest}\n')

    if not args.no_verify:
        flash_verify(cli, args)

def xilinx_reboot(cli: SPIClient, args):
    if args.method=='xc7':
        conf = [
            # dummy and sync
            0xffffffff,
            0xffffffff,
            0xaa995566,
            0x20000000, # no-op
            0x30020001, # Write address to WBSTAR
            args.base,
            0x30008001, # Write IPROG command to CMD
            0x0000000F,
        ]
        # pad with no-op
        conf = conf + [0x20000000]*(64-len(conf))
        conf = b''.join([struct.pack('>I', w) for w in conf])
        assert len(conf)==256

    elif args.method=='spartan6':
        assert (args.base&0x00ffffff)==args.base
        conf = [
            0xffff,
            0xffff,
            0xffff,
            0xaa99, # sync_H
            0x5566, # sync_L
            0x3261, # write gen1
            args.base&0xffff, # appl lower
            0x3281, # write gen2
            0x0300 | (args.base>>24), # 03 | appl upper
            0x32a1, # write gen3
            0x0000, # golden lower
            0x32c1, # write gen4
            0x0300, # 03 | golden lower
            0x30a1, # write CMD
            0x000e, # IPROG
        ]
        conf = conf + [0x2000]*(128-len(conf))
        conf = b''.join([struct.pack('>H', w) for w in conf])
        assert len(conf)==256

    else:
        raise ValueError(f'Method {args.method} not supported')

    try:
        repl, = cli.tr([conf], dest=Dest.ICAPE2)
    except socket.timeout:
        _log.info('No reply.  Presume booting...')
    else:
        _log.error('Reply. %r', repl)
        _log.error('Presume not booting???')
        sys.exit(1)

def peers(s: str) -> [(str, int)]:
    from argparse import ArgumentError
    ret = []
    # first see if arg is file containing list of endpoints
    try:
        with open(s, 'r') as F:
            for line in F:
                line = line.strip()
                if line[:1] in ('' or '#'):
                    continue
                ret.append(peer(line))
        return ret

    except FileNotFoundError:
        # look for comma seperated list of endpoints
        ret = [peer(ep) for ep in s.split(',')]

    if len(ret)==0:
        raise ArgumentError(None, 'destination list must include at least one peer')

    unique = set(ret)
    if len(unique)!=len(ret):
        raise ArgumentError(None, 'destination list must not contain duplicates')

    return ret

def peer(s: str) -> (str, int):
    host, _sep, port = s.partition(':')
    return (host, int(port or '804'))

def getargs():
    def human_number(s: str) -> int:
        units = {
            'K': 1024,
            'M': 1024*1024,
        }
        unit = s[-1].upper()
        if unit in units:
            s = s[:-1]
        val = int(s, 0)
        return val * (units.get(unit) or 1)

    def human_number_address(s: str):
        if s=='gold':
            return 0
        elif s=='app':
            return 0x800000
        else:
            return human_number(s)

    def human_number_size(s: str):
        if s!='bit':
            s = human_number(s)
        return s

    from argparse import ArgumentParser, FileType
    P = ArgumentParser()
    P.add_argument('-v', '--verbose', action='store_const', const=logging.DEBUG,
                   dest='level', default=logging.INFO,
                   help='Make more noise')
    P.add_argument('-q', '--quiet', action='store_const', const=logging.WARNING,
                   dest='level',
                   help='Make less noise')
    P.add_argument('dest', type=peers,
                   help='''Device host/IP : port.  eg. "devfoo" or "myhost:804".
A comma seperated list of the same, or the name of a file containing lines of the same format.
''')

    SP = P.add_subparsers()

    S = SP.add_parser('spi', help='Raw SPI transactions.  "%(prog)s spi 9000 9f0000"')
    S.add_argument('op', nargs='+',
                   type=binascii.unhexlify,
                   help='Byte string in hex format.  eg. "1234" -> b"\x12\x34"')
    S.set_defaults(func=raw_spi)

    S = SP.add_parser('info', help='Query CFI info')
    S.set_defaults(func=flash_info)

    S = SP.add_parser('status', help='Query Flash status')
    S.set_defaults(func=flash_status)

    S = SP.add_parser('clear', help='Clear Flash status')
    S.set_defaults(func=flash_clear_status)

    S = SP.add_parser('setup', help='Set SR1 and CR1')
    S.add_argument('--sr1', type=lambda v: int(v, 0))
    S.add_argument('--cr1', type=lambda v: int(v, 0))
    S.add_argument('--marble-init', action='store_true',
                   help='Burn OTP fuses to configure Marble address map and protection')
    S.add_argument('-y', '--yes', action='store_true', default=False)
    S.set_defaults(func=flash_setup)

    S = SP.add_parser('reset', help='SW Reset Flash')
    S.set_defaults(func=flash_reset)

    S = SP.add_parser('read', help='Read Flash')
    S.add_argument('base', type=human_number_address,
                   help='Base address (bytes)  eg. "1024" or "4M" or "0x800"')
    S.add_argument('size', type=human_number_size,
                   help='Size (bytes), or "bit" to attempt to read as xilinx bit file')
    S.add_argument('-f', '--file', default='-',
                   help='Read into file instead of stdout')
    S.add_argument('--otp', action='store_const', const='otp',
                   dest='space', default='mem',
                   help='Read out OTP space instead of memory')
    S.set_defaults(func=flash_read)

    S = SP.add_parser('verify', help='Compare contents with file')
    S.add_argument('base', type=human_number_address,
                   help='Base address (bytes)  eg. "1024" or "4M" or "0x800"')
    S.add_argument('-S', '--size', type=human_number,
                   help='Size (bytes)')
    S.add_argument('file',
                   help='Read from file instead of stdin')
    S.set_defaults(func=flash_verify)

    S = SP.add_parser('wipe', help='Bulk/mass Erase entire flash')
    S.add_argument('-f', '--force', action='store_true',
                   help='Override Block Protect')
    S.set_defaults(func=flash_bulk_erase)

    S = SP.add_parser('erase', help='Erase some/all of flash')
    S.add_argument('base', type=human_number_address,
                   help='Base address (bytes)  eg. "1024" or "4M" or "0x800"')
    S.add_argument('size', type=human_number,
                   help='Size (bytes)')
    S.add_argument('-f', '--force', action='store_true',
                   help='Override Block Protect')
    S.add_argument('-n', '--no-act', action='store_true', default=False,
                   help='Do not actually erase')
    S.set_defaults(func=flash_erase)

    S = SP.add_parser('program', help='Write flash')
    S.add_argument('base', type=human_number_address,
                   help='Base address (bytes)  eg. "1024" or "4M" or "0x800"')
    S.add_argument('file',
                   help='Read from file instead of stdin')
    S.add_argument('-f', '--force', action='store_true',
                   help='Override Block Protect')
    S.add_argument('-n', '--no-act', action='store_true', default=False,
                   help='Do not actually erase')
    S.add_argument('--no-erase', action='store_true', default=False,
                   help='Do not erase before programming')
    S.add_argument('--no-verify', action='store_true', default=False,
                   help='Skip verification after programming')
    S.set_defaults(func=flash_program)

    S = SP.add_parser('reboot', help='Command FPGA to reboot')
    S.add_argument('base', type=human_number_address,
                   help='Flash address of .bit file')
    S.add_argument('--method', metavar='NAME', default='xc7',
                   help='Reboot method: xc7 or spartan6')
    S.add_argument('-7', dest='method',
                   action='store_const', const='xc7',
                   help='Shorthand for: --method xc7')
    S.set_defaults(func=xilinx_reboot)

    return P

def wrapper(name, dest, args):
    # lookup by name to avoid pickle limitations
    action = globals()[name]
    # configure in child process
    logging.basicConfig(level=args.level)

    with SPIClient(dest) as cli:
        action(cli, args)

def main():
    MP.set_start_method('spawn')
    P = getargs()
    args = P.parse_args()
    logging.basicConfig(level=args.level)

    try:
        action = args.func
    except AttributeError:
        P.print_usage()
        sys.exit(1)

    procs = []
    for dest in args.dest:
        P = MP.Process(target=wrapper, args=(action.__name__, dest, args))
        procs.append((dest, P))
        P.start()

    fails = []
    for dest, P in procs:
        try:
            P.join()
            if P.exitcode==0:
                continue
        except:
            _log.exception('join %s', dest)
        fails.append((dest, P.exitcode))

    if fails:
        print('Operations failed for:')
        for (addr, port), code in fails:
            print(f' {code} {addr}:{port}')
        sys.exit(1)
