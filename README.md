# CLI for Bedrock FPGA control

A CLI tool to interact with
[LBNL Bedrock SPI over UDP engine](https://github.com/BerkeleyLab/Bedrock/blob/master/badger/spi_flash_engine.v).

Also tied to S25FL128S flash chip.

## Requires

- Python >= 3.10

## Setup

```sh
git clone https://github.com/mdavidsaver/alluvium.git
cd alluvium
python3 -m alluvium -h
```

## Usage

The basic form of use is: `python3 -m alluvium <host_or_IP> <command> ...`.
The entry point provides a number of sub-commands.

```sh
$ python3 -m alluvium 192.168.19.4 status
SR1 0b10011000 [SRWD  , p_err , e_err , BP2   , BP1   , bp0   , wel   , wip   ]
SR2 0b00000000 [es   , ps   ]
CR1 0b00100100 [lc1   , lc0   , TBPROT, dnu, bpnv  , TBPARM, quad  , freeze]

$ python3 -m alluvium 192.168.79.4 info
00 b'0120184d0180523080ffffffffffffff'
10 b'51525902004000534651002736000006'
20 b'08080f020203031802010800021f0010'
30 b'00fd000001ffffffffffffffffffffff'
40 b'50524931332102010008000103000007'
50 b'01'
Manu: Infineon
SArc: 4KB param sect. w/ uniform 64KB
Faml: 128
Modl: b'R0'
Size: 16777216 b
IF  : b'\x02\x01'
PGSz: 256
#ER : (2) Boot
ER1 : 32x 4096 b
ER2 : 254x 65536 b
ER3 : 65536x 16776960 b
ER4 : 65536x 16776960 b
ER5 : 65536x 5308160 b
```

### Flash chip address and size

Addresses and sizes can be given in various forms: 8388608, 0x800000, 8M.

In addition, two special address alias names may be given: `gold` (0) and `app` (8M).
Also, the `read` command accepts the special size `bit` to read the size of a
xilinx bit file currently stored in flash.

### Reading out flash

```sh
# read out fixed size
$ python3 -m alluvium 192.168.19.4 read 8M 0x100 | hexdump -C
...

# read size from xilinx bit file header
$ python3 -m alluvium 192.168.19.4 read gold bit -f current-gold.bit
...
```

### Programming

```sh
$ python3 -m alluvium 192.168.19.4 program appl new-appl.bit
...
```

### Manipulation of "Status" and config registers

To clear the indication of a previous error

```sh
$ python3 -m alluvium 192.168.19.4 clear
...
```

```sh
# Clear SRWP and block protect
$ python3 -m alluvium localhost:8804 setup --sr1 0
...

# enable SRWD, BP2, and BP1
$ python3 -m alluvium localhost:8804 setup --sr1 0b10011000
...

# Initial setup of OTP bits.  (Caution, read the datasheet first)
$ python3 -m alluvium localhost:8804 setup --sr1 0 --cr1 0b00100100
...
```

## Batch operations

More than one device may be manipulated in parallel.
Alluvium will exit after all operations complete or timeout,
and will return with code 0 only if all operations succeed.

While the following works for all commands,
it is not useful for commands which write a output file
as that output would be corrupt.

In addition to simple host/IP address and port,
a comma seperated list of such entries may be given.

```sh
$ python3 -m alluvium 192.168.19.4,192.168.19.56 status
```

For larger numbers of devices, a file of such entires may also be given.

```sh
$ cat device.list
192.168.19.4
192.168.19.56
192.168.19.100
$ python3 -m alluvium device.list status
```

## Software Simulation

For software testing, a simulation is available.

```sh
python3 -m alluvium.sim
INFO:__main__:Listen on ('127.0.0.1', 8804)
...
```

The simulator process will repond to `"w\n"` annd `"r\n"` on stdin
to change write protect pin.

```sh
python3 -m alluvium localhost:8804 info
...
```
