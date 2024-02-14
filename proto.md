# Packet Badget SPI protocol

UDP packets on port 804

Request response.

First byte of all requests is 0x52.

First byte of all replies is 0x51

## Theory of Operation.

The spi_flash_engine FPGA logic maintains a pair of buffers (TX and RX).
The client first writes a sequence of commands into the TX buffer.
The engine then steps through these commands, shifting data with the SPI bus.
Result data is placed into the corresponding locations in the RX buffer.

The client can poll the run/busy status, and the contents of the RX buffer.

### Example

```
-> Sendto
<- Recvfrom

# Shift JEDEC SPI flash ID commmand (0x9f), followed by 5 zeros
-> b"\x52\x01\x06\x9f\x00\x00\x00\x00\x00"

# Reply with Busy status.
<- b'\x51\x03\xff\xff\x01\x42\xff\xff\xff'

# Read/Poll
-> b'\x52\x00\x00\x00\x00\x00\x00\x00\x00'

# Reply with Done status.
<- b'\x51\x01\xff\xff\x01\x42\x18\x42\x01'
```

Here the result of shifting `b"\x9f\x00\x00\x00\x00\x00"`
is `b"\xff\x01\x42\x18\x42\x01"`.

Multiple SPI transactions can be batched into a single Request.

## Request / Write

Transaction request.  aka. write to SPI engine memory.

0x52 0x01 ... 0xab 0xXX ...

To begin a SPI transaction, send 0x52 followed by 0x01 (write),
then a variable number of transaction.

Each transaction is preceeded by a command/length byte,
followed by a variable number of data bytes.

### Command/length byte

```
0bA000BBBB
  |   \---- Encoded length
  \--------- ~CE ???
```

The command/length byte encodes a 9-bit length in the lower 4 bits.
So only lengths with bit 0b100000111 set can be encoded (max. 263).

|-----+-------------+--------+
| Len | Len base_2  | Encode |
|-----+-------------+--------+
| 1   | 0b000000001 | 0b0001 |
| 4   | 0b000000100 | 0b0100 |
| 6   | 0b000000110 | 0b0110 |
| 260 | 0b100000100 | 0b1100 |
| 263 | 0b100000111 | 0b1111 |
|-----+-------------+--------+

eg. the command byte 0x0f should be followed by 263 data bytes.

## Request / Read

Upon receiving a Busy reply, send a message beginning with
"\x52\x00", followed by zero padding to the same size
as the Request/Write message.

## Reply / Busy

In reply to a Request or Read message.  SPI engine busy.

Begins with `b"\x51\x03".  Subsequent bytes should be ignored.

Client should send another Read.

## Reply / Done

In reply to a Request or Read message.  Operations complete.
Ready for next Write.

Begins with `b"\x51\x01".  Subsequent bytes are data corresponding
to the original Write.

