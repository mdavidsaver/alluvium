# Notes on flash chip configuration on Marble

The S25FL128S datasheet __warns__ that one time programable (OTP) bits in `CR1`
must __not__ be burned/set after any erase or program commands has been executed!

So `CR1[TBPARM]` and `CR1[TBPROT]` must only be set during bring-up of
a new device.

## Write protection

The S25FL128S flash chip on the LBNL [Marble](https://github.com/BerkeleyLab/Marble)
has several complex write protection mechanisms.

Out of the box, the `WP#` pin has no effect.

As configured (by setting `SR1[SRWD]`) the `WP#` pin inhibits the Write Registers (WRR) SPI command.

When permitted, the WRR command may be used to set/clear the three Block Protect bits (`SR[BP#]`).

The `BP[2-0]` bits act to inhibit writes to some fraction of the flash address space
(`0b000` -> 0%, `0b110` -> 50%, `0b111` -> 100%).

By default, the fraction of the flash address space effected by Block Protect beings
with the top/high addresses.  eg. `BP[2-0]=0b110` protects `0x800000 -> 0xffffff`.

This may be flipped by burning the one time programable `CR1[TBPROT]`.
If done, then `BP[2-0]=0b110` instead protects `0x000000 -> 0x7fffff`.

## 4KB sector location

The erase geometry of S25FL128S has two different sector sizes.
Some 4KB and others 64KB.

By default the sectors are laid out with the 4KB sectors at the bottom/low addresses: 32x 4096, then 254x 65536.

This may be flipped by burning the one time programable `CR1[TBPARM]`
to move the 4KB regions to the top/high addresses: 254x 65536, 32x 4096.

## Marble Golden / Application images

The logic behind setting CR1[TBPROT]` is that a bootloader or fallback or "golden"
bit file can be placed in the lower half of the flash chip.
An application bit file can then be placed in the uppser half.

Setting `SR1[SRWD | BP2 | BP1]`, and pulling down `WP#`, prevents the
lower half of the flash from being modified.

The "golden" bit file would then need to provide a means to cause the FPGA
to reboot with a bit stream loaded from a different location.

`CR1[TBPARM]` is also set to allow an application bit file use of
the smaller regions for non-volatile configuration.
