# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3

from io import BytesIO

from ..xbit import XBit

dummy_bit = b'\x00\t\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01a\x008TEST_BIT;COMPRESS=TRUE;UserID=0XFFFFFFFF;Version=2023.1\x00b\x00\r7k160tffg676\x00c\x00\x0b2024/01/29\x00d\x00\t15:56:10\x00e\x00.\x94(' + 0x2e9428*b'\0'
assert len(dummy_bit)==3052703

def test_decode():
    F = BytesIO(dummy_bit)
    x = XBit.parse(F)

    assert x.design==b'TEST_BIT;COMPRESS=TRUE;UserID=0XFFFFFFFF;Version=2023.1'
    assert x.part==b'7k160tffg676'
    assert x.date==b'2024/01/29'
    assert x.time==b'15:56:10'
    assert x.size==0x2e9428
    assert x.file_size==len(dummy_bit)
    assert F.tell()==len(dummy_bit)

    F = BytesIO(dummy_bit + b'\xff\xff\xff\xff\xff')
    x = XBit.parse(F)

    assert x.time==b'15:56:10'
    assert x.size==0x2e9428
    assert x.file_size==len(dummy_bit)
