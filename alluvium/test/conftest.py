# See included COPYRIGHT and LICENSE files
# SPDX-License-Identifier: GPL-3

import asyncio
import threading
import struct

import pytest

from ..sim import BSPI, FlashDev
from ..client import SPIClient

@pytest.fixture
def bspi():
    dest = [None]
    ready = threading.Event()
    done = asyncio.Event()
    loop = asyncio.new_event_loop()

    dev = FlashDev()

    async def run_sim():
        try:
            bus = BSPI()
            bus._dev = dev
            loop = asyncio.get_running_loop()
            TR, _bus = await loop.create_datagram_endpoint(lambda: bus, ('127.0.0.1', 0))
            dest[0] = TR.get_extra_info('sockname')
        finally:
            ready.set()
        await done.wait()

    worker = threading.Thread(target=loop.run_until_complete, args=(run_sim(),))
    worker.start()

    ready.wait()

    cli = SPIClient(ep=dest[0])
    cli._mem = dev

    try:
        yield cli

    finally:
        loop.call_soon_threadsafe(done.set)
        worker.join()
