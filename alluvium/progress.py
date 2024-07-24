import time
import sys

class Progress:
    def __init__(self, limit:int, fd=sys.stderr):
        self._last, self.limit, self._fd = 0, limit, fd
        self.T0 = None
    def __enter__(self):
        self.T0 = time.monotonic()
        #self._fd.write('\n')
        return self
    def __exit__(self,A,B,C):
        self._fd.write(f'\r {self._last:08x}/{self.limit:08x}\n')

    def update(self, v:int):
        self._last = v
        T = time.monotonic()
        dT = T - self.T0
        if dT<0.1:
            return

        self._fd.write(f'\r {v:08x}/{self.limit:08x}')
