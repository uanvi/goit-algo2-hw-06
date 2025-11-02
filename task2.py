import json
import time
import hashlib
import math
from typing import Iterable


def iter_ips_from_log(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                ip = obj.get("remote_addr")
                if ip:
                    yield ip
            except Exception:
                continue


def exact_unique_count(path: str) -> int:
    return len(set(iter_ips_from_log(path)))


class HyperLogLog:
    def __init__(self, p: int = 14):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m

    def _hash(self, value: str) -> int:
        h = hashlib.sha1(value.encode()).digest()
        return int.from_bytes(h[:8], "big")

    def _rho(self, w: int, max_bits: int) -> int:
        if w == 0:
            return max_bits + 1
        rank = 1
        for i in range(max_bits - 1, -1, -1):
            if (w >> i) & 1:
                break
            rank += 1
        return rank

    def add(self, value: str) -> None:
        x = self._hash(value)
        idx = x >> (64 - self.p)
        w = x & ((1 << (64 - self.p)) - 1)
        rank = self._rho(w, 64 - self.p)
        self.registers[idx] = max(self.registers[idx], rank)

    def count(self) -> float:
        alpha = 0.7213 / (1 + 1.079 / self.m)
        raw = alpha * self.m * self.m / sum(2 ** -r for r in self.registers)
        
        zeros = self.registers.count(0)
        if raw <= 2.5 * self.m and zeros > 0:
            return self.m * math.log(self.m / zeros)
        
        return raw


def hll_unique_count(path: str, p: int = 14) -> float:
    hll = HyperLogLog(p)
    for ip in iter_ips_from_log(path):
        hll.add(ip)
    return hll.count()


if __name__ == "__main__":
    path = "lms-stage-access.log"
    
    t0 = time.perf_counter()
    exact = exact_unique_count(path)
    exact_time = time.perf_counter() - t0
    
    t0 = time.perf_counter()
    hll = hll_unique_count(path)
    hll_time = time.perf_counter() - t0
    
    print("Результати порівняння:")
    print(f"{'':25} {'Точний підрахунок':>20} {'HyperLogLog':>15}")
    print(f"{'Унікальні елементи':25} {exact:>20.0f} {hll:>15.0f}")
    print(f"{'Час виконання (сек.)':25} {exact_time:>20.4f} {hll_time:>15.4f}")