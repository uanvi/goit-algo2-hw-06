from typing import Iterable, Dict, Any
import hashlib


class BloomFilter:
    __slots__ = ("m", "k", "_bits", "_bytes_len")

    def __init__(self, size: int, num_hashes: int):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size має бути додатним цілим числом")
        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes має бути додатним цілим числом")
        
        self.m = size
        self.k = num_hashes
        self._bytes_len = (self.m + 7) // 8
        self._bits = bytearray(self._bytes_len)

    def _set_bit(self, idx: int) -> None:
        byte_i = idx >> 3
        bit_i = idx & 7
        self._bits[byte_i] |= (1 << bit_i)

    def _get_bit(self, idx: int) -> bool:
        byte_i = idx >> 3
        bit_i = idx & 7
        return bool(self._bits[byte_i] & (1 << bit_i))

    def _hashes(self, item_str: str):
        b = item_str.encode("utf-8", errors="ignore")
        h1 = int.from_bytes(hashlib.sha256(b"seed1" + b).digest(), "big")
        h2 = int.from_bytes(hashlib.sha256(b"seed2" + b).digest(), "big")
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, item: str) -> None:
        if not isinstance(item, str) or item == "":
            return
        for idx in self._hashes(item):
            self._set_bit(idx)

    def __contains__(self, item: str) -> bool:
        if not isinstance(item, str) or item == "":
            return False
        return all(self._get_bit(idx) for idx in self._hashes(item))

    def might_contain(self, item: str) -> bool:
        return item in self


def check_password_uniqueness(bloom: BloomFilter, passwords: Iterable[Any]) -> Dict[Any, str]:
    results: Dict[Any, str] = {}
    for pwd in passwords:
        if not isinstance(pwd, str) or pwd == "":
            results[pwd] = "некоректне значення"
            continue
        
        if bloom.might_contain(pwd):
            results[pwd] = "вже використаний"
        else:
            results[pwd] = "унікальний"
            bloom.add(pwd)
    
    return results


if __name__ == "__main__":
    bloom = BloomFilter(size=1000, num_hashes=3)
    
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)
    
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)
    
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")
