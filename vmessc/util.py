from typing import Optional


def get_super_domain(domain: str) -> Optional[str]:
    pos = domain.find(".")
    if pos > 0:
        return domain[pos + 1 :]


def fnv32a(buf: bytes) -> bytes:
    hval = 0x811C9DC5
    fnv_32_prime = 0x01000193
    for ch in buf:
        hval = ((hval ^ ch) * fnv_32_prime) & 0xFFFFFFFF
    return hval.to_bytes(4, "big")
