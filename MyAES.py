import secrets
from hashlib import blake2b

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def jiami(password: str, data: bytes):
    try:
        pd = blake2b(password.encode(), digest_size=32, usedforsecurity=True).digest()
        rand = [secrets.token_bytes(8), secrets.token_bytes(8)]
        obj = AESGCM(pd)
        return rand[0] + rand[1] + obj.encrypt(rand[0], data, rand[1])
    except:
        return False


def jiemi(password: str, data: bytes):
    try:
        pd = blake2b(password.encode(), digest_size=32, usedforsecurity=True).digest()
        obj = AESGCM(pd)
        return obj.decrypt(data[:8], data[16:], data[8:16])
    except:
        return False
