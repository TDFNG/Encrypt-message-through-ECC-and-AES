from hashlib import blake2b

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def jiami(password: str, data: bytes):
    try:
        pd = blake2b(password.encode(), digest_size=32, usedforsecurity=True).digest()
        aad = blake2b(password.encode(), digest_size=16, usedforsecurity=True).digest()
        nonce = blake2b(password.encode(), digest_size=12, usedforsecurity=True).digest()
        obj = AESGCM(pd)
        return obj.encrypt(nonce, data, aad)
    except:
        return False


def jiemi(password: str, data: bytes):
    try:
        pd = blake2b(password.encode(), digest_size=32, usedforsecurity=True).digest()
        aad = blake2b(password.encode(), digest_size=16, usedforsecurity=True).digest()
        nonce = blake2b(password.encode(), digest_size=12, usedforsecurity=True).digest()
        obj = AESGCM(pd)
        return obj.decrypt(nonce, data, aad)
    except:
        return False
