import pickle
import secrets
from hashlib import blake2b

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def jiami(password: str, data: bytes):
    try:
        pd = blake2b(password.encode(), digest_size=32, usedforsecurity=True).digest()
        rand = [secrets.token_bytes(8), secrets.token_bytes(8)]
        obj = AESGCM(pd)
        return pickle.dumps((rand, obj.encrypt(rand[0], data, rand[1])))
    except:
        return False


def jiemi(password: str, data: bytes):
    try:
        pd = blake2b(password.encode(), digest_size=32, usedforsecurity=True).digest()
        rand, edata = pickle.loads(data)
        obj = AESGCM(pd)
        return obj.decrypt(rand[0], edata, rand[1])
    except:
        return False
