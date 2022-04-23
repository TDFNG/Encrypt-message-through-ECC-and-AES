import base64
import gc
import hashlib
import os
import pickle
import secrets

import MyAES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

try:
    Priv_K = ec.generate_private_key(ec.BrainpoolP512R1(), None)
    Publ_K = Priv_K.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    nonce_l = secrets.token_bytes(16)
    print('\n请将下方的密钥（↓）发送给对方\n')
    print(base64.urlsafe_b64encode(pickle.dumps((nonce_l, Publ_K))).decode())
    del Publ_K
    print('\n请输入对方提供的密钥\n')
    nonce_r, NPub_K = pickle.loads(base64.urlsafe_b64decode(input()))
    Share_K = Priv_K.exchange(ec.ECDH(), load_pem_public_key(NPub_K))
    del Priv_K, NPub_K
    if nonce_l < nonce_r:
        nonce_l, nonce_r = nonce_r, nonce_l
    AES_K = HKDF(
        algorithm=ec.hashes.SHA3_512(),
        length=64,
        salt=nonce_l,
        info=nonce_r,
    ).derive(Share_K)
    del Share_K, nonce_l, nonce_r
    AESkey = hashlib.sha3_512(AES_K).hexdigest()
    del AES_K
    gc.collect()
    os.system('cls')
    while 1:
        print('\n请输入内容（若是密文将自动解密，若是明文将自动加密）\n')
        message = ''
        while message == '':
            message = input()
        try:
            D_M = MyAES.jiemi(AESkey, base64.urlsafe_b64decode(message)).decode()
            os.system('cls')
            print('\n明文:\n')
            print(D_M, '\n')
            del D_M
            os.system('pause')
        except:
            E_M = base64.urlsafe_b64encode(MyAES.jiami(AESkey, message.encode())).decode()
            os.system('cls')
            print('\n加密已完成，请将下方的密文发送给对方\n')
            print(E_M, '\n')
            del E_M
            os.system('pause')
        del message
        gc.collect()
        os.system('CLS')
except:
    try:
        del AESkey
    except:
        pass
    gc.collect()
    os.system('cls')
    print('\n程序运行出错\n')
    os.system('pause')
