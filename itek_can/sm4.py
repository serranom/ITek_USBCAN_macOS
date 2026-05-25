from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

AUTH_KEY = b"itekon2012usbcan"


def sm4_encrypt_ecb(plaintext: bytes, key: bytes = AUTH_KEY) -> bytes:
    sm4 = CryptSM4()
    sm4.set_key(key, SM4_ENCRYPT)
    return sm4.crypt_ecb(plaintext)
