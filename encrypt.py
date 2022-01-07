from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256

ENCRYPT_FIRST = '0'


def encrypt(mode):
    print('start encrypt')
    print()

    plaintext = read_plaintext()

    # 讀取 RSA 公鑰
    publickey, privatekey = read_key('B', 'A')  # A的public key與B的private key

    if mode == ENCRYPT_FIRST:
        ciphertext = OAEP_encrypt(plaintext, publickey)
        message, signature = PSS_sign(ciphertext, privatekey)
        # 將加密結果寫入檔案
        with open("encrypted_data.bin", "wb") as f:
            f.write(signature)
            f.write(message)
    else:
        message, signature = PSS_sign(plaintext, privatekey)
        ciphertext = OAEP_encrypt(message, publickey)
        signature1 = OAEP_encrypt(signature[:128], publickey)
        signature2 = OAEP_encrypt(signature[128:], publickey)
        # 將加密結果寫入檔案
        with open("encrypted_data.bin", "wb") as f:
            f.write(signature1)
            f.write(signature2)
            f.write(ciphertext)

    print()
    print('end encrypt')


def read_plaintext():
    # 要加密的資料（必須為 bytes）
    with open("plaintext", "rb") as f:
        data = f.read()
    return data


def read_key(pub_name, pri_name):
    pubkey = RSA.import_key(open(pub_name+"_public_key.pem", "rb").read())
    prikey = RSA.import_key(open(pri_name+"_private_key.pem", "rb").read())
    return pubkey, prikey


def OAEP_encrypt(message, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def PSS_sign(message, prikey):
    h = SHA256.new(message)
    sign = pss.new(prikey).sign(h)
    return bytes(message), sign


if __name__ == '__main__':
    pass

