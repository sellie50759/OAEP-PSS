from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256

ENCRYPT_FIRST = '0'


def decrypt(mode):
    print('start decrypt')
    print()

    # 讀取 RSA 金鑰
    publickey, privatekey = read_key('A', 'B')

    if mode == ENCRYPT_FIRST:
        message, signature = read_ciphertext(mode)
        PSS_verify(message, signature, publickey)
        plaintext = OAEP_decrypt(message, privatekey)
    else:
        pass
        '''
        message, signature = PSS_sign(plaintext, privatekey)
        ciphertext = OAEP_encrypt(message, publickey)
        encsignature = OAEP_encrypt(signature, publickey)

        # 將加密結果寫入檔案
        with open("encrypted_data.bin", "wb") as f:
            f.write(ciphertext)
            f.write(encsignature)
        '''

    # 輸出解密後的資料
    with open("text", "wb") as f:
        f.write(plaintext)

    print()
    print('end decrypt')


def read_key(pub_name, pri_name):
    pubkey = RSA.import_key(open(pub_name+"_public_key.pem", "rb").read())
    prikey = RSA.import_key(open(pri_name+"_private_key.pem", "rb").read())
    return pubkey, prikey


def read_ciphertext(mode):
    # 要加密的資料（必須為 bytes）
    if mode == ENCRYPT_FIRST:
        with open("encrypted_data.bin", "rb") as f:
            sign = f.read(256)
            message = f.read()
        return message, sign
    return None


def OAEP_decrypt(message, prikey):
    cipher = PKCS1_OAEP.new(prikey)
    ciphertext = cipher.decrypt(message)
    return ciphertext


def PSS_verify(message, signature, pubkey):
    h = SHA256.new(message)
    verifier = pss.new(pubkey)
    try:
        verifier.verify(h, signature)
    except (ValueError, TypeError):
        print("The signature is not authentic.")
        exit(-1)


if __name__ == '__main__':
    pass
