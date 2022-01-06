from Cryptodome.PublicKey import RSA


def gen_AB_key():
    print('start generate public key and private key')
    print()

    gen_key_and_save('A')
    gen_key_and_save('B')

    print()
    print('end generate public key and private key')


def gen_key_and_save(name):
    publickey, privatekey = RSA_gen_key()
    save_key(name, publickey, privatekey)


def RSA_gen_key():
    # 產生 RSA 私鑰
    prikey = RSA.generate(2048)

    # 產生 RSA 公鑰
    pubkey = prikey.public_key()

    # 儲存 RSA 公私鑰
    pubkeyPEM = pubkey.export_key('PEM')
    prikeyPEM = prikey.export_key('PEM')

    return pubkeyPEM, prikeyPEM


def save_key(name, pubkey, prikey):
    with open(name + '_public_key.pem', 'wb') as f:
        f.write(pubkey)
    with open(name + '_private_key.pem', 'wb') as f:
        f.write(prikey)


if __name__ == '__main__':
    gen_AB_key()
