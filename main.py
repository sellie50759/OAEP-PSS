from generate_key import gen_AB_key
from decrypt import decrypt
from encrypt import encrypt
import os


def key_exist():
    key_filename_list = ['A_public_key.pem', 'B_public_key.pem', 'A_private_key.pem', 'B_private_key.pem']
    for filename in key_filename_list:
        file_abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        if not os.path.isfile(file_abs_path):
            return False
    return True


def validate(f):
    if f in ["0", "1"]:
        return True
    else:
        return False


def decryptedtext_equal_plaintext():
    with open("plaintext", 'rb') as f:
        plaintext = f.read()
    with open("text", 'rb') as f:
        decryptedtext = f.read()

    if plaintext == decryptedtext:
        return True
    else:
        return False


def main():
    if not key_exist():
        gen_AB_key()

    message = "please input your mode:\n" + \
              "0 is encrypt first\n" + \
              "1 is sign first\n"

    mode = input(message)
    while not validate(mode):
        mode = input(message)

    encrypt(mode)
    decrypt(mode)

    if decryptedtext_equal_plaintext():
        print("sign and encrypt success.")
    else:
        print("sign and encrypt fail!")


if __name__ == "__main__":
    main()

'''
reference
https://pycryptodome.readthedocs.io/en/latest/src/api.html
https://officeguide.cc/python-pycryptodome-rsa-asymmetric-encryption-tutorial-examples/
'''
