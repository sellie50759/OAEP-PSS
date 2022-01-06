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


if __name__ == "__main__":
    if not key_exist():
        gen_AB_key()
    mode = input("please input your mode:\n" +
                 "0 is encrypt first\n" +
                 "1 is sign first\n")

    while not validate(mode):
        mode = input("please input your mode:\n" +
                     "0 is encrypt first\n" +
                     "1 is sign first\n")
    encrypt(mode)
    decrypt(mode)

'''
reference
https://pycryptodome.readthedocs.io/en/latest/src/api.html
https://officeguide.cc/python-pycryptodome-rsa-asymmetric-encryption-tutorial-examples/
'''