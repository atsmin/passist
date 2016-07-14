# -*- coding:utf-8 -*-
import argparse
from getpass import getpass
from string import ascii_lowercase, ascii_uppercase, printable
import random
import os
from contextlib import contextmanager

from simplecrypt import encrypt, decrypt


def iter_password(length=8, num_of_numbers=2, num_of_uppers=2, num_of_symbols=1):
    numbers = list(map(str, range(0, 10)))
    uppers = list(ascii_uppercase)
    lowers = list(ascii_lowercase)
    symbols = list(printable[62:94])  # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    num_of_lowers = length - num_of_numbers - num_of_uppers - num_of_symbols
    while True:
        random.shuffle(numbers)
        random.shuffle(uppers)
        random.shuffle(lowers)
        random.shuffle(symbols)
        p = numbers[:num_of_numbers] + \
            uppers[:num_of_uppers] + \
            lowers[:num_of_lowers] + \
            symbols[:num_of_symbols]
        random.shuffle(p)
        yield ''.join(p)


class Passist:
    def __init__(self, salt, filename):
        self.salt = salt
        self.filename = filename

    def read_encrypted(self, string=True):
        if not os.path.isfile(self.filename):
            return '{}'

        with open(self.filename, 'rb') as input:
            ciphertext = input.read()
            plaintext = decrypt(self.salt, ciphertext)
            if string:
                return plaintext.decode('utf8')
            else:
                return plaintext

    def write_encrypted(self, plaintext):
        with open(self.filename, 'wb') as output:
            ciphertext = encrypt(self.salt, plaintext)
            output.write(ciphertext)

    @contextmanager
    def readwrite(self, name):
        passwords = eval(self.read_encrypted())
        new_password = next(iter_password())
        yield (passwords, new_password)
        self.write_encrypted(str(passwords))

    def show(self, name):
        passwords = eval(self.read_encrypted())
        if isinstance(name, str):
            return passwords[name]
        else:
            return passwords

    def add(self, name):
        with self.readwrite(name) as (passwords, new_password):
            passwords.update({name: new_password})
        return {name: new_password}

    def update(self, name):
        with self.readwrite(name) as (passwords, new_password):
            passwords[name] = new_password
        return {name: new_password}

    def delete(self, name):
        with self.readwrite(name) as (passwords, new_password):
            del passwords[name]
        return passwords


def main():
    parser = argparse.ArgumentParser(prog='passist.py')
    parser.add_argument('-s', '--show', nargs='?', const=True)
    parser.add_argument('-a', '--add', nargs=1)
    parser.add_argument('-u', '--update', nargs=1)
    parser.add_argument('-d', '--delete', nargs=1)
    args = parser.parse_args()

    salt = getpass("passist password: ")
    filename = './.p'

    passist = Passist(salt, filename)
    if args.show:
        print(passist.show(args.show))
    elif args.add:
        print(passist.add(args.add))
        print('New password added!')
    elif args.update:
        print(passist.update(args.update))
        print('Password updated!')
    elif args.delete:
        print(passist.delete(args.delete))
        print('Password deleted!')


if __name__ == '__main__':
    main()
