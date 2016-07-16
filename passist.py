# -*- coding:utf-8 -*-
import os
import shutil
import json
import random
import argparse
from getpass import getpass
from contextlib import contextmanager
from string import ascii_lowercase, ascii_uppercase, printable

from simplecrypt import encrypt, decrypt
import clipboard


def passiter(length=8, num_of_numbers=2, num_of_uppers=2, num_of_symbols=1):
    numbers = list(map(str, range(0, 10)))
    uppers = list(ascii_uppercase)
    lowers = list(ascii_lowercase)
    symbols = list(printable[62:94])  # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    num_of_lowers = length - num_of_numbers - num_of_uppers - num_of_symbols
    while True:
        p = random.sample(numbers, num_of_numbers) + \
            random.sample(uppers, num_of_uppers) + \
            random.sample(lowers, num_of_lowers) + \
            random.sample(symbols, num_of_symbols)
        random.shuffle(p)
        yield ''.join(p)


def as_json(func):
    def wrapper(self, *args):
        return json.dumps(
            func(self, *args), sort_keys=True, indent=4
        )
    return wrapper


def copy2clipboard(func):
    def wrapper(self, *args):
        dct = func(self, *args)
        if len(dct) == 1:
            print('Password was copyed to clipboard.')
            clipboard.copy(dct[args[0]])
        return dct
    return wrapper


class PassistExcepstion(Exception):
    pass


class Passist:
    def __init__(self, key, filename):
        self.key = key
        self.filename = filename

    def read_encrypted(self, string=True):
        if not os.path.isfile(self.filename):
            return '{}'
        with open(self.filename, 'rb') as input:
            ciphertext = input.read()
            print('decrypting...')
            plaintext = decrypt(self.key, ciphertext)
            if string:
                return plaintext.decode('utf8')
            else:
                return plaintext

    def write_encrypted(self, plaintext):
        with open(self.filename, 'wb') as output:
            print('encrypting...')
            ciphertext = encrypt(self.key, plaintext)
            output.write(ciphertext)

    @contextmanager
    def readwrite(self, name, password):
        dct = eval(self.read_encrypted())
        if not password:
            password = next(passiter())
        yield (dct, password)
        self.write_encrypted(str(dct))

    @as_json
    @copy2clipboard
    def show(self, name):
        dct = eval(self.read_encrypted())
        if isinstance(name, str):
            if name not in dct.keys():
                raise PassistExcepstion(name + ' doesn\'t exist in the keystore!')
            return {name: dct[name]}
        else:
            return dct

    @as_json
    @copy2clipboard
    def add(self, name, password):
        with self.readwrite(name, password) as (dct, password):
            if name in dct.keys():
                raise PassistExcepstion(name + ' already exists in the keystore!')
            dct[name] = password
        return {name: password}

    @as_json
    @copy2clipboard
    def update(self, name, password):
        with self.readwrite(name, password) as (dct, password):
            if name not in dct.keys():
                raise PassistExcepstion(name + ' doesn\'t exist in the keystore!')
            dct[name] = password
        return {name: password}

    @as_json
    def delete(self, name, password):
        with self.readwrite(name, password) as (dct, password):
            if name not in dct.keys():
                raise PassistExcepstion(name + ' doesn\'t exist in the keystore!')
            del dct[name]
        return dct

    def backup(self, path):
        shutil.copyfile(self.filename, path)


def main():
    parser = argparse.ArgumentParser(prog='passist.py')
    parser.add_argument('-s', '--show', nargs='?', const=True)
    parser.add_argument('-a', '--add')
    parser.add_argument('-u', '--update')
    parser.add_argument('-d', '--delete')
    parser.add_argument('-p', '--password')
    parser.add_argument('-b', '--backup', nargs=1)
    args = parser.parse_args()

    key = getpass("Passist password: ")
    filename = './.p'

    passist = Passist(key, filename)
    if args.show:
        print(passist.show(args.show))
    elif args.add:
        print(passist.add(args.add, args.password))
        print('New password added successfully.')
    elif args.update:
        print(passist.update(args.update, args.password))
        print('The password updated successfully.')
    elif args.delete:
        print(passist.delete(args.delete, args.password))
        print('The password deleted successfully.')
    elif args.backup:
        passist.backup(args.backup[0])
        print('The password file was backuped successfully.')


if __name__ == '__main__':
    main()
