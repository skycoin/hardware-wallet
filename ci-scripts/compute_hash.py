#!/usr/bin/env python
import hashlib
import binascii
import argparse


def calculate_binary_hash(path):
    with open(path, "rb") as f:
        binary = f.read()
        hex_hash = hashlib.sha256(binary).hexdigest()
        return "".join(['\\x' + hex_hash[i:i + 2] for i in range(0, len(hex_hash), 2)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Commandline tool for calculating hash of binary file")
    parser.add_argument("-f", "--file", dest='path', help="Path to binary", required=True)
    print(calculate_binary_hash(parser.parse_args().path))
