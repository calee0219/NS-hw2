#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Security Homework 2"""

import numpy as np


import sys
import json


def usage():
    """usage: Helper function about how to use the program"""
    print("usage: python3 main.py log_folder")


def load_data(path):
    """Load data from json file"""
    with open(path, 'r') as reader:
        jf = json.loads(reader.read())
        return jf


def main():
    """main function"""
    if len(sys.argv) != 2:
        usage()
        return
    folder_path = str(sys.argv[1])
    print("Testing folder: ", folder_path)
    data = load_data(folder_path)
    print(data)


if __name__ == "__main__":
    main()
