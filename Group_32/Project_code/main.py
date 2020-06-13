#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Security Homework 2"""

import sys
import os
import json

#import xml.etree.ElementTree as ET
import xmltodict
import collections
orderedDict = collections.OrderedDict()
from collections import OrderedDict
#import numpy as np

from sysmon_data import *


def usage():
    """usage: Helper function about how to use the program"""
    print("usage: python3 main.py log_folder")


def load_json(path):
    """Load data from json file"""
    with open(path, 'r') as reader:
        json_data = json.loads(reader.read())
        return json_data


def load_xml(path):
    """Load data from xml file"""
    #tree = ET.parse(path)
    #xml_data = tree.getroot()
    with open(path, 'r') as reader:
        xml_data = xmltodict.parse(reader.read())
    return xml_data


def load_training_data():
    """Load training data"""
    #print(sysmon_matrix)


def main():
    """main function"""
    if len(sys.argv) != 2:
        usage()
        return
    folder_path = str(sys.argv[1])
    print("Testing folder: ", folder_path)
    subfolder = os.listdir(folder_path)
    for testcase in subfolder:
        print("{index}: ".format(index=testcase), end="")
        wireshark_data = load_json(os.path.join(folder_path, testcase, "Wireshark.json"))
        sysmon_data = load_xml(os.path.join(folder_path, testcase, "Sysmon.xml"))
        security_data = load_xml(os.path.join(folder_path, testcase, "Security.xml"))
        #print(wireshark_data)
        #print(sysmon_data)
        #print(security_data)
        print(end="\n")
    # Load Training data
    load_training_data()


if __name__ == "__main__":
    main()
