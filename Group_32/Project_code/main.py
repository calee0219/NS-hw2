#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Security Homework 2"""

import sys
import os
import json

import xml.etree.ElementTree as ET
import xmltodict
#import numpy as np


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


def main():
    """main function"""
    if len(sys.argv) != 2:
        usage()
        return
    folder_path = str(sys.argv[1])
    print("Testing folder: ", folder_path)
    wireshark_data = load_json(os.path.join(folder_path, "Wireshark.json"))
    sysmon_data = load_xml(os.path.join(folder_path, "Sysmon.xml"))
    security_data = load_xml(os.path.join(folder_path, "Security.xml"))
    #print(wireshark_data)
    print(sysmon_data)
    #print(security_data)


if __name__ == "__main__":
    main()
