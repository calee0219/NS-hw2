#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Security Homework 2
Author: calee, alan, yian
Date: 2020/06/13
"""

import sys
import os

import xmltodict


def usage():
    """usage: Helper function about how to gen training matrix"""
    print("usage: python3 data.py train_folder")


def load_xml(path):
    """Load data from xml file"""
    with open(path, 'r') as reader:
        xml_data = xmltodict.parse(reader.read())
    return xml_data


def main():
    """main function"""
    if len(sys.argv) != 2:
        usage()
        return
    folder_path = str(sys.argv[1])
    print("Training data folder: ", folder_path)
    subfolder = os.listdir(folder_path)
    sysmon = []
    for person in subfolder:
        # Sysmon
        sysmon_dict = load_xml(os.path.join(folder_path, person, "Sysmon.xml"))
        sysmon.append(sysmon_dict)

    # Write sysmon data into sysmon_data.py
    with open("./sysmon_data.py", 'w') as writer:
        writer.write("sysmon_matrix = ")
        writer.write(str(sysmon))
        writer.close()


if __name__ == "__main__":
    main()
