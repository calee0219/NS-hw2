#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Security Homework 2
Author: calee, alan, yian
Date: 2020/06/13
"""

import sys
import os
import numpy as np

import xmltodict
import sklearn
import pandas as pd
event_name = "OriginalFileName"


def usage():
    """usage: Helper function about how to gen training matrix"""
    print("usage: python3 data.py train_folder")


def load_xml(path):
    """Load data from xml file"""
    with open(path, 'r') as reader:
        xml_data = xmltodict.parse(reader.read())
    return xml_data

def collect_sysmon(sysmon):
    """Collect sysmon data"""
    feature_table = []
    feature_name = []
    tot_feature = 0
    for num in range(len(sysmon)):
        sysmon_data = sysmon[num]
        cnt = {}
        for event in sysmon_data['Events']['Event']:
            for data in event['EventData']['Data']:
                if data['@Name'] == event_name:
                    ori = data['#text']
                    if ori in cnt.keys():
                        cnt[ori] += 1
                    else:
                        cnt[ori] = 1

        feature_table.append([0 for i in range(tot_feature)])
        for key, value in cnt.items():
            try:
                feature_num = feature_name.index(key)
                feature_table[num][feature_num] = value
            except:
                feature_name.append(key)
                feature_table[num].append(value)
                tot_feature += 1
    for row in feature_table:
        row_len = len(row)
        for i in range(tot_feature-row_len):
            row.append(0)
    # Write sysmon data into sysmon_data.py
    with open("./training_data.py", 'w') as writer:
        writer.write("event_name = ")
        writer.write('"'+event_name+'"')
        writer.write("\nsysmon_feature_name = ")
        writer.write(str(feature_name))
        writer.write("\nsysmon_matrix = ")
        writer.write(str(feature_table))
        writer.close()

def collect_security(security):
    """Collect security data"""
    feature_table = []
    feature_name = []
    tot_feature = 0
    for num in range(len(security)):
        security_data = security[num]
        cnt = {}
        for event in security_data['Events']['Event']:
            feature = event['System']['EventID']
            if feature in cnt.keys():
                cnt[feature] += 1
            else:
                cnt[feature] = 1

        feature_table.append([0 for i in range(tot_feature)])
        for key, value in cnt.items():
            try:
                feature_num = feature_name.index(key)
                feature_table[num][feature_num] = value
            except:
                feature_name.append(key)
                feature_table[num].append(value)
                tot_feature += 1
    for row in feature_table:
        row_len = len(row)
        for i in range(tot_feature-row_len):
            row.append(0)
    # Write security data into security_data.py
    with open("./training_data.py", 'a') as writer:
        writer.write("\nevent_name = ")
        writer.write('"'+event_name+'"')
        writer.write("\nsecurity_feature_name = ")
        writer.write(str(feature_name))
        writer.write("\nsecurity_matrix = ")
        writer.write(str(feature_table))

def main():
    """main function"""
    if len(sys.argv) != 2:
        usage()
        return
    folder_path = str(sys.argv[1])
    print("Training data folder: ", folder_path)
    subfolder = sorted(os.listdir(folder_path))
    sysmon = []
    security = []
    for person in subfolder:
        print(person)
        # Sysmon
        sysmon_dict = load_xml(os.path.join(folder_path, person, "Sysmon.xml"))
        sysmon.append(sysmon_dict)
        security_dict = load_xml(os.path.join(folder_path, person, "Security.xml"))
        security.append(security_dict)

    #collect_sysmon(sysmon)
    collect_security(security)

if __name__ == "__main__":
    main()
