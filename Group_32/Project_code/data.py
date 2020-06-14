#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Security Homework 2
Author: calee, alan, yian
Date: 2020/06/13
"""

import sys
import os
import json
import numpy as np

import xmltodict
import sklearn
import pandas as pd
event_name = "OriginalFileName"
security_name = "EventID"


def usage():
    """usage: Helper function about how to gen training matrix"""
    print("usage: python3 data.py train_folder")


def load_json(path):
    """Load data from json file"""
    json_str = ""
    with open(path, 'rb') as reader:
        for line in reader:
            line_str= str(line.decode('utf-8', errors="ignore"))
            json_str += line_str
        #    print(line_str, end='')
        json_data = json.loads(json_str)
        #print(json_data)
        return json_data


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
        writer.write("\nsecurity_name = ")
        writer.write('"'+security_name+'"')
        writer.write("\nsecurity_feature_name = ")
        writer.write(str(feature_name))
        writer.write("\nsecurity_matrix = ")
        writer.write(str(feature_table))


def collect_wireshark(wireshark):
    feature_table = []
    feature_name = []
    tot_feature = 0
    for num in range(len(wireshark)):
        cnt = {}
        wireshark_data = wireshark[num]
        for packet in wireshark_data:
            layer = packet['_source']['layers']
            try:
                feature = layer['ip']['ip.dst']
                if feature in cnt.keys():
                    cnt[feature] += 1
                else:
                    cnt[feature] = 1
            except:
                if "jizz" in cnt.keys():
                    cnt["jizz"] += 1
                else:
                    cnt["jizz"] = 1

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
        writer.write("\nwireshark_feature_name = ")
        writer.write(str(feature_name))
        writer.write("\nwireshark_matrix = ")
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
    wireshark = []
    for person in subfolder:
        print(person)
        # Sysmon
        sysmon_dict = load_xml(os.path.join(folder_path, person, "Sysmon.xml"))
        sysmon.append(sysmon_dict)
        security_dict = load_xml(os.path.join(folder_path, person, "Security.xml"))
        security.append(security_dict)
        wireshark_dict = load_json(os.path.join(folder_path, "Person_1", "Wireshark.json"))
        wireshark.append(wireshark_dict)

    collect_sysmon(sysmon)
    collect_security(security)
    collect_wireshark(wireshark)

if __name__ == "__main__":
    main()
