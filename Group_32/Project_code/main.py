#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Security Homework 2"""

import sys
import os
import json

import xmltodict
import numpy as np
import pandas as pd
from sklearn import tree
from sklearn.neighbors import KNeighborsClassifier
from sklearn import preprocessing

from training_data import *
TREE = 0
KNN = 1
RULE_BASE = 2


def usage():
    """usage: Helper function about how to use the program"""
    print("usage: python3 main.py log_folder")


def load_json(path):
    """Load data from json file"""
    json_str = ""
    with open(path, 'rb') as reader:
        for line in reader:
            line_str= str(line.decode('utf-8', errors="ignore"))
            json_str += line_str
        json_data = json.loads(json_str)
        return json_data


def load_xml(path):
    """Load data from xml file"""
    #tree = ET.parse(path)
    #xml_data = tree.getroot()
    with open(path, 'r') as reader:
        xml_data = xmltodict.parse(reader.read())
    return xml_data


def decision_tree(x, predict):
    """Run Decision Tree"""
    y = [1, 2, 3, 4, 5, 6]
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(x, y)
    return clf.predict([predict])


def knn(x, predict):
    """rum knn"""
    y = [1, 2, 3, 4, 5, 6]
    clf = KNeighborsClassifier(n_neighbors=1, algorithm='brute')
    clf = clf.fit(x, y)
    return clf.predict([predict])


def rule_base(x, predict):
    """Run rule base"""
    feature_cnt = [0, 0, 0, 0, 0, 0]
    # total feature
    tot_feature = len(x[0])
    for feature in range(tot_feature):
        for user in range(6):
            if x[user][feature] > 5:
                other = 0
                for k in range(1, 6):
                    other += x[(user+k)%6][feature]
                if x[user][feature] > other:
                    feature_cnt[user] += x[user][feature]

    return feature_cnt.index(max(feature_cnt))+1


def prediction(feature_name, matrix, cnt, model):
    """Count feature num and predict"""
    predict = []
    for feature in feature_name:
        try:
            predict.append(cnt[feature])
        except:
            predict.append(0)

    # print(predict)
    if model == 0:
        ans = decision_tree(matrix, predict)[0]
    elif model == 1:
        ans = knn(matrix, predict)[0]
    elif model == 2:
        ans = rule_base(matrix, predict)
    # print(ans)
    return ans


def main():
    """main function"""
    if len(sys.argv) != 2:
        usage()
        return

    folder_path = str(sys.argv[1])
    # print("Testing folder: ", folder_path)
    subfolder = os.listdir(folder_path)


    for testcase in subfolder:
        # Data testing for sysmon
        print("{index}: ".format(index=testcase), end='')
        ballot_box = [-1, 0, 0, 0, 0, 0, 0]
        sysmon_data = load_xml(os.path.join(folder_path, testcase, "Sysmon.xml"))
        cnt = {}
        for event in sysmon_data['Events']['Event']:
            for data in event['EventData']['Data']:
                if data['@Name'] == event_name:
                    feature = data['#text']
                    if feature in cnt.keys():
                        cnt[feature] += 1
                    else:
                        cnt[feature] = 1

        # Data normalize
        scale_sysmon = preprocessing.scale(sysmon_matrix)
        ballot = prediction(sysmon_feature_name, scale_sysmon, cnt, KNN)
        ballot_box[ballot] += 1
        print(ballot)

        normal_sysmon = preprocessing.normalize(sysmon_matrix)
        ballot = prediction(sysmon_feature_name, normal_sysmon, cnt, KNN)
        ballot_box[ballot] += 1
        print(ballot)

        scale_sysmon = preprocessing.scale(sysmon_matrix)
        ballot = prediction(sysmon_feature_name, scale_sysmon, cnt, RULE_BASE)
        ballot_box[ballot] += 1
        print(ballot)

        normal_sysmon = preprocessing.normalize(sysmon_matrix)
        ballot = prediction(sysmon_feature_name, normal_sysmon, cnt, RULE_BASE)
        ballot_box[ballot] += 1
        print(ballot)

        # Data testing for security
        security_data = load_xml(os.path.join(folder_path, testcase, "Security.xml"))
        cnt = {}
        for event in security_data['Events']['Event']:
            feature = event['System'][security_name]
            if feature in cnt.keys():
                cnt[feature] += 1
            else:
                cnt[feature] = 1

        scale_security = preprocessing.scale(security_matrix)
        ballot = prediction(security_feature_name, scale_security, cnt, KNN)
        ballot_box[ballot] += 1
        print(ballot)

        normal_security = preprocessing.normalize(security_matrix)
        ballot = prediction(security_feature_name, normal_security, cnt, KNN)
        ballot_box[ballot] += 1
        print(ballot)

        wireshark_data = load_json(os.path.join(folder_path, testcase, "Wireshark.json"))
        cnt = {}
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

        scale_wireshark = preprocessing.scale(wireshark_matrix)
        ballot = prediction(wireshark_feature_name, scale_wireshark, cnt, KNN)
        ballot_box[ballot] += 1
        print(ballot)

        normal_wireshark = preprocessing.normalize(wireshark_matrix)
        ballot = prediction(wireshark_feature_name, normal_wireshark, cnt, KNN)
        ballot_box[ballot] += 1
        print(ballot)

        print(ballot_box)
        print('person', str(ballot_box.index(max(ballot_box))))


if __name__ == "__main__":
    main()
