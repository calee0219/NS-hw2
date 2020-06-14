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




def main():
    """main function"""
    if len(sys.argv) != 2:
        usage()
        return
    folder_path = str(sys.argv[1])
    print("Testing folder: ", folder_path)
    subfolder = os.listdir(folder_path)


    for testcase in subfolder:
        print("{index}: ".format(index=testcase), end='')
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

        predict = []
        for feature in sysmon_feature_name:
            try:
                predict.append(cnt[feature])
            except:
                predict.append(0)
        #print(predict)
        # Load Training data
        #ans = decision_tree(sysmon_matrix, predict)
        #print(ans)
        #ans = knn(sysmon_matrix, predict)
        #print(ans)
        #ans = rule_base(sysmon_matrix, predict)
        #print(ans)
        # Data normalize
        scale_sysmon = preprocessing.scale(sysmon_matrix)
        #ans = decision_tree(scale_sysmon, predict)
        #print("DT scale: {}".format(ans))
        ans = knn(scale_sysmon, predict)
        print("KNN scale: {}".format(ans))
        ans = rule_base(scale_sysmon, predict)
        print("RB scale: {}".format(ans))
        normal_sysmon = preprocessing.normalize(sysmon_matrix)
        #ans = decision_tree(normal_sysmon, predict)
        #print("DT normal: {}".format(ans))
        ans = knn(normal_sysmon, predict)
        print("KNN normal: {}".format(ans))
        ans = rule_base(normal_sysmon, predict)
        print("RB normal: {}".format(ans))


if __name__ == "__main__":
    main()
