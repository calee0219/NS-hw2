event_name = "OriginalFileName"
sysmon_feature_name = ['taskhostw.exe', 'FlashUtil.exe', 'svchost.exe', 'smartscreen.exe', 'NGenTask.exe', 'makecab.exe', 'Defrag.EXE', 'sdiagnhost.exe', 'CLEANMGR.DLL', 'dmclient.exe', 'DiskSnapshot.exe', '?', 'tzsync.exe', 'RUNDLL32.EXE', 'lpremove.exe', 'dstokenclean.exe', 'sc.exe', 'TiWorker.exe', 'TrustedInstaller.exe', 'SpeechModelDownload.exe', 'provtool', 'logonui.exe', 'soffice.bin', 'soffice.exe', 'slui.exe', 'MpCmdRun.exe', 'GoogleUpdate.exe', 'SpeechRuntime.exe', 'SystemSettings.exe', 'NisSrv.exe', 'MsMpEng.exe', 'taskkill.exe', 'mofcomp.exe', 'MpSigStub.exe', 'UpdatePlatform.exe', 'wuauclt.exe', 'CompPkgSrv.exe', 'chrome.exe', 'Dumpcap.exe', 'Wireshark.exe', 'Cmd.Exe', 'WerFault.exe', 'dllhost.exe', 'devcpp.exe', 'software_reporter_tool.exe', 'LocalBridge.exe', 'ImeBroker.exe', 'AppHostNameRegistrationVerifier.exe', 'VSSVC.EXE', 'consent.exe', 'FodHelper.EXE', 'DismHost.exe', 'splaunch.EXE', 'dwm.exe', 'python.exe', 'SystemPropertiesAdvanced.EXE', 'CONTROL.EXE', 'python-3.8.3.exe', 'PowerShell.EXE', 'msiexec.exe', 'browser_broker.EXE', 'electron.exe', 'GetMac.exe', 'WinSAT.exe', 'mcbuilder.exe']
sysmon_matrix = [[18, 2, 9, 5, 4, 1, 2, 1, 1, 3, 1, 1, 1, 6, 1, 1, 3, 3, 3, 1, 1, 1, 6, 4, 2, 9, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [8, 0, 4, 0, 3, 0, 2, 1, 1, 0, 0, 121, 1, 0, 0, 0, 3, 2, 2, 0, 1, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 13, 2, 1, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [15, 0, 10, 1, 4, 0, 1, 0, 1, 2, 0, 0, 0, 1, 0, 0, 1, 4, 4, 0, 1, 0, 0, 0, 2, 0, 2, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 4, 2, 2, 1, 5, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [4, 2, 5, 0, 0, 0, 0, 0, 0, 2, 0, 15, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [16, 0, 15, 0, 5, 0, 4, 1, 2, 2, 1, 7, 1, 10, 1, 1, 2, 4, 4, 1, 1, 0, 0, 0, 0, 9, 1, 2, 3, 1, 2, 1, 1, 1, 1, 1, 4, 5, 1, 0, 3, 0, 2, 0, 0, 0, 0, 0, 2, 3, 1, 1, 0, 0, 6, 2, 1, 5, 2, 2, 1, 10, 1, 0, 0], [9, 0, 7, 1, 3, 0, 2, 1, 2, 3, 1, 1, 1, 8, 1, 1, 3, 3, 3, 1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]]
security_name = "EventID"
security_feature_name = ['4672', '4624', '4634', '4648', '4616', '4907', '4798', '4797', '5379', '4625', '4799', '5038', '5061', '5058']
security_matrix = [[27, 28, 2, 1, 1, 1, 9, 5, 6, 1, 0, 0, 0, 0], [16, 16, 0, 0, 0, 0, 4, 0, 16, 1, 0, 0, 0, 0], [30, 30, 0, 0, 0, 4374, 7, 1, 6, 1, 10, 0, 0, 0], [27, 27, 2, 1, 0, 0, 6, 1, 26, 0, 0, 249, 1, 1], [40, 40, 0, 0, 0, 7, 12, 225, 365, 3, 16, 0, 2, 2], [11, 11, 0, 0, 1, 1, 0, 0, 23, 0, 0, 0, 0, 0]]
wireshark_feature_name = ['8.8.8.8', '10.0.2.15', '89.238.68.201', '10.0.2.255', '224.0.0.251', 'jizz', '224.0.0.252', '239.255.255.250', '172.217.160.109', '172.217.160.100', '172.217.27.131', '172.217.160.67', '40.90.137.127', '52.139.153.205', '117.18.232.200', '204.79.197.200', '52.139.250.253', '172.217.160.99', '13.74.179.117', '13.107.246.10', '52.114.128.70', '13.68.93.109', '104.26.10.240', '117.18.237.29', '172.217.160.110', '172.217.27.132', '216.58.200.35', '52.114.75.78', '104.27.178.60', '172.217.27.130', '172.217.160.104', '216.58.200.42', '172.217.160.66', '216.58.200.226', '172.217.160.78', '140.113.194.69', '172.217.160.98', '172.217.24.10', '216.58.200.225', '23.20.80.113', '34.96.111.110', '103.231.98.196', '163.28.225.57', '103.229.10.227', '52.248.89.84', '35.241.8.149', '54.164.34.2', '69.173.159.25', '35.227.202.26', '13.35.7.52', '20.36.252.130', '52.114.77.34', '64.4.54.18', '138.91.140.216', '104.94.55.130', '52.175.23.79', '23.74.248.176', '163.28.5.26', '192.229.232.240', '117.18.232.240', '172.217.160.68', '216.58.200.234', '182.48.10.221', '31.13.87.36', '192.229.237.25', '152.199.43.87', '216.58.200.34', '172.217.24.1', '103.229.10.215', '216.58.200.46', '34.95.124.132', '3.225.92.69', '52.89.85.38', '104.244.42.200', '172.217.30.195', '13.73.26.107', '216.58.200.227', '52.114.159.32', '52.229.174.233', '104.27.179.60', '172.217.160.106', '172.217.27.129', '74.125.204.138', '216.58.200.228', '66.117.25.36', '13.35.7.15', '13.35.163.3', '54.38.193.101', '54.213.109.122', '13.35.163.42', '54.242.44.147', '124.146.215.48', '52.74.65.51', '172.217.26.131', '172.217.27.142', '204.13.202.71', '52.229.207.60', '13.75.122.216', '64.233.177.94', '69.173.159.35', '50.116.239.135', '20.188.78.184', '52.114.76.35', '191.232.139.2', '52.114.158.50', '40.90.189.152', '104.94.57.208', '104.94.37.40', '13.67.75.200', '34.195.91.242', '69.173.159.55', '202.131.200.84', '103.229.206.27', '13.35.7.30', '172.217.160.65', '172.217.24.3', '52.72.195.204', '35.241.55.82', '172.217.160.82', '216.58.200.242', '172.217.24.18', '52.114.132.23', '224.0.0.22', '255.255.255.255', '192.168.100.4', '52.229.172.155', '1.1.1.1', '23.53.66.242', '52.184.80.179', '52.229.173.178', '172.217.160.74', '216.58.200.36', '100.25.225.218', '13.35.37.99', '35.190.90.30', '34.96.100.63', '52.163.89.138', '23.48.143.155', '13.88.139.208', '23.41.137.56', '52.139.168.125', '40.81.188.85', '172.217.27.136', '74.125.196.94', '151.101.76.157', '104.244.42.8', '13.35.37.85', '204.79.197.203', '203.69.81.81', '104.18.102.194', '203.69.81.51', '106.10.218.43', '13.67.116.41', '13.107.21.200', '23.219.32.118', '40.81.31.55', '40.114.54.223', '61.220.62.221', '141.226.224.32', '151.101.77.44', '151.101.66.2', '51.140.157.153', '216.58.200.50', '151.139.128.14', '173.222.180.223', '163.28.5.9', '173.222.181.87', '163.28.5.34', '40.90.23.247', '96.7.254.121', '23.48.130.177']
wireshark_matrix = [[301, 19913, 18, 126, 77, 196, 87, 144, 18, 47, 109, 159, 3, 57, 15, 285, 35, 103, 15, 14, 18, 54, 2, 65, 79, 142, 62, 9, 85, 782, 30, 19, 434, 291, 59, 168, 80, 26, 356, 17, 25, 184, 32, 26, 37, 22, 48, 34, 156, 18, 37, 11, 15, 19, 9, 25, 140, 5, 1484, 13, 190, 10, 603, 140, 50, 96, 47, 100, 12, 11, 155, 12, 12, 61, 36, 10, 54, 9, 40, 54, 41, 74, 6, 48, 18, 84, 18, 29, 43, 36, 65, 14, 14, 80, 26, 6, 29, 18, 276, 28, 11, 25, 9, 17, 29, 4, 14, 10, 14, 54, 53, 8, 17, 49, 69, 67, 24, 23, 37, 16, 15, 9, 11, 1, 182, 26, 80, 58, 48, 36, 70, 70, 60, 15, 16, 19, 11, 90, 48, 12, 13, 1, 9, 14, 84, 40, 22, 153, 94, 28, 11, 31, 260, 96, 13, 19, 105, 49, 20, 99, 58, 13, 18, 12, 11, 26, 13, 11, 16, 12, 10], [301, 19913, 18, 126, 77, 196, 87, 144, 18, 47, 109, 159, 3, 57, 15, 285, 35, 103, 15, 14, 18, 54, 2, 65, 79, 142, 62, 9, 85, 782, 30, 19, 434, 291, 59, 168, 80, 26, 356, 17, 25, 184, 32, 26, 37, 22, 48, 34, 156, 18, 37, 11, 15, 19, 9, 25, 140, 5, 1484, 13, 190, 10, 603, 140, 50, 96, 47, 100, 12, 11, 155, 12, 12, 61, 36, 10, 54, 9, 40, 54, 41, 74, 6, 48, 18, 84, 18, 29, 43, 36, 65, 14, 14, 80, 26, 6, 29, 18, 276, 28, 11, 25, 9, 17, 29, 4, 14, 10, 14, 54, 53, 8, 17, 49, 69, 67, 24, 23, 37, 16, 15, 9, 11, 1, 182, 26, 80, 58, 48, 36, 70, 70, 60, 15, 16, 19, 11, 90, 48, 12, 13, 1, 9, 14, 84, 40, 22, 153, 94, 28, 11, 31, 260, 96, 13, 19, 105, 49, 20, 99, 58, 13, 18, 12, 11, 26, 13, 11, 16, 12, 10], [301, 19913, 18, 126, 77, 196, 87, 144, 18, 47, 109, 159, 3, 57, 15, 285, 35, 103, 15, 14, 18, 54, 2, 65, 79, 142, 62, 9, 85, 782, 30, 19, 434, 291, 59, 168, 80, 26, 356, 17, 25, 184, 32, 26, 37, 22, 48, 34, 156, 18, 37, 11, 15, 19, 9, 25, 140, 5, 1484, 13, 190, 10, 603, 140, 50, 96, 47, 100, 12, 11, 155, 12, 12, 61, 36, 10, 54, 9, 40, 54, 41, 74, 6, 48, 18, 84, 18, 29, 43, 36, 65, 14, 14, 80, 26, 6, 29, 18, 276, 28, 11, 25, 9, 17, 29, 4, 14, 10, 14, 54, 53, 8, 17, 49, 69, 67, 24, 23, 37, 16, 15, 9, 11, 1, 182, 26, 80, 58, 48, 36, 70, 70, 60, 15, 16, 19, 11, 90, 48, 12, 13, 1, 9, 14, 84, 40, 22, 153, 94, 28, 11, 31, 260, 96, 13, 19, 105, 49, 20, 99, 58, 13, 18, 12, 11, 26, 13, 11, 16, 12, 10], [301, 19913, 18, 126, 77, 196, 87, 144, 18, 47, 109, 159, 3, 57, 15, 285, 35, 103, 15, 14, 18, 54, 2, 65, 79, 142, 62, 9, 85, 782, 30, 19, 434, 291, 59, 168, 80, 26, 356, 17, 25, 184, 32, 26, 37, 22, 48, 34, 156, 18, 37, 11, 15, 19, 9, 25, 140, 5, 1484, 13, 190, 10, 603, 140, 50, 96, 47, 100, 12, 11, 155, 12, 12, 61, 36, 10, 54, 9, 40, 54, 41, 74, 6, 48, 18, 84, 18, 29, 43, 36, 65, 14, 14, 80, 26, 6, 29, 18, 276, 28, 11, 25, 9, 17, 29, 4, 14, 10, 14, 54, 53, 8, 17, 49, 69, 67, 24, 23, 37, 16, 15, 9, 11, 1, 182, 26, 80, 58, 48, 36, 70, 70, 60, 15, 16, 19, 11, 90, 48, 12, 13, 1, 9, 14, 84, 40, 22, 153, 94, 28, 11, 31, 260, 96, 13, 19, 105, 49, 20, 99, 58, 13, 18, 12, 11, 26, 13, 11, 16, 12, 10], [301, 19913, 18, 126, 77, 196, 87, 144, 18, 47, 109, 159, 3, 57, 15, 285, 35, 103, 15, 14, 18, 54, 2, 65, 79, 142, 62, 9, 85, 782, 30, 19, 434, 291, 59, 168, 80, 26, 356, 17, 25, 184, 32, 26, 37, 22, 48, 34, 156, 18, 37, 11, 15, 19, 9, 25, 140, 5, 1484, 13, 190, 10, 603, 140, 50, 96, 47, 100, 12, 11, 155, 12, 12, 61, 36, 10, 54, 9, 40, 54, 41, 74, 6, 48, 18, 84, 18, 29, 43, 36, 65, 14, 14, 80, 26, 6, 29, 18, 276, 28, 11, 25, 9, 17, 29, 4, 14, 10, 14, 54, 53, 8, 17, 49, 69, 67, 24, 23, 37, 16, 15, 9, 11, 1, 182, 26, 80, 58, 48, 36, 70, 70, 60, 15, 16, 19, 11, 90, 48, 12, 13, 1, 9, 14, 84, 40, 22, 153, 94, 28, 11, 31, 260, 96, 13, 19, 105, 49, 20, 99, 58, 13, 18, 12, 11, 26, 13, 11, 16, 12, 10], [301, 19913, 18, 126, 77, 196, 87, 144, 18, 47, 109, 159, 3, 57, 15, 285, 35, 103, 15, 14, 18, 54, 2, 65, 79, 142, 62, 9, 85, 782, 30, 19, 434, 291, 59, 168, 80, 26, 356, 17, 25, 184, 32, 26, 37, 22, 48, 34, 156, 18, 37, 11, 15, 19, 9, 25, 140, 5, 1484, 13, 190, 10, 603, 140, 50, 96, 47, 100, 12, 11, 155, 12, 12, 61, 36, 10, 54, 9, 40, 54, 41, 74, 6, 48, 18, 84, 18, 29, 43, 36, 65, 14, 14, 80, 26, 6, 29, 18, 276, 28, 11, 25, 9, 17, 29, 4, 14, 10, 14, 54, 53, 8, 17, 49, 69, 67, 24, 23, 37, 16, 15, 9, 11, 1, 182, 26, 80, 58, 48, 36, 70, 70, 60, 15, 16, 19, 11, 90, 48, 12, 13, 1, 9, 14, 84, 40, 22, 153, 94, 28, 11, 31, 260, 96, 13, 19, 105, 49, 20, 99, 58, 13, 18, 12, 11, 26, 13, 11, 16, 12, 10]]