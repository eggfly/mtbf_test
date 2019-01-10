#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

# ----------------------------
# Usage:
# python connect_mioffice_5g_wifi.py your_account your_password [device_serial_no]

# Note:
# tested only on Android P
# ----------------------------

import hashlib
import os
import sys
import time as tt
import urllib2

def connect(serial_no):
    cmd = "adb wait-for-device && adb shell svc wifi enable && adb root && adb push ./my_WifiConfigStore.xml /data/misc/wifi/WifiConfigStore.xml && adb reboot"
    if len(serial_no) > 0:
        adb = "adb -s " + serial_no
        cmd = cmd.replace("adb", adb)
    print "wifi configured, reboot now to take effect..."
    os.system(cmd)

if len(sys.argv) < 3:
    print "Error: Wifi account or password not provided, check the following usage\n"
    print "Usage:"
    print "python connect_mioffice_5g_wifi.py your_account your_password [device_serial_no]"
    exit(1)

identity=sys.argv[1].strip()
password=sys.argv[2].strip()
serial_no = ""
if len(sys.argv) >= 4:
    serial_no=sys.argv[3]

# sed -i"_bak" "s/$from_str/$to_str/g" ./WifiConfigStore.xml
print "identity=" + identity
print "password=" + password
fin = open("./WifiConfigStore.xml", "r")
template=fin.read()
fin.close()
fout = open("./my_WifiConfigStore.xml", "w")
template = template.replace("replace_me_identity", identity)
template = template.replace("replace_me_password", password)
fout.write(template)
fout.close()

connect(serial_no)