#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
import hashlib
import os
import sys
import time as tt
import urllib2

__debug = False

def list_devices(verbose=True):
    lines = os.popen("adb devices").readlines()
    if len(lines) == 0 or not lines[0].startswith("List of devices attached"):
        # print the error
        if verbose:
            print(lines)
        return dict()

    devices_dict = dict()
    # ignore head string 'list of devices attached'
    del lines[0]

    for line in lines:
        line = line.strip()
        if len(line) == 0:
            continue

        device_state = line.split()  # split by white space, e.g. \t space,  equal to \\s+ in java
        length = len(device_state)
        if length == 2:
            state = device_state[1].strip()
            devices_dict[device_state[0].strip()] = state
            if state == "device":
                if verbose:
                    print(get_device_info(device_state[0].strip()))
        else:
            print("Error occurred while splitting： %s", line)
    return devices_dict


def get_device_info(serial):
    adb = Adb(serial)
    os.system("adb -s " + serial + " wait-for-device")
    android_version = adb.run_cmd("shell getprop ro.build.version.release", True).strip()
    fingerprint = adb.run_cmd("shell getprop ro.build.fingerprint", True).strip()
    device_name = adb.run_cmd("shell getprop ro.product.model", True).strip()
    device_model = adb.run_cmd("shell getprop ro.build.product", True).strip()
    brand = adb.run_cmd("shell getprop ro.product.brand", True).strip()
    cpu_code_name = adb.run_cmd("shell getprop ro.board.platform", True).strip()
    lines = adb.run_cmd("shell 'cat /proc/cpuinfo'", True).strip()
    cpu_core_count = lines.count("processor")
    # grep MemTotal: | awk '{print int($2/1024.0/1024.0 + 0.5)}'
    lines = adb.run_cmd("shell cat proc/meminfo", True, True)
    memory = 0
    for line in lines:
        line = line.strip()
        if line.startswith("MemTotal:"):
            memStr = line.split()[1]
            if len(memStr) > 0:
                memory = float(memStr) / 1024 / 1024
            break
    device = DeviceInfo()
    device.android_version = android_version.decode()
    device.brand = brand.decode()
    device.name = device_name.decode()
    device.model = device_model.decode()
    device.fingerprint = fingerprint.decode()
    device.cpu = cpu_code_name.decode()
    device.core_count = cpu_core_count
    device.memory = round(memory, 1)
    device.serial_no = adb.run_cmd("shell getprop ro.serialno", True).strip()
    device.third_app_count = get_installed_app_count(serial, False)
    device.system_app_count = get_installed_app_count(serial, True)
    return device


def sleep_ignore_error(seconds):
    try:
        tt.sleep(seconds)
    except BaseException as e:
        print(e)


class DeviceInfo:
    android_version = ""
    name = ""
    model = ""
    brand = ""
    cpu = ""
    core_count = 0
    memory = 0
    serial_no = ""
    third_app_count = 0
    system_app_count = 0
    fingerprint = ""

    def __str__(self):
        return "brand:" + self.brand + " name:" + self.name + " model:" + self.model + " serial:" + self.serial_no.decode() \
               + " android:" + self.android_version + " cpu:" + self.cpu + " cores:" \
               + str(self.core_count) + " memory:" + str(self.memory) + "Gb" + " system_app_count:" \
               + str(self.system_app_count) \
               + " third_app_count:" + str(self.third_app_count)


def get_installed_app_count(serial, system):
    cmd = "shell pm list package "
    if system:
        cmd += '-s'
    else:
        cmd += '-3'
    adb = Adb(serial)
    out = adb.run_cmd(cmd, True, True)
    return len(out)


class Adb:
    _device = ""
    __debug = False

    def __init__(self, serial):
        self._device = serial

    def run_cmd(self, cmd, return_output=False, output_as_lines=False):
        device = ' -s ' + self._device
        cmdline = "adb" + device + " " + cmd
        if self.__debug:
            print("Debug: executing '" + cmdline + "'")
        if return_output:
            if output_as_lines:
                return os.popen(cmdline).readlines()
            else:
                return os.popen(cmdline).read()
        else:
            os.system(cmdline)


def is_system_server_restarted(device=''):
    adb = Adb(device)
    ret = adb.run_cmd("shell getprop sys.miui.runtime.reboot", True)
    ret = ret.strip()
    try:
        return int(ret) > 0
    except Exception as e:
        print("is_system_server_restarted:", e)
        return False


def md5_matches(file, expect_md5):
    if not os.path.isfile(file):
        return False
    md5 = MD5(file)
    matched = (md5 == expect_md5)
    if not matched:
        print("Warning: md5 of " + file + " is " + md5 + " which does not match expected value: " + expect_md5)
    return matched


def MD5(file):
    md5_value = hashlib.md5()
    file = open(file, "rb")
    while True:
        data = file.read(2048)  # read 2kb each time to avoid OOM
        if not data:
            break
        md5_value.update(data)
    file.close()
    return md5_value.hexdigest()


def mtbf_preparation(selected_device, enable_signal_trace):
    # dump kernel traces
    # trigger_sysrq = False

    print("\n\n>>>>>running preparation steps on device[" + selected_device + "]...<<<<<")

    # 0. replace certain libs
    adb = Adb(selected_device)
    if os.path.isfile("./replace_native_libs.config"):
        adb.run_cmd('root')
        config_file = './replace_native_libs.config'
        replace_any = False
        configs = {}
        with open(config_file, 'r') as fin:
            lines = fin.readlines()
            lineNo = 0
            for line in lines:
                lineNo += 1
                line = line.strip()
                if len(line) == 0 or line.startswith("#"):
                    continue
                mapping = line.split()
                if len(mapping) != 2:
                    raise Exception(
                        "Illegal mapping at line " + str(lineNo) + " in " + os.path.abspath(config_file) + " : " + line)
                configs[mapping[0]]= mapping[1]
                replace_any = True
        if replace_any:
            text = adb.run_cmd('disable-verity', True).strip()
            print(text)
            text = adb.run_cmd('disable-verity', True).strip()
            print(text)
            print('reboot device to take effect...')
            adb.run_cmd('reboot')
            adb.run_cmd('wait-for-device')
            sleep_ignore_error(2);
            adb.run_cmd('root')
            adb.run_cmd('remount')

            print("")
            print('replacing native libs: ')
            for key in configs:
                print("push " + key + " to " + configs[key])
                adb.run_cmd('push ' + key + ' ' + configs[key])

            print('reboot device to take effect...')
            adb.run_cmd("reboot")
            adb.run_cmd('wait-for-device')
            sleep_ignore_error(2);
            adb.run_cmd('root')
            adb.run_cmd('remount')
            print("")

            try_count = 120
            str_count = str(try_count)
            while try_count > 0:
                out = adb.run_cmd("shell getprop sys.boot_completed", True).strip()
                if out == '1':
                    break
                try_count -= 1
                print("wait for device to be fully online")
                sleep_ignore_error(1)
            if try_count == 0:
                # timeout
                raise Exception("device didn't finish booting in " + str_count + " sec, please check phone state!")

    adb.run_cmd("root && echo running adb as root")

    # first check if setcoredump file exists, if not download it
    download_setcoredump_with_retry()
    # 1. dump heap profile on system_server OOM, fd leads
    if adb.run_cmd('shell getprop ro.miui.dumpheap', True).strip() == '1':
        print("dumpheap already enabled")
    else:
        adb.run_cmd("shell setprop ro.miui.dumpheap 1 && echo 'dumpheap on system_server OOM enabled'")
    # ro.miui.mtbftest
    if adb.run_cmd('shell getprop ro.miui.mtbftest', True).strip() == '1':
        print("mtbftest already enabled")
    else:
        adb.run_cmd("shell setprop ro.miui.mtbftest 1 && echo 'mtbftest enabled'")
    adb.run_cmd("shell setprop persist.sys.watchdog_enhanced false")
    print("persist.sys.watchdog_enhanced:")
    adb.run_cmd("shell getprop persist.sys.watchdog_enhanced")

    # 2. dump core file on native crash
    print("copy ./setcoredump onto /data/local/tmp/setcoredump")
    adb.run_cmd('push ./setcoredump /data/local/tmp/setcoredump')
    adb.run_cmd('shell chmod +x /data/local/tmp/setcoredump')

    ss_pid_str = adb.run_cmd("shell pidof system_server", True).strip()
    if len(ss_pid_str) == 0:
        raise Exception("shell system_server not found?")

    sf_pid_str = adb.run_cmd("shell pidof surfaceflinger", True).strip()
    if len(sf_pid_str) == 0:
        raise Exception("surfaceflinger not found?")
    adb.run_cmd(
        'shell /data/local/tmp/setcoredump -f -p ' + ss_pid_str + " && echo 'core dump on system_server enabled'")
    adb.run_cmd('shell /data/local/tmp/setcoredump -p ' + sf_pid_str + " && echo 'core dump on surfaceflinger enabled'")

    # 3. increase logd buffer size and adjust default limit level
    adb.run_cmd("shell setprop persist.logd.limit Debug && echo 'logd limit level adjusted to Debug'")
    adb.run_cmd('shell setprop persist.logd.size 16M && echo "logd buffer size increased to 16Mb"')
    adb.run_cmd('shell setprop ctl.start logd-reinit && echo logd reinitialized')

    if enable_signal_trace:
        print("enable signal trace now...")
        adb.run_cmd("shell 'echo 1 > /sys/kernel/debug/tracing/events/signal/enable'")
        adb.run_cmd(
            "shell 'echo /sys/kernel/debug/tracing/events/signal/enable: && cat /sys/kernel/debug/tracing/events/signal/enable'")
        adb.run_cmd("shell 'echo 1 > /sys/kernel/debug/tracing/tracing_on'")
        adb.run_cmd("shell 'echo /sys/kernel/debug/tracing/tracing_on: && cat /sys/kernel/debug/tracing/tracing_on'")

    # 4. don't restart system_server on Watchdog
    # notice, extra change needed: http://gerrit.pt.miui.com/#/c/429775/
    adb.run_cmd('shell setprop persist.sys.hangOnWatchdog 1 && echo hangOnWatchdog enabled')

    # 6. persist logcat output and dmesg
    # push a shell script onto the device and execute it in background to keep persist logs
    # todo


def download_setcoredump_with_retry():
    retry_count = 2
    while retry_count > 0:
        retry_count -= 1
        open_share_file_url = "https://raw.githubusercontent.com/wwm0609/mtbf_test/master/setcoredump"
        if download_setcoredump(open_share_file_url):
            return
        open_share_file_url = "https://drive.google.com/uc?authuser=0&id=1TQBCge48rCaQW-APCT_mV7T3o54NCSL-&export=download"
        if download_setcoredump(open_share_file_url):
            return
    print(
        "setcoredump not exist, you can download it from: https://wiki.n.miui.com/download/attachments/67175775/setcoredump?version=2&modificationDate=1536919492000&api=v2, then put it into " + os.path.abspath(
            "./") + "/")


def download_file(url, out, hash=''):
    try:
        web = urllib2.urlopen(url)
        outfile = open(os.path.abspath(out), 'wb')
        outfile.write(web.read())
        outfile.close()
        web.close()
        if len(hash) > 0:
            return md5_matches(out, hash)
        return True
    except Exception as e:
        print("failed to download: " + url + " to " + out, e)
    return False


def download_setcoredump(url):
    expected_hash = 'a031555070d0385d12318fc2563aaa33'
    if not md5_matches(os.path.abspath("./setcoredump"), expected_hash):
        # try download it firstly
        print("downloading setcoredump file...")
        if download_file(url, './setcoredump', expected_hash):
            print("downloaded setcoredump file")
            return True
        else:
            print("failed to download setcoredump file from " + url)
    return True


def check_upgrade_and_execute_new_version():
    print("checking for new version...")
    version_uri = 'https://raw.githubusercontent.com/wwm0609/mtbf_test/master/version.txt'
    new_script_uri = 'https://raw.githubusercontent.com/wwm0609/mtbf_test/master/mtbf_preparation.py'
    new_version_txt = "./new_mtbf_preparation_version.txt"
    new_version_script = "./mtbf_preparation_latest.py"
    download_file(version_uri, new_version_txt)
    if os.path.isfile("./new_mtbf_preparation_version.txt"):
        try:
            fin = open(new_version_txt, 'r')
            new_version = fin.readline().strip().split("version=")[1]
            new_version_hash = fin.readline().strip().split("md5=")[1]
            if float(new_version) > __script_version and download_file(new_script_uri, new_version_script,
                                                                       new_version_hash):
                print("new version available, executing it now")
                os.system("python " + os.path.abspath(new_version_script) + " --no-upgrade")
                current_script_path = (__file__)
                print("upgrade self")
                os.rename(new_version_script, current_script_path)
                os._exit(0)
            else:
                print("new_version:" + new_version + " skipped")
        except Exception as e:
            print("failed to parse " + new_version_txt, e)


if __name__ == "__main__":
    # WARNING:
    # DO NOT RENAME THIS VARIABLE OR MANUALLY
    # UPDATE THE VALUE, IT SHALL BE UPDATED BY release.sh AUTOMATICALLY
    __script_version = 0.19

    argv = sys.argv
    argc = len(argv)
    print("script version: " + str(__script_version))

    # check if there is a newer version
    no_upgrade = False
    for arg in sys.argv:
        if arg == '--no-upgrade':
            no_upgrade = True
    if not no_upgrade:
        check_upgrade_and_execute_new_version()

    # show usage
    if argc == 2 and argv[1].startswith("--help"):
        print("usage:")
        print(
            "--device=[serial_no] : run preparation on manually picked device, if not specified will run on each connected device")
        print("--signaltrace : enable signal trace")
    else:
        idx = 0
        manual_picked_device = ""
        _enable_signal_trace = ""
        while idx < argc:
            if argv[idx].startswith("--device="):
                manual_picked_device = argv[idx].split("--device=")[1]
                if len(manual_picked_device) == 0:
                    raise Exception("empty serial is not allowed!")
                else:
                    print("manually picked device: " + manual_picked_device)
            if argv[idx].startswith('--signaltrace'):
                _enable_signal_trace = True
            if argv[idx].startswith("--debug"):
                __debug = True
            idx += 1
        os.system("adb wait-for-device >> /dev/null")
        print("list of connected devices:")
        devices = list_devices(True)
        # check if the device user specified is online
        if len(manual_picked_device) > 0:
            if devices[manual_picked_device] != "device":
                raise Exception(manual_picked_device + " is " + devices[manual_picked_device])
            else:
                mtbf_preparation(manual_picked_device, _enable_signal_trace)
        else:
            for key in devices:
                # pick a online device
                if devices[key] == 'device':
                    mtbf_preparation(key, _enable_signal_trace)
                else:
                    print("\nWarning: device " + key + " is " + devices[key] + ", skip it")

    c = raw_input("press any key to exit: ")
    print("exit now...")
    exit(0)
