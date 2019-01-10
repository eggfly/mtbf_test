#!/bin/bash
com_miui_daemon_pid=0
monkey_pid=0
sleeptime=3

adb root
echo "Loading devices"
sleep $sleeptime

echo "shell am stopservice com.phonetest.stresstest/service.TimeService"
adb shell am stopservice com.phonetest.stresstest/service.TimeService


com_miui_daemon_pid=$(adb shell ps -A | grep com.miui.daemon | awk '{ print $2 }')
echo "adb shell kill -9 com_miui_daemon_pid (：$com_miui_daemon_pid)"
adb shell kill -9 ${com_miui_daemon_pid}

#sleep $sleeptime
monkey_pid=$(adb shell ps -A | grep monkey | awk '{ print $2 }')
echo "adb shell kill -9 monkey_pid(：$monkey_pid)"
adb shell kill -9 ${monkey_pid}

echo "Good Bye MTBF!"