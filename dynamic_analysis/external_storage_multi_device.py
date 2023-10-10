# -*- coding: UTF-8 -*-
import os
import subprocess
from time import sleep, strftime, localtime, time
import uiautomator2 as u2
from xml.dom.minidom import parseString
import argparse

'''
1 determining permissions  ps: no Chinese character in apk path
2 adb root     
3 install app  
4 set property 
5 unlock phone
6 UI test      
7 pull log file 
8 uninstall app
9 adb reboot   
'''

# Config
log_path = 
test_duration = "5"
switch_file_path = 

dataset_path = 
record_storage_path = 
runtime_screenshot_storage_path = 

# bypass_init_process
bypass_list = []
skip_list = []

# device ID
device_id = ""
device_num = ""


def controller(apk_path, testlog_path, screenshots_path):
    load_bypass_list()
    test_count = 0
    while True:
        with open(switch_file_path, "r") as switch_file:
            print(get_time() + " -- [Check_status]")
            status = switch_file.readline()
            if status == "off":
                break
        if get_battery_level() < 40:
            print(get_time() + " -- [Low_battery]")
            while get_battery_level() < 60:
                sleep(60 * 5)
        apk = get_next_apk(os.path.join(apk_path, device_num))

        if apk == "None":
            break
        apk_name = apk.split("\\")[-1]

        if not apk_name.startswith("ok") and not apk_name.startswith("work"):
            processed_name = rename(apk, "before")
            if processed_name != "ERROR":
                return_code = external_storage_test(processed_name, testlog_path, screenshots_path)
                if return_code == "DONE":
                    rename(processed_name, "after")
                    test_count += 1
                    print(get_time() + " -- [Test_count]" + str(test_count))
                elif return_code == "No permission":
                    rename(processed_name, "after")
                    continue
                elif return_code == "ERROR":
                    rename(processed_name, "error")
                elif return_code == "root":
                    rename(processed_name, "root")
                else:
                    print("[Error_in_function_controller] Wrong return code: " + return_code)
            else:
                break
            if test_count % 6 == 3:
                print(get_time() + " -- [Sleeping 10]")
                sleep(60 * 10)
            if test_count % 6 == 0:
                print(get_time() + " -- [Sleeping 15]")
                sleep(60 * 15)


def external_storage_test(apk_path, testlog_path, screenshots_path):
    try:
        package_name, permissions = get_apk_info(apk_path)

        if "android.permission.READ_EXTERNAL_STORAGE" not in permissions:
            print(get_time() + " -- [No_permissions] " + apk_path)
            return "No permission"

        print(get_time() + " -- [New_test]" + package_name)
        os.system("adb root")

        print(get_time() + " -- [Installing]")
        output = install_apk(apk_path)
        if "Success" not in output:
            Rlog("[Install_failed] " + package_name)
            Rlog("[Install_failed_msg] " + output.replace("\n", " "))
            print(get_time() + " -- [Install_failed] " + package_name)
            return "ERROR"
        print(get_time() + " -- [Install_success] " + apk_path)

        setprop("testkernel", package_name)
        sleep(3)

        for i in range(20):
            os.system("adb -s " + device_id + " shell input keyevent KEYCODE_VOLUME_DOWN")

        unlock()
        print(get_time() + " -- [Unlocked]")
        sleep(3)

        print(get_time() + " -- [Push_string_file]")
        push_string(apk_path)

        print(get_time() + " -- [Try to bypass init process]")
        bypass_ret = uiautomator_bypass(package_name)
        if bypass_ret == "root":
            print(get_time() + " -- [Root detect]")
            os.system("adb -s " + device_id + " shell am force-stop " + package_name)
            sleep(1)
            print(get_time() + " -- [Device_reboot]")
            os.system("adb -s " + device_id + " reboot")
            sleep(40)
            return "root"

        print(get_time() + " -- [Start_UI_test] " + apk_path)
        fastbot(package_name, test_duration)

        os.system("adb -s " + device_id + " shell am force-stop " + package_name)
        sleep(1)

        print(get_time() + " -- [Pull_result_file]")
        os.system("adb -s " + device_id + " pull /proc/testlog " + os.path.join(testlog_path,package_name))
        sleep(3)

        pull_screenshots(package_name, screenshots_path)
        sleep(3)

        check_ret = check_extend_buffer_fail()
        if check_ret != "OK":
            Rlog(check_ret)

        print(get_time() + " -- [Uninstalling]")
        output = uninstall_apk(package_name)
        if "Success" not in output:
            Rlog("[Uninstall_failed] " + package_name)
            print(get_time() + " -- [Uninstall_failed] " + package_name)
        else:
            print(get_time() + " -- [Uninstall_success] " + apk_path)
            sleep(3)

        print(get_time() + " -- [Device_reboot]")
        os.system("adb -s " + device_id + " reboot")
        sleep(40)
        return "DONE"
    except Exception as e:
        print(get_time() + " -- [Error] " + apk_path)
        print(e)
        Rlog("[Test_error]" + apk_path + "\n" + str(e))
        print(get_time() + " -- [Device_reboot]")
        os.system("adb -s " + device_id + " reboot")
        sleep(40)
        return "ERROR"


def install_apk(path):
    cmd = "adb -s " + device_id + " install -g " + path
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")
    if len(p.communicate()) == 2:
        output = p.communicate()[0] + p.communicate()[1]
    else:
        output = p.communicate()[0]
    return output


def uninstall_apk(package_name):
    cmd = "adb -s " + device_id + " uninstall " + package_name
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")
    output = p.communicate()[0]
    return output


def pull_screenshots(package_name, screenshots_path):
    cmd = "adb -s " + device_id + " shell \"ls /sdcard | grep fastbot-" + package_name + "\""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")
    output = p.communicate()[0]
    for dir_name in output.strip().split("\n"):
        sub_cmd = "adb -s " + device_id + " pull /sdcard/" + dir_name + " " + screenshots_path
        os.system(sub_cmd)
        sub_cmd = "adb -s " + device_id + " shell \"rm -r /sdcard/" + dir_name + "\""
        os.system(sub_cmd)


def setprop(prop_name, prop_value):
    os.system("adb -s " + device_id + " shell \"setprop " + prop_name + " " + prop_value + "\"")


def get_apk_info(apk_path):
    cmd = "aapt d permissions " + apk_path
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")
    output = p.communicate()[0]
    package_name = output[output.find("package:") + 9:output.find("\n", output.find("package:"))]

    permissions = []
    permissions_start = output.find("\n", output.find("package:"))
    while output.find("uses-permission: name=\'", permissions_start) != -1:
        permissions.append(output[output.find("uses-permission: name=\'", permissions_start) + 23:output.find("\'\n",
                                                                                                              permissions_start)])
        permissions_start = output.find("\'\n", permissions_start) + 2
    return package_name, permissions


def fastbot(package_name, duration):
    cmd = "adb -s " + device_id + " shell \"CLASSPATH=/sdcard/monkeyq.jar:/sdcard/framework.jar:/sdcard/fastbot-thirdpart.jar exec " \
                                  "app_process /system/bin com.android.commands.monkey.Monkey -p " + package_name + " --agent reuseq " \
                                                                                                                    "--running-minutes " + duration + " --throttle 1500 -v -v > /dev/null\""
    os.system(cmd)


def unlock():
    os.system("adb -s " + device_id + " shell input keyevent KEYCODE_POWER")
    sleep(1)
    os.system("adb -s " + device_id + " shell input swipe 100 600 100 100 100")
    sleep(1)
    os.system("adb -s " + device_id + " shell input swipe 100 600 100 100 100")
    sleep(1)
    os.system("adb -s " + device_id + " shell input swipe 100 600 100 100 50")


def Rlog(log_content):
    with open(log_path, "a+") as log_file:
        log_file.write(get_time() + " -- " + log_content + "\n")


def find_apks(path):
    result = []
    file_list = os.listdir(path)
    for file in file_list:
        cur_path = os.path.join(path, file)
        if not os.path.isdir(cur_path):
            if ".apk" in file:
                apk_name = file.split("\\")[-1]
                if not apk_name.startswith("ok") and not apk_name.startswith("work"):
                    result.append(cur_path)
    return result


def get_next_apk(path):
    apk_list = find_apks(path)
    if len(apk_list) > 0:
        return apk_list[0]
    else:
        return "None"


def rename(file_path, status):
    file_name = file_path.split("\\")[-1]

    if not file_name.endswith(".apk"):
        print("[Error_in_function_rename] Wrong file: " + file_path)

    if status == "before":
        tar_file_name = file_path.replace(file_name, "work_" + file_name)
    elif status == "after":
        tar_file_name = file_path.replace(file_name, "ok_" + file_name)
    elif status == "error":
        tar_file_name = file_path.replace(file_name, "error_" + file_name)
    elif status == "root":
        tar_file_name = file_path.replace(file_name, "root_" + file_name)
    else:
        print("[Error_in_function_rename] Wrong status: " + status)
        return "ERROR"

    os.rename(file_path, tar_file_name)
    return tar_file_name


def uiautomator_bypass(package_name):
    d = u2.connect(device_id)  # connect to device
    d.app_start(package_name)

    limit = 0
    while limit < 5:
        xml = d.dump_hierarchy()

        xml_dom = parseString(xml)
        collection = xml_dom.documentElement

        nodes = collection.getElementsByTagName("node")

        flag_match = 0

        for node in nodes:
            flag_skip_node = 0
            if flag_match == 1:
                break
            if "checkable" in node.attributes.keys() and "checked" in node.attributes.keys():
                if "true" == node.attributes["checkable"].value and "false" == node.attributes["checked"].value:
                    d(resourceId=node.attributes["resource-id"].value).click()
                    flag_match = 1
                    break
            if "text" in node.attributes.keys():
                if "Root" in node.attributes["text"].value or "ROOT" in node.attributes["text"].value \
                        or "root" in node.attributes["text"].value:
                    d.uiautomator.stop()
                    return "root"
                if "" != node.attributes["text"].value and len(node.attributes["text"].value) < 20:
                    for word in skip_list:
                        if word in node.attributes["text"].value:
                            flag_skip_node = 1
                            break
                    if flag_skip_node == 0:
                        for word in bypass_list:
                            if word in node.attributes["text"].value:
                                d(text=node.attributes["text"].value).click()
                                flag_match = 1
                                break
        if flag_match == 0:
            break
        else:
            limit += 1
            sleep(8)
    sleep(8)
    d.uiautomator.stop()
    sleep(5)
    return "DONE"


def load_bypass_list():
    with open("external_bypass_word.txt", "r") as file:
        for word in file.readlines():
            bypass_list.append(word.strip())

    with open("external_skip_word.txt", "r") as file:
        for word in file.readlines():
            skip_list.append(word.strip())


def check_extend_buffer_fail():
    cmd = "adb -s " + device_id + " shell \"dmesg | grep syscall_test\""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")
    if "init buffer failed" in p.communicate()[0]:
        return p.communicate()[0]
    else:
        return "OK"


def get_time():
    current_time = int(time())
    local = localtime(current_time)
    dt = strftime('%Y:%m:%d %H:%M:%S', local)
    return dt


def parse_arg():
    parser = argparse.ArgumentParser(description="-d or --device + deviceID value\n-n or --number + device number")
    parser.add_argument('-d', "--device")
    parser.add_argument('-n', "--number")
    args = parser.parse_args()
    global device_id, device_num
    device_id = args.device
    device_num = args.number


def get_battery_level():
    cmd = "adb -s " + device_id + " shell \"dumpsys battery\""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")
    output = p.communicate()[0]
    for line in output.split("\n"):
        if "level" in line:
            return int(line.split(":")[1].strip())


def push_string(apk_path):
    string_filename = device_id + "_string"
    cmd = "aapt2 dump strings " + apk_path + " > " + string_filename
    os.system(cmd)
    cmd = "adb -s " + device_id + " push " + string_filename + " /sdcard/max.valid.strings"
    os.system(cmd)


if __name__ == "__main__":
    parse_arg()
    controller(dataset_path, record_storage_path, runtime_screenshot_storage_path)
