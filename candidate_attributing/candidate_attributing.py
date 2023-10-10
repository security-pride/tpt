import os
import time
import sys
import zipfile
import subprocess
import uiautomator2 as u2
import argparse

from xml.dom.minidom import parseString


# Config
test_duration = "5"
apktool_output_path = 

java_template_path = "java.js"
libc_template_path = "libc.js"

bypass_list = []
skip_list = []

apk_path_arg = ""
package_name_arg = ""
file_arg = ""
mode_arg = ""


def attributing(apk_path, package_name, target_file_name, mode):
    stack_arr = frida_test(apk_path, package_name, target_file_name, mode)

    if mode == "java":
        # apktool(apk_path)
        package_name_list = set()
        collect_package_name_in_apk(apktool_output_path, package_name_list)
        for stack in stack_arr:
            is_found = False
            for function_name in stack:
                for package_name_in_apk in package_name_list:
                    if function_name.startswith(package_name_in_apk):
                        print(package_name_in_apk)
                        is_found = True
                        break
                if is_found:
                    break
    elif mode == "native":
        lib_list = collect_lib_in_apk(apk_path)
        for stack in stack_arr:
            for lib_name in stack:
                if lib_name in lib_list:
                    print(lib_name)
                    break
    else:
        sys.exit(-1)


def frida_test(apk_path, package_name, target_file_name, mode):
    load_bypass_list()

    output = install_apk(apk_path)
    if "Success" not in output:
        print(get_time() + " -- [Install_failed] " + package_name)
        sys.exit(-1)
    print(get_time() + " -- [Install_success] " + apk_path)

    unlock()
    print(get_time() + " -- [Unlocked]")
    time.sleep(3)

    print(get_time() + " -- [Push_string_file]")
    push_string(apk_path)

    frida_cmd = "frida -U -f " + package_name + " --no-pause -l " + frida_script(package_name, target_file_name, mode) \
                + " > temp.txt"
    p = subprocess.Popen(frida_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")

    time.sleep(5)
    print(get_time() + " -- [Try to bypass init process]")
    bypass_ret = uiautomator_bypass(package_name)

    print(get_time() + " -- [Start_UI_test] " + apk_path)
    fastbot(package_name, test_duration)

    os.system("adb shell am force-stop " + package_name)

    stack_arr = []
    with open("temp.txt", "r") as log_file:
        is_stack = False
        stack = []
        for line in log_file.readlines():
            if mode == "java":
                if line == "java.lang.Exception\n":
                    is_stack = True
                    continue
                if is_stack:
                    if line.strip() == "":
                        is_stack = False
                        stack_arr.append(stack)
                        stack = []
                        continue
                    function_start_index = line.find("at") + 3
                    function_end_index = line.find("(")
                    function_name = line[function_start_index: function_end_index]
                    stack.append(function_name)
            elif mode == "native":
                if line == "=============================open Stack strat=======================\n":
                    is_stack = True
                    continue
                if is_stack:
                    if line == "=============================open Stack end  =======================\n":
                        is_stack = False
                        stack_arr.append(stack)
                        stack = []
                        continue
                    lib_start_index = line.find(" ") + 1
                    lib_end_index = line.find("!")
                    lib_name = line[lib_start_index: lib_end_index]
                    stack.append(lib_name)
            else:
                sys.exit(-1)
    return stack_arr


def uiautomator_bypass(package_name):
    d = u2.connect()
    d.app_wait(package_name)

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
            time.sleep(8)
    time.sleep(8)
    d.uiautomator.stop()
    time.sleep(5)
    return "DONE"


def load_bypass_list():
    with open("external_bypass_word.txt", "r") as file:
        for word in file.readlines():
            bypass_list.append(word.strip())

    with open("external_skip_word.txt", "r") as file:
        for word in file.readlines():
            skip_list.append(word.strip())


def push_string(apk_path):
    string_filename = "string"
    cmd = "aapt2 dump strings " + apk_path + " > " + string_filename
    os.system(cmd)
    cmd = "adb push " + string_filename + " /sdcard/max.valid.strings"
    os.system(cmd)


def unlock():
    os.system("adb shell input keyevent KEYCODE_POWER")
    time.sleep(1)
    os.system("adb shell input swipe 100 600 100 100 100")
    time.sleep(1)
    os.system("adb shell input swipe 100 600 100 100 100")
    time.sleep(1)
    os.system("adb shell input swipe 100 600 100 100 50")


def install_apk(path):
    cmd = "adb install -g " + path
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="gbk")
    if len(p.communicate()) == 2:
        output = p.communicate()[0] + p.communicate()[1]
    else:
        output = p.communicate()[0]
    return output


def fastbot(package_name, duration):
    cmd = "adb shell \"CLASSPATH=/sdcard/monkeyq.jar:/sdcard/framework.jar:/sdcard/fastbot-thirdpart.jar exec " \
          "app_process /system/bin com.android.commands.monkey.Monkey -p " + package_name + " --agent reuseq " \
          "--running-minutes " + duration + " --throttle 1500 -v -v > /dev/null\""
    os.system(cmd)


def frida_script(package_name, target_file_name, mode):
    if mode == "java":
        template_path = java_template_path
        script_file_name = get_time() + "_" + package_name + "_java.js"
    elif mode == "native":
        template_path = libc_template_path
        script_file_name = get_time() + "_" + package_name + "_native.js"
    else:
        print("Mode arg should be java or native")
        sys.exit(1)

    with open(script_file_name, "w") as script_file:
        with open(template_path, "r") as template_file:
            for line in template_file.readlines():
                if "$searchString" in line:
                    script_file.write(line.replace("$searchString", "\"" + target_file_name + "\""))
                else:
                    script_file.write(line)
    return os.path.abspath(script_file_name)


def collect_package_name_in_apk(base_path, package_name_list):
    file_list = os.listdir(base_path)
    for file in file_list:
        cur_path = os.path.join(base_path, file)
        if "smali" in cur_path:
            if os.path.isdir(cur_path):
                collect_package_name_in_apk(cur_path, package_name_list)
            else:
                smali_index = cur_path.find("smali")
                start_index = cur_path.find(os.sep, smali_index) + 1
                end_index = cur_path.rfind(os.sep)
                if start_index != 0:
                    package_name = cur_path[start_index:end_index].replace(os.sep, ".")
                    if not package_name.startswith("android") and package_name != "":
                        package_name_list.add(package_name)
    return package_name_list


def collect_lib_in_apk(apk_path):
    lib_list = set()
    with zipfile.ZipFile(apk_path, 'r') as zip_file:
        file_list = zip_file.namelist()
        for filename in file_list:
            if filename.endswith(".so"):
                start_index = filename.rfind("/") + 1
                lib_list.add(filename[start_index:])
    return lib_list


def apktool(apk_path):
    apktool_cmd = "apktool d " + apk_path + " -f -o " + apktool_output_path
    os.system(apktool_cmd)


def get_time():
    current_time = int(time.time())
    localtime = time.localtime(current_time)
    dt = time.strftime('%Y_%m_%d_%H_%M', localtime)
    return dt


def parse_arg():
    parser = argparse.ArgumentParser(description="-a or --apk + apk file path\n-p or --packagename + package name\n-f or --file + target file name\n-m or --mode + mode")
    parser.add_argument('-a', "--apk")
    parser.add_argument('-p', "--packagename")
    parser.add_argument('-f', "--file")
    parser.add_argument('-m', "--mode")
    args = parser.parse_args()
    global apk_path_arg, package_name_arg, file_arg, mode_arg
    apk_path_arg = args.apk
    package_name_arg = args.packagename
    file_arg = args.file
    mode_arg = args.mode


if __name__ == "__main__":
    parse_arg()
    attributing(apk_path_arg, package_name_arg, file_arg, mode_arg)
