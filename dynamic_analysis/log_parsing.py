import os
import struct
import json
import argparse

from time import strftime, localtime, time

LOG_SCINFO = 1
LOG_SCDATA = 2
LOG_SCSTART = 3
LOG_SCFD = 4
LOG_SCSTACK = 5
LOG_SCMEM = 6


file_path = ""
output_path = ""


def process_testlog(filepath, log_file_path, scinfo_path, sdcard_path, filter, scinfo_switch):
    syscall = {}
    fdpairs = []
    package_name = filepath.split("\\")[-1]
    with open(log_file_path, "w") as log_file:
        with open(scinfo_path, "w") as scinfo_file:
            with open(filepath, "rb") as file:
                with open(sdcard_path, "w") as sdcard_file:
                    while True:
                        raw_size = file.read(4)
                        if raw_size == b'':
                            break
                        size = struct.unpack("i", raw_size)[0]
                        raw_struct_type = file.read(4)
                        struct_type = struct.unpack("i", raw_struct_type)[0]
                        if struct_type == LOG_SCINFO:
                            if scinfo_switch == 1:
                                if size == 80:
                                    scinfo = {}
                                    raw_id = file.read(4)
                                    raw_pid = file.read(4)
                                    raw_syscallno = file.read(8)
                                    raw_args0 = file.read(8)
                                    raw_args1 = file.read(8)
                                    raw_args2 = file.read(8)
                                    raw_args3 = file.read(8)
                                    raw_args4 = file.read(8)
                                    raw_args5 = file.read(8)
                                    raw_ret = file.read(8)
                                    scinfo["I"] = struct.unpack("i", raw_id)[0]
                                    if str(struct.unpack("Q", raw_syscallno)[0]) in syscall:
                                        scinfo["C"] = syscall[str(struct.unpack("Q", raw_syscallno)[0])]
                                    else:
                                        scinfo["C"] = struct.unpack("Q", raw_syscallno)[0]
                                    args = [struct.unpack("q", raw_args0)[0], struct.unpack("q", raw_args1)[0],
                                            struct.unpack("q", raw_args2)[0], struct.unpack("q", raw_args3)[0],
                                            struct.unpack("q", raw_args4)[0], struct.unpack("q", raw_args5)[0]]
                                    scinfo["A"] = args
                                    scinfo["R"] = struct.unpack("q", raw_ret)[0]
                                    scinfo_file.write(str(scinfo))
                                    scinfo_file.write('\n')
                                else:
                                    print("Wrong scinfo size")
                            else:
                                file.read(72)
                        elif struct_type == LOG_SCDATA:
                            if size > 24:
                                scdata = {}
                                raw_id = file.read(4)
                                raw_pos = file.read(4)
                                raw_syscallno = file.read(8)
                                data_len = size - 24
                                raw_data = file.read(data_len)
                                scdata["I"] = struct.unpack("i", raw_id)[0]
                                if str(struct.unpack("Q", raw_syscallno)[0]) in syscall:
                                    scdata["C"] = syscall[str(struct.unpack("Q", raw_syscallno)[0])]
                                else:
                                    scdata["C"] = struct.unpack("Q", raw_syscallno)[0]
                                if scdata["C"] in fdpairs:
                                    if scinfo_switch == 1:
                                        fd1 = struct.unpack("i", raw_data[0:4])
                                        fd2 = struct.unpack("i", raw_data[4:8])
                                        scdata["A"] = [fd1, fd2]
                                else:
                                    path = raw_data.decode("gbk", "ignore")
                                    if filter == 1:
                                        if "/data/user/0" not in path and len(path) > 12 and \
                                                "/storage/emulated/0/Android/data/" + package_name not in path and \
                                                "/data/data/" + package_name not in path and "/data/dalvik-cache/" not in path \
                                                and "/storage/emulated/0\x00" != path and \
                                                "/storage/emulated\x00" != path and "/storage/emulated/0/Android\x00" != path \
                                                and "/storage/emulated/0/Android/data\x00" != path and "/dev/ashmem\x00" != path \
                                                and "/vendor/odm" not in path and "/vendor/lib64\x00" != path and "/odm/lib64\x00" != path \
                                                and "/system/lib64\x00" != path and "/proc/self/fd/" not in path and "/dev/socket/" not in path \
                                                and "/system/framework" not in path and "/system/app/webview" not in path \
                                                and "/data/app/" + package_name not in path and "/proc/self/maps\x00" != path:
                                            scdata["D"] = path
                                            if path.startswith("/sdcard") or path.startswith("/storage"):
                                                sdcard_file.write(str(scdata))
                                                sdcard_file.write('\n')
                                            else:
                                                log_file.write(str(scdata))
                                                log_file.write('\n')
                                    else:
                                        scdata["D"] = path
                                        log_file.write(str(scdata))
                                        log_file.write('\n')
                            else:
                                print("Wrong scdata size")
                                break
                        elif struct_type == LOG_SCSTART:
                            if size == 16:
                                scstart = {}
                                raw_pid = file.read(4)
                                raw_is32 = file.read(1)
                                file.read(3)
                                scstart["size"] = size
                                scstart["type"] = "SCSTART"
                                scstart["pid"] = struct.unpack("i", raw_pid)[0]
                                is32 = struct.unpack("?", raw_is32)[0]
                                scstart["is32"] = is32
                                log_file.write(str(scstart))
                                log_file.write('\n')
                                if is32:
                                    with open("syscall_dict.txt", "r") as pre_file:
                                        syscall = json.loads(pre_file.read())
                                    temp_fdpairs = ["NR_compat_socketpair", "NR_compat_pipe", "NR_compat_pipe2"]
                                    fdpairs.extend(temp_fdpairs)
                                else:
                                    with open("syscall64_dict.txt", "r") as pre_file:
                                        syscall = json.loads(pre_file.read())
                                    temp_fdpairs = ["NR64_compat_socketpair", "NR64_compat_pipe2"]
                                    fdpairs.extend(temp_fdpairs)
                            else:
                                print("Wrong scstart size")
                        elif struct_type == LOG_SCFD:
                            if size > 16:
                                file.read(size - 8)
                            else:
                                print("Wrong scfd size")


def parse_arg():
    parser = argparse.ArgumentParser(description="-d or --device + deviceID value\n-n or --number + device number")
    parser.add_argument('-f', "--file")
    parser.add_argument('-o', "--output")
    args = parser.parse_args()
    global file_path, output_path
    file_path = args.file
    output_path = args.output


if __name__ == "__main__":
    parse_arg()
    process_testlog(file_path, os.path.join(output_path, "testlog_processed"),
                    os.path.join(output_path, "testlog_scinfo"), os.path.join(output_path, "testlog_sdcard"), 1, 1)
