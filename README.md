# Paper-on-Third-party-Identifiers
## Experiment Data
file_operation.csv -- All file operations collected during our experiment

## Kernel Instrumentation
kernel_instrumentation -- All kernel source code files that we modified. The annotations in the file indicate the file path and the location of the modifications.

## Android Instrumentation
android_instrumentation -- All Android source code files the we modified. The annotations in the file indicate the file path and the location of the modifications.

## Dynamic Analysis
dynamic_analysis -- Code used for running our dynamic analysis.
### Usage
First, configure the parameters in the 'external_storage_multi_device.py' Python file, and
`python external_storage_multi_device.py -d <device serial number> -n <instance number>`
- Required parameters
```
-d device serial number # used for multi devices testing (acquired by "adb devices")
-n instance number # test instance numbers that can be set arbitrarily
```
Then, parse the output log
`python log_parsing.py -f <log_file> -o <output_path>`
- Required parameters
```
-f log_file # path to the log file
-o output_path
```
## Candidate Attributing
candidate_attributing -- Code used in our candidate attributing step.
### Usage
Before conducting the candidate attributing, please install and start Frida on the test device.
Configure the parameters in the 'candidate_attributing.py' Python file, and
`python candidate_attributing.py -a <apk file> -p <package name> -f <target file> -m <mode>`
- Required parameters
```
-a apk file # path to the apk files to be tested
-p package name # package name of tested file
-f target file # file name that you want to attribute
-m mode # attributing mode (java or native)
```