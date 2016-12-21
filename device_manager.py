# module for managing the emulators
# currently there is only one emulator which is running all the time
# since this will be a major performance problem (no concurrency), this will have to be changed
# supporting multiple (running and free) emulators does however pose some problems, see SMVHunter

import subprocess
import time


def get_emulator():
    # TODO: what to do about these emulator types?, use specific one? support multiple?
    # TODO: creating a new avd example: android create avd -n <name> -t <targetID>
    # TODO: maybe use -http-proxy argument, maybe also -gpu on
    emulator_type = "Nexus_5_API_24"
    port = "5554"
    cmd = "~/Android/Sdk/tools/emulator -avd " + emulator_type + " -port " + port + \
          " -wipe-data -use-system-libs -http-proxy http://localhost:8080 &"
    subprocess.check_call(cmd, shell=True)
    emulator_id = "emulator-" + port
    wait_until_boot_completed(emulator_id)

    return emulator_id


def wait_until_boot_completed(emulator_id):
    cmd = "adb -s " + emulator_id + " wait-for-device shell getprop sys.boot_completed"
    while "1" not in subprocess.check_output(cmd, shell=True):
        time.sleep(1)


def return_emulator(emulator_id):
    # TODO: not working because of telnet auth token
    cmd = "adb -s " + emulator_id + " emu kill"
    subprocess.call(cmd, shell=True)
