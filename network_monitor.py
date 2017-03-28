# in top level directory, because of path problems with subprocess calls

import subprocess32 as subprocess
import logging
import shlex


logger = logging.getLogger(__name__)


def start_network_monitor(emulator_id, package_name, log_id):
    pid = get_pid(emulator_id, package_name)
    process = trace_pid(emulator_id, pid, log_id)
    return process


def get_pid(emulator_id, package_name):
    cmd = "adb -s " + emulator_id + " shell ps | grep " + package_name + " | awk '{print $2}'"
    logger.debug(cmd)
    pid = subprocess.check_output(cmd, shell=True)
    pid = pid.replace("\n","")
    return pid


def trace_pid(emulator_id, pid, log_id):
    shell_cmd = "adb -s " + emulator_id + " shell su"
    logger.debug(shell_cmd)
    network_monitor_process = subprocess.Popen(shlex.split(shell_cmd),
                                               stderr=open("logs/network_monitor_log" + str(log_id), "w"),
                                               stdin=subprocess.PIPE)

    strace_cmd = "strace -p " + pid + " -q -f -e connect\n"
    logger.debug(strace_cmd)
    network_monitor_process.stdin.write(strace_cmd)

    return network_monitor_process


def kill_network_monitor(network_monitor_process):
    network_monitor_process.kill()
    try:
        network_monitor_process.wait(timeout=10)
    except subprocess.TimeoutExpired as e:
        logger.error("Could not close network monitor: {}", e)
    except OSError as e:
        logger.warn(e)
