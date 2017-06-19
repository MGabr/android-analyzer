import logging
import shlex

import subprocess32 as subprocess

from src.definitions import LOGS_DIR


logger = logging.getLogger(__name__)


class NetworkMonitor:
    def __init__(self, strace_enabled, emulator_id, package_name, log_id):
        self.process = None

        self.strace_enabled = strace_enabled
        self.emulator_id = emulator_id
        self.package_name = package_name
        self.log_id = log_id

    def __enter__(self):
        self.start()

    def start(self):
        if self.strace_enabled:
            pid = get_pid(self.emulator_id, self.package_name)
            self.process = trace_pid(self.emulator_id, pid, self.log_id)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.kill()

    def kill(self):
        if self.process:
            self.process.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired as e:
                logger.exception("Could not close network monitor")
            except OSError as e:
                logger.warn(e)


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
                                               stderr=open(LOGS_DIR + "network_monitor_log" + str(log_id), "w"),
                                               stdin=subprocess.PIPE)

    strace_cmd = "strace -p " + pid + " -q -f -e connect\n"
    logger.debug(strace_cmd)
    network_monitor_process.stdin.write(strace_cmd)

    return network_monitor_process
