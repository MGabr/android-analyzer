from common.dto.scenario import Scenario
from common.dto_dependency_loader import asinstanceof


class DynamicAnalysisResult:
    # if no dynamic analysis was run, log_id should not be set
    def __init__(self,
                 scenario,
                 log_id=None,
                 crashed_on_run=False,
                 crashed_on_setup=False,
                 is_running=False,
                 timed_out=False):
        self.scenario = asinstanceof(scenario, Scenario)
        self.log_id = log_id
        self.crashed_on_run = crashed_on_run
        self.crashed_on_setup = crashed_on_setup
        self.is_running = is_running
        self.timed_out = timed_out

        self.has_been_run = bool(self.log_id)

    def __json__(self):
        return {
            'scenario': self.scenario,
            'log_id': self.log_id,
            'crashed_on_run': self.crashed_on_run,
            'crashed_on_setup': self.crashed_on_setup,
            'has_been_run': self.has_been_run,
            'is_running': self.is_running,
            'timed_out': self.timed_out}


class LogAnalysisResult:
    def __init__(self, dynamic_analysis_result, connected_hosts=None):
        self.dynamic_analysis_result = asinstanceof(dynamic_analysis_result, DynamicAnalysisResult)
        self.connected_hosts = connected_hosts

        self.is_vulnerable = bool(self.connected_hosts)

    def __json__(self):
        return {
            'dynamic_analysis_result': self.dynamic_analysis_result,
            'connected_hosts': list(self.connected_hosts) if self.connected_hosts else None,
            'is_vulnerable': self.is_vulnerable}

