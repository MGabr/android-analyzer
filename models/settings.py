from analysis.static.static_analysis import StaticAnalysisResults
import itertools
import textwrap


class Settings:
    def __init__(self, scenarios_settings):
        self.scenarios_settings = scenarios_settings

    def get_scenarios(self, static_analysis_results):
        scenarios = []
        solved_scenarios = []
        for scenario_setting in self.scenarios_settings:
            matching = []
            # get only static analysis results with the right vulnerability type
            for static_analysis_result in static_analysis_results.result_list:
                if static_analysis_result.vuln_type in scenario_setting.vuln_types:
                    matching += [static_analysis_result]

            if matching:
                # create combined scenario for static analysis results with same activity name
                for activity_name in {result.meth_nm for result in matching}:
                    combined_result_list = [result for result in matching
                                            if result.meth_nm == activity_name]
                    combined_results = StaticAnalysisResults(static_analysis_results.package, combined_result_list)
                    scenarios += [Scenario(scenario_setting, activity_name, combined_results)]
            else:
                # there is no static analysis result with the right vulnerability type for this scenario
                # -> dynamic analysis is not required
                solved_scenarios += [Scenario(scenario_setting)]

        return scenarios, solved_scenarios


class ScenarioSettings:
    _ID = itertools.count()

    def __init__(
            self,
            vuln_types,
            mitm_certificate,
            sys_certificates,
            user_certificates,
            error_message,
            is_default=True,
            enabled=True):
        self.id = self._ID.next()
        self.is_default = is_default
        self.enabled = enabled
        self.vuln_types = vuln_types
        self.mitm_certificate = mitm_certificate
        self.sys_certificates = sys_certificates
        self.user_certificates = user_certificates
        self.error_message = textwrap.dedent(error_message)

    # TODO: remove
    def get_vuln_types_str(self):
        return self.vuln_types

    def get_sys_certificates_ids(self):
        return [s.id for s in self.sys_certificates]

    def get_user_certificates_ids(self):
        return [u.id for u in self.user_certificates]


class Certificate:
    _ID = itertools.count()

    def __init__(self, name, description, custom_cert=None, custom_cert_domain=None, custom_ca=None, is_default=True):
        self.id = self._ID.next()
        self.name = name
        self.is_default = is_default
        self.description = textwrap.dedent(description)
        self.custom_cert = custom_cert
        self.custom_cert_domain = custom_cert_domain
        self.custom_ca = custom_ca


class Scenario:
    # if there is no corresponding static analysis result / the dynamic analysis does not need to be run
    # activity_name and static_analysis_results should not be set
    def __init__(self, scenario_settings, activity_name=None, static_analysis_results=None):
        self.scenario_settings = scenario_settings
        self.activity_name = activity_name
        self.static_analysis_results = static_analysis_results

    def is_statically_vulnerable(self):
        return self.activity_name and self.static_analysis_results