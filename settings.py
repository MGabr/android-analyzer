from static_analysis import StaticAnalysisResults


class Settings:
    def __init__(self, scenarios_settings):
        self.scenarios_settings = scenarios_settings

    def get_scenarios(self, static_analysis_results):
        scenarios = []
        for scenario_setting in self.scenarios_settings:
            matching = []
            # get only static analysis results with the right vulnerability type
            for static_analysis_result in static_analysis_results.result_list:
                if static_analysis_result.vuln_type in scenario_setting.vuln_types:
                    matching += [static_analysis_result]

            # create combined scenario for static analysis results with same activity name
            for activity_name in {result.meth_nm for result in static_analysis_results.result_list}:
                combined_result_list = [result for result in static_analysis_results.result_list
                                        if result.meth_nm == activity_name]
                combined_results = StaticAnalysisResults(static_analysis_results.package, combined_result_list)
                scenarios += [Scenario(scenario_setting, activity_name, combined_results)]

        return scenarios


class ScenarioSettings:
    def __init__(self, vuln_types, certificate, error_message):
        self.vuln_types = vuln_types
        self.certificate = certificate
        self.error_message = error_message


class Certificate:
    def __init__(self, description, custom_cert=None, custom_cert_domain=None, custom_ca=None):
        self.description = description
        self.custom_cert = custom_cert
        self.custom_cert_domain = custom_cert_domain
        self.custom_ca = custom_ca


class Scenario:
    def __init__(self, scenario_settings, activity_name, static_analysis_results):
        self.scenario_settings = scenario_settings
        self.activity_name = activity_name
        self.static_analysis_results = static_analysis_results