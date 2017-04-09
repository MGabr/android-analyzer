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
                if static_analysis_result.vuln_type == scenario_setting.vuln_type.value:
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


class Scenario:
    # if there is no corresponding static analysis result / the dynamic analysis does not need to be run
    # activity_name and static_analysis_results should not be set
    def __init__(self, scenario_settings, activity_name=None, static_analysis_results=None):
        self.scenario_settings = scenario_settings
        self.activity_name = activity_name
        self.static_analysis_results = static_analysis_results

    def is_statically_vulnerable(self):
        return self.activity_name and self.static_analysis_results