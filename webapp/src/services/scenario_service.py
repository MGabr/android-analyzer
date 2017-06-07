from src.services.scenario_settings_service import get_all_enabled_of_user
from src.models.vuln_type import VulnType


class Scenario:
    # if there is no corresponding static analysis result / the dynamic analysis does not need to be run
    # activity_name and static_analysis_results should not be set
    def __init__(self, scenario_settings, apk_filename, activity_name=None, static_analysis_results=None):
        self.scenario_settings = scenario_settings
        self.apk_filename = apk_filename
        self.activity_name = activity_name
        self.static_analysis_results = static_analysis_results

        self.is_statically_vulnerable = bool(self.activity_name and self.static_analysis_results)

    def __json__(self):
        return {
            'scenario_settings': self.scenario_settings,
            'apk_filename': self.apk_filename,
            'activity_name': self.activity_name,
            'static_analysis_results': self.static_analysis_results,
            'is_statically_vulnerable': self.is_statically_vulnerable}


class Scenarios:
    def __init__(self, scenarios, solved_scenarios):
        self.scenarios = scenarios
        self.solved_scenarios = solved_scenarios

    def __json__(self):
        return {'scenarios': self.scenarios, 'solved_scenarios': self.solved_scenarios}


class StaticAnalysisResults:
    def __init__(self, apk_filename, package, min_sdk_version, target_sdk_version, result_list):
        self.apk_filename = apk_filename
        self.package = package
        self.min_sdk_version = min_sdk_version
        self.target_sdk_version = target_sdk_version
        self.result_list = result_list

    def __json__(self):
        return {
            'apk_filename': self.apk_filename,
            'package': self.package,
            'min_sdk_version': self.min_sdk_version,
            'target_sdk_version': self.target_sdk_version,
            'result_list': self.result_list}


def get_for_choosen_activities_and_settings(static_analysis_results, choosen_activities, scenario_settings_id):
    filtered_result_list = [r for r in static_analysis_results.result_list if r.meth_nm in choosen_activities]
    filtered_results = StaticAnalysisResults(
        static_analysis_results.apk_filename,
        static_analysis_results.package,
        static_analysis_results.min_sdk_version,
        static_analysis_results.target_sdk_version,
        filtered_result_list)
    filtered_settings = [s for s in get_all_enabled_of_user() if s.id == int(scenario_settings_id)]
    return _get_of(filtered_results, filtered_settings)


def get_all_of_user(static_analysis_results):
    filtered_result_list = [r for r in static_analysis_results.result_list
                            if r.vuln_type.value != VulnType.selected_activities.value]
    filtered_results = StaticAnalysisResults(
        static_analysis_results.apk_filename,
        static_analysis_results.package,
        static_analysis_results.min_sdk_version,
        static_analysis_results.target_sdk_version,
        filtered_result_list)
    return _get_of(filtered_results, get_all_enabled_of_user())


def _get_of(static_analysis_results, scenario_settings):
    scenarios = []
    solved_scenarios = []
    for scenario_setting in scenario_settings:
        matching = []
        # get only static analysis results with the right vulnerability type
        for static_analysis_result in static_analysis_results.result_list:
            if static_analysis_result.vuln_type.value == scenario_setting.vuln_type.value:
                matching += [static_analysis_result]

        if matching:
            # create combined scenario for static analysis results with same activity name
            for activity_name in {result.meth_nm for result in matching}:
                combined_result_list = [result for result in matching if result.meth_nm == activity_name]
                combined_results = StaticAnalysisResults(
                    static_analysis_results.apk_filename,
                    static_analysis_results.package,
                    static_analysis_results.min_sdk_version,
                    static_analysis_results.target_sdk_version,
                    combined_result_list)
                scenarios += [Scenario(
                    scenario_setting,
                    static_analysis_results.apk_filename,
                    activity_name,
                    combined_results)]
        else:
            # there is no static analysis result with the right vulnerability type for this scenario
            # -> dynamic analysis is not required
            solved_scenarios += [Scenario(scenario_setting, static_analysis_results.apk_filename)]

    return Scenarios(scenarios, solved_scenarios)
