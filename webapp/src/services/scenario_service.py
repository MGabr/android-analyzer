from src.services.scenario_settings_service import get_all_enabled_of_user
from src.models.vuln_type import VulnType


class Scenario:
    def __init__(self, scenario_settings, apk_filename, static_analysis_result):
        self.scenario_settings = scenario_settings
        self.apk_filename = apk_filename
        self.static_analysis_result = static_analysis_result

    def __json__(self):
        return {
            'scenario_settings': self.scenario_settings,
            'apk_filename': self.apk_filename,
            'static_analysis_result': self.static_analysis_result}


class ScenariosData:
    def __init__(self, scenario_list, static_analysis_results):
        self.scenario_list = scenario_list # per scenario_settings, only in Scenario because of legacy code

        # general information from static analysis valid for all scenarios
        self.apk_filename = static_analysis_results.apk_filename
        self.package = static_analysis_results.package
        self.min_sdk_version = static_analysis_results.min_sdk_version
        self.target_sdk_version = static_analysis_results.target_sdk_version
        self.result_list = static_analysis_results.result_list

    def __json__(self):
        return {
            'scenario_list': self.scenario_list,
            'apk_filename': self.apk_filename,
            'package': self.package,
            'min_sdk_version': self.min_sdk_version,
            'target_sdk_version': self.target_sdk_version}


def get_for_choosen_activities_and_settings(static_analysis_results, choosen_activities, scenario_settings_id):
    filtered_result_list = [r for r in static_analysis_results.result_list if r.activity_name in choosen_activities]
    filtered_settings = [s for s in get_all_enabled_of_user() if s.id == int(scenario_settings_id)]
    return _get_of(filtered_result_list, static_analysis_results, filtered_settings)


def get_all_of_user(static_analysis_results):
    filtered_result_list = [r for r in static_analysis_results.result_list
                            if r.vuln_type.value != VulnType.selected_activities.value]
    return _get_of(filtered_result_list, static_analysis_results, get_all_enabled_of_user())


def _get_of(static_analysis_result_list, static_analysis_results, scenario_settings):
    scenario_datas = []
    for scenario_setting in scenario_settings:
        # get only static analysis results with the right vulnerability type
        scenarios = []
        for static_analysis_result in static_analysis_result_list:
            if static_analysis_result.vuln_type.value == scenario_setting.vuln_type.value:
                scenarios += [Scenario(scenario_setting, static_analysis_results.apk_filename, static_analysis_result)]
        if scenarios:
            scenario_datas += [ScenariosData(scenarios, static_analysis_results)]

    return scenario_datas
