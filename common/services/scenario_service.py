from common.dto.scenario import Scenario, ScenariosData
from common.models.vuln_type import VulnType

from src.services.scenario_settings_service import get_all_enabled_of_user


def has_activities_to_select(static_analysis_results, current_user):
    filtered_result_list = [r for r in static_analysis_results.result_list
                            if r.vuln_type == VulnType.selected_activities.value]
    return bool(_get_of(filtered_result_list, static_analysis_results, get_all_enabled_of_user(current_user)))


def get_for_choosen_activities_and_settings(
        static_analysis_results,
        choosen_activities,
        scenario_settings_id,
        current_user):
    filtered_result_list = [r for r in static_analysis_results.result_list if r.activity_name in choosen_activities]
    filtered_settings = [s for s in get_all_enabled_of_user(current_user) if s.id == int(scenario_settings_id)]
    return _get_of(filtered_result_list, static_analysis_results, filtered_settings)


def get_all_of_user(static_analysis_results, current_user):
    filtered_result_list = [r for r in static_analysis_results.result_list
                            if r.vuln_type != VulnType.selected_activities.value]
    return _get_of(filtered_result_list, static_analysis_results, get_all_enabled_of_user(current_user))


def _get_of(static_analysis_result_list, static_analysis_results, scenario_settings):
    scenario_datas = []
    for scenario_setting in scenario_settings:
        scenarios = []

        # get only static analysis results with the right vulnerability type
        for static_analysis_result in static_analysis_result_list:
            if static_analysis_result.vuln_type == scenario_setting.vuln_type.value:
                if not scenario_setting.only_exported_activities or static_analysis_result.exported:
                    scenarios += [Scenario(scenario_setting, static_analysis_results.apk_filename, static_analysis_result)]

        if scenarios:
            # only analyse the first num_activities_limit scenarios
            if scenario_setting.num_activities_limit:
                scenarios = scenarios[:scenario_setting.num_activities_limit]

            scenario_datas += [ScenariosData(
                scenarios,
                static_analysis_results.apk_filename,
                static_analysis_results.package,
                static_analysis_results.min_sdk_version,
                static_analysis_results.target_sdk_version)]

    return scenario_datas
