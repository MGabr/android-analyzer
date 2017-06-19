from common.dto.static_analysis import StaticAnalysisResult
from common.dto_dependency_loader import asinstanceof, asinstancesof, DtoDependencyLoader
from common.models.scenario_settings import ScenarioSettings


class Scenario:
    def __init__(self, scenario_settings, apk_filename, static_analysis_result, scenario_settings_id=None):
        self.scenario_settings = DtoDependencyLoader.load_if_none(
            scenario_settings,
            scenario_settings_id,
            ScenarioSettings)
        self.apk_filename = apk_filename
        self.static_analysis_result = asinstanceof(static_analysis_result, StaticAnalysisResult)

    def __json__(self):
        return {
            'scenario_settings': None,
            'scenario_settings_id': self.scenario_settings.id,
            'apk_filename': self.apk_filename,
            'static_analysis_result': self.static_analysis_result}


# per scenario_settings, only in Scenario because of legacy code
class ScenariosData:
    def __init__(self, scenario_list, apk_filename, package, min_sdk_version, target_sdk_version):
        self.scenario_list = asinstancesof(scenario_list, Scenario)

        # general information from static analysis valid for all scenarios
        self.apk_filename = apk_filename
        self.package = package
        self.min_sdk_version = min_sdk_version
        self.target_sdk_version = target_sdk_version

    def __json__(self):
        return {
            'scenario_list': self.scenario_list,
            'apk_filename': self.apk_filename,
            'package': self.package,
            'min_sdk_version': self.min_sdk_version,
            'target_sdk_version': self.target_sdk_version}

