from src.models.vuln_type import VulnType
from src.services import scenario_settings_service
from flask import render_template


class ScenarioSettingsResultView:
    def __init__(self, scenario_settings, scenario_result_views=None, _static_analysis_running=False):
        self.scenario_settings = scenario_settings
        self.scenario_result_views = scenario_result_views or []
        self._static_analysis_running = _static_analysis_running

    def is_vulnerable(self):
        for r in self.scenario_result_views:
            if r.is_vulnerable():
                return True
        return False

    def is_statically_vulnerable(self):
        for r in self.scenario_result_views:
            if r.is_statically_vulnerable():
                return True
        return False

    def has_selected_activity(self):
        for r in self.scenario_result_views:
            if r.is_selected_activity():
                return True
        return False

    def has_activity_to_select(self):
        for r in self.scenario_result_views:
            if r.is_activity_to_select():
                return True
        return False

    def static_analysis_running(self):
        return self._static_analysis_running


class ScenarioResultView:
    def __init__(
            self,
            static_analysis_result=None,
            log_analysis_result=None,
            activity_selected=False,
            _dynamic_analysis_running=False):
        self.static_analysis_result = static_analysis_result
        self.log_analysis_result = log_analysis_result
        self.activity_selected = activity_selected
        self._dynamic_analysis_running = _dynamic_analysis_running

    def activity_name(self):
        if self.log_analysis_result:
            return self.log_analysis_result.dynamic_analysis_result.scenario.activity_name
        if self.static_analysis_result:
            return self.static_analysis_result.meth_nm
        return None

    def is_vulnerable(self):
        return self.log_analysis_result and self.log_analysis_result.is_vulnerable

    def is_statically_vulnerable(self):
        if self.static_analysis_result:
            return True
        return self.log_analysis_result and self.log_analysis_result.is_statically_vulnerable

    def is_selected_activity(self):
        if self.activity_selected:
            return True
        if self.log_analysis_result and self.log_analysis_result.is_statically_vulnerable:
            result_list = self.log_analysis_result.dynamic_analysis_result.scenario.static_analysis_results.result_list
            return bool([r for r in result_list if r.vuln_type.value == VulnType.selected_activities.value])
        return False

    def is_activity_to_select(self):
        if self.static_analysis_result and not self.is_selected_activity():
            return self.static_analysis_result.vuln_type.value == VulnType.selected_activities.value
        return False

    def dynamic_analysis_running(self):
        if self._dynamic_analysis_running:
            return True
        return self.log_analysis_result and self.log_analysis_result.dynamic_analysis_result.is_running

    def dynamic_analysis_has_been_run(self):
        return self.log_analysis_result and self.log_analysis_result.dynamic_analysis_result.has_been_run

    def crashed_on_run(self):
        return self.log_analysis_result and self.log_analysis_result.dynamic_analysis_result.crashed_on_run

    def crashed_on_setup(self):
        return self.log_analysis_result and self.log_analysis_result.dynamic_analysis_result.crashed_on_setup


def render_all_scenario_settings():
    srvs = list()
    scenarios = scenario_settings_service.get_all_enabled_of_user()
    for s in scenarios:
        srvs += [ScenarioSettingsResultView(s, _static_analysis_running=True)]

    full_html = render_template('results.html', results=srvs)
    return full_html


def render_static_analysis_results(static_analysis_results):
    srvs = list()
    scenarios = scenario_settings_service.get_all_enabled_of_user()
    for s in scenarios:
        result_list_for_s = [r for r in static_analysis_results.result_list if r.vuln_type.value == s.vuln_type.value]
        rvs = [ScenarioResultView(static_analysis_result=r,
                                  _dynamic_analysis_running=r.vuln_type.value != VulnType.selected_activities.value)
               for r in result_list_for_s]
        srvs += [ScenarioSettingsResultView(s, scenario_result_views=rvs)]

    return _html_dict(srvs, only_first_as_resultrow=True)


def render_selected_activities(scenarios, scenario_settings_id):
    flatten = lambda l: [item for sublist in l for item in sublist]

    results = flatten([r.result_list for r in [s.static_analysis_results for s in scenarios.scenarios]])

    srvs = list()
    scenario = scenario_settings_service.get_of_user(scenario_settings_id)
    result_list_for_s = [r for r in results
                         if r.vuln_type.value == VulnType.selected_activities.value]
    rvs = [ScenarioResultView(static_analysis_result=r,
                              activity_selected=True,
                              _dynamic_analysis_running=True)
           for r in result_list_for_s]
    srvs += [ScenarioSettingsResultView(scenario, scenario_result_views=rvs)]

    return _html_dict(srvs, only_first_as_resultrow=True)


def render_log_analysis_results(log_analysis_results):
    srvs = list()
    for s in {r.dynamic_analysis_result.scenario.scenario_settings for r in log_analysis_results}:
        log_analysis_results_for_s = [r for r in log_analysis_results
                                      if r.dynamic_analysis_result.scenario.scenario_settings.id == s.id]
        rvs = [ScenarioResultView(log_analysis_result=r) for r in log_analysis_results_for_s]
        srvs += [ScenarioSettingsResultView(s, scenario_result_views=rvs)]

    return _html_dict(srvs)


def _html_dict(srvs, only_first_as_resultrow=False):
    html = dict()
    for srv in srvs:

        for index, r in enumerate(srv.scenario_result_views):
            if not only_first_as_resultrow or index == 0:
                result_row_id = "resultrow" + str(srv.scenario_settings.id) + "-" + r.activity_name()
                html[result_row_id] = render_template('partials/resultrow.html', results=srv, result=r)
            if not only_first_as_resultrow or index > 0:
                subresult_row_id = "subresultrow" + str(srv.scenario_settings.id) + "-" + r.activity_name()
                html[subresult_row_id] = render_template('partials/subresultrow.html', results=srv, result=r)

        if not srv.scenario_result_views:
            result_row_id = "resultrow" + str(srv.scenario_settings.id)
            html[result_row_id] = render_template('partials/resultrow.html', results=srv, result=None)

    html["single_resultrow"] = only_first_as_resultrow

    return html
