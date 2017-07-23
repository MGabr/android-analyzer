from common.models.vuln_type import VulnType
from common.services import scenario_settings_service
from common.services.template_functions import resultrow_id_for_result, subresultrow_id_for_result
from common.template_base import render_template


class ApkResultView:
    def __init__(self, apk_filename, scenario_settings_result_views):
        self.apk_filename = apk_filename
        self.scenario_settings_result_views = scenario_settings_result_views


class ScenarioSettingsResultView:
    def __init__(self,
                 scenario_settings,
                 apk_filename,
                 scenario_result_views=None,
                 _static_analysis_running=False,
                 _number_of_result_views=None,
                 _internet_perm=True,
                 _crashed_on_disass=False,
                 _crashed=False):
        self.apk_filename = apk_filename
        self.scenario_settings = scenario_settings
        self.scenario_result_views = scenario_result_views or []
        self._static_analysis_running = _static_analysis_running
        self._number_of_result_views = _number_of_result_views
        self._internet_perm = _internet_perm
        self._crashed_on_disass = _crashed_on_disass
        self._crashed = _crashed


    def requires_internet(self):
        return self._internet_perm

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

    def number_of_result_views(self):
        # sometimes (e.g during dynamic analysis) there are updates with only a single scenario_result_view
        # to not mess up table formatting, rowspan, we need the real number of scenario_result_views
        # even if they are not included now
        return self._number_of_result_views or len(self.scenario_result_views or [None])

    def crashed_on_disass(self):
        return self._crashed_on_disass

    def crashed_on_static_analysis(self):
        return self._crashed


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
            return self.log_analysis_result.dynamic_analysis_result.scenario.static_analysis_result.activity_name
        if self.static_analysis_result:
            return self.static_analysis_result.activity_name
        return None

    def is_vulnerable(self):
        return self.log_analysis_result and self.log_analysis_result.is_vulnerable

    def is_statically_vulnerable(self):
        return self.static_analysis_result or self.log_analysis_result

    def is_selected_activity(self):
        if self.activity_selected:
            return True
        if self.log_analysis_result:
            vuln_type = self.log_analysis_result.dynamic_analysis_result.scenario.static_analysis_result.vuln_type
            return  vuln_type == VulnType.selected_activities.value
        return False

    def is_activity_to_select(self):
        if self.static_analysis_result and not self.is_selected_activity():
            return self.static_analysis_result.vuln_type == VulnType.selected_activities.value
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

    def timed_out(self):
        return self.log_analysis_result and self.log_analysis_result.dynamic_analysis_result.timed_out


def render_all_scenario_settings(filenames, current_user):
    scenarios = scenario_settings_service.get_all_enabled_of_user(current_user)
    arvs = list()
    for f in filenames:
        srvs = list()
        for s in scenarios:
            srvs += [ScenarioSettingsResultView(s, f, _static_analysis_running=True)]
        arvs += [ApkResultView(f, srvs)]

    full_html = render_template('apkresults.html', apk_results=arvs)
    return full_html


def render_static_analysis_results(static_analysis_results, current_user, internet_perm=True, crashed_on_disass=False, crashed=False):
    srvs = list()
    scenarios = scenario_settings_service.get_all_enabled_of_user(current_user)
    for s in scenarios:

        single_result_for_s = [r for r in static_analysis_results.result_list if r.vuln_type == s.vuln_type.value]
        if single_result_for_s:
            single_result_for_s = [single_result_for_s[0]]

        rvs = [ScenarioResultView(static_analysis_result=r,
                                  _dynamic_analysis_running=r.vuln_type != VulnType.selected_activities.value)
               for r in single_result_for_s]

        srvs += [ScenarioSettingsResultView(s,
                                            static_analysis_results.apk_filename,
                                            scenario_result_views=rvs,
                                            _internet_perm=internet_perm,
                                            _crashed_on_disass=crashed_on_disass,
                                            _crashed=crashed)]

    return _html_dict(srvs, only_first_as_resultrow=True)


def render_scenario_datas(scenario_datas):
    srvs = list()
    for scenario_data in scenario_datas:
        rvs = [ScenarioResultView(
            static_analysis_result=r.static_analysis_result,
            _dynamic_analysis_running=r.static_analysis_result.vuln_type != VulnType.selected_activities.value)
               for r in scenario_data.scenario_list]

        srvs += [ScenarioSettingsResultView(
            scenario_data.scenario_list[0].scenario_settings,
            scenario_data.apk_filename,
            scenario_result_views=rvs)]

    return _html_dict(srvs, only_first_as_resultrow=True)


def render_selected_activities(scenarios, scenario_settings_id, current_user):
    scenario = scenario_settings_service.get_of_user(scenario_settings_id, current_user)

    results = [s.static_analysis_result for s in scenarios.scenario_list]
    result_list_for_s = [r for r in results if r.vuln_type == VulnType.selected_activities.value]
    rvs = [ScenarioResultView(static_analysis_result=r, activity_selected=True, _dynamic_analysis_running=True)
           for r in result_list_for_s]

    srvs = [ScenarioSettingsResultView(scenario, scenarios.apk_filename, scenario_result_views=rvs)]

    return _html_dict(srvs, only_first_as_resultrow=True)


def render_log_analysis_results(log_analysis_results, total_log_analysis_results_number=None):
    srvs = list()
    for s in {r.dynamic_analysis_result.scenario.scenario_settings for r in log_analysis_results}:
        log_analysis_results_for_s = [r for r in log_analysis_results
                                      if r.dynamic_analysis_result.scenario.scenario_settings.id == s.id]
        rvs = [ScenarioResultView(log_analysis_result=r) for r in log_analysis_results_for_s]
        apk_filename = log_analysis_results_for_s[0].dynamic_analysis_result.scenario.apk_filename
        srvs += [ScenarioSettingsResultView(
            s,
            apk_filename,
            scenario_result_views=rvs,
            _number_of_result_views=total_log_analysis_results_number)]

    return _html_dict(srvs)


def _html_dict(srvs, only_first_as_resultrow=False):
    html = dict()
    for srv in srvs:
        for index, r in enumerate(srv.scenario_result_views):
            if not only_first_as_resultrow or index == 0:
                result_row_id = resultrow_id_for_result(srv, r)
                html[result_row_id] = render_template('partials/resultrow.html', results=srv, result=r)
            if not only_first_as_resultrow or index > 0:
                subresult_row_id = subresultrow_id_for_result(srv, r)
                html[subresult_row_id] = render_template('partials/subresultrow.html', results=srv, result=r)

        if not srv.scenario_result_views:
            result_row_id = resultrow_id_for_result(srv, None)
            html[result_row_id] = render_template('partials/resultrow.html', results=srv, result=None)

    # TODO: possible error?
    html["single_resultrow"] = only_first_as_resultrow

    return html
