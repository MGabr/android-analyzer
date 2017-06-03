def context_processor():

    def display_comma_joined(set):
        return ", ".join(set)

    def display_br_joined(set):
        return "<br />".join(set)

    def display_nl_joined(set):
        return "\n".join(set)

    # TODO: where to use?
    def row_class_for_result(r):
        if r.is_vulnerable():
            return "danger"
        elif r.is_statically_vulnerable():
            return "warning"
        elif r.static_analysis_running() or r.dynamic_analysis_running():
            return "muted"
        else:
            return "success"
            # TODO: for crashed analysis

    def glyphicon_for_static_result(srv):
        if srv.has_activity_to_select() or srv.has_selected_activity():
            return "glyphicon glyphicon-list text-muted"
        if srv.is_vulnerable() or srv.is_statically_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        elif srv.static_analysis_running():
            return "glyphicon glyphicon-hourglass text-muted"
        else:
            return "glyphicon glyphicon-ok text-success"

    def glyphicon_for_dynamic_result(r):
        if r.timed_out():
            return "glyphicon glyphicon-time text-muted"
        elif r.is_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        elif r.dynamic_analysis_running():
            return "glyphicon glyphicon-hourglass text-muted"
        elif r.is_statically_vulnerable():
            return "glyphicon glyphicon-ok text-success"
        elif r.crashed_on_run() or r.crashed_on_setup():
            return "glyphicon glyphicon-fire text-muted"
        else:
            return "glyphicon glyphicon-minus text-muted"

    def _vulntype_for_result(srv):
        return srv.scenario_settings.vuln_type.value

    def vulntype_for_result(srv):
        return _vulntype_for_result(srv)

    def vulntype_tooltiptitle_for_result(srv):
        if srv.static_analysis_running():
            return "App is currently analysed"
        elif srv.has_activity_to_select():
            return "Selected activities of app will be analysed"
        elif srv.has_selected_activity():
            return "Selected activities of app are analysed"
        elif srv.is_statically_vulnerable():
            return "App might be vulnerable!"
        else:
            return "App not vulnerable"

    # TODO: check for definitive static vulnerabilities, not just custom implementations
    # TODO: check if custom implementations in framework code are detected
    def vulntype_tooltip_for_result(srv):
        if srv.static_analysis_running():
            return "The app is currently analysed statically."
        elif srv.has_activity_to_select():
            return '''
            This scenario has no static analysis for custom implementations.<br />
            It instead analyses selected activities.<br />
            Select the activities that should be analysed.<br />
            Removed those that should not be analysed.
            '''
        elif srv.has_selected_activity():
            return '''
            This scenario has no static analysis for custom implementations.<br />
            It instead analyses selected activities.
            '''
        elif srv.is_statically_vulnerable():
            return '''
            The app has a custom implementation of the {clazz} class.<br />
            Such implementations are often vulnerable to MITM attacks.
            '''.format(clazz=_vulntype_for_result(srv))
        else:
            return '''
            The app has no custom implementation of the {clazz} class.<br />
            Vulnerabilities due to custom implementations of this class can be ruled out.
            '''.format(clazz=_vulntype_for_result(srv))

    def subresultrow_id_for_result(srv, r):
        activity_name = "-" + r.activity_name() if r else ""
        return "subresultrow" + str(srv.scenario_settings.id) + activity_name

    def resultrow_id_for_result(srv, r):
        activity_name = "-" + r.activity_name() if r else ""
        return "resultrow" + str(srv.scenario_settings.id) + activity_name

    def resultrow_class_for_result(srv):
        return "resultrow" + str(srv.scenario_settings.id)

    def activityselect_id_for_result(srv, r):
        return "aselect" + str(srv.scenario_settings.id) + "-" + r.activity_name()

    def activityselect_class_for_result(srv):
        if srv.has_activity_to_select():
            return "aselect" + str(srv.scenario_settings.id)
        return ""

    def _display_connected_hostnames(r):
        connected_hosts = None
        if r.log_analysis_result:
            connected_hosts = [host for host in r.log_analysis_result.connected_hosts if not 'http://' in host]
        return display_br_joined(connected_hosts or [])

    def _display_connected_http_hostnames_str(r):
        connected_hosts = None
        if r.log_analysis_result:
            connected_hosts = [host for host in r.log_analysis_result.connected_hosts if 'http://' in host]
        if connected_hosts:
            return '''<br />
            Additionally HTTP requests to the following URLs were made:<br />
            {hns}
            '''.format(hns=display_br_joined(connected_hosts or []))
        return ""

    def connected_hostnames_for_result(r):
        connected_hosts = None
        if r.log_analysis_result:
            connected_hosts = r.log_analysis_result.connected_hosts
        return display_nl_joined(connected_hosts or []) or ""

    def connected_hostnames_tooltiptitle_for_result(r):
        if r.timed_out():
            return "Analysis has timed out"
        elif r.dynamic_analysis_running():
            return "App is currently analysed"
        elif r.is_vulnerable():
            return "App successfully attacked!"
        elif r.is_statically_vulnerable() and r.dynamic_analysis_has_been_run():
            return "Attack unsuccessful"
        elif r.crashed_on_setup() or r.crashed_on_run():
            return "Analysis has crashed"
        else:
            return "App was not attacked"

    # TODO: more detailed error message if only statically vulnerable
    def connected_hostnames_tooltip_for_result(r, srv):
        if r.timed_out():
            return "Dynamic analysis has timed out"
        elif r.dynamic_analysis_running():
            return "The app is currently analysed dynamically"
        elif r.is_vulnerable():
            return '''
            The app is vulnerable to a Man-in-the-Middle attack.<br />
            Requests to the following hostnames could be intercepted:<br />
            {hns}{hhns}
            '''.format(hns=_display_connected_hostnames(r), hhns=_display_connected_http_hostnames_str(r))
        elif r.is_statically_vulnerable():
            return '''
            Dynamic analysis could not show that the app is vulnerable to a Man-in-the-Middle attack.<br />
            No requests could be successfully intercepted.<br />
            Note that the custom implementation of the {clazz} class might still not be secure.
            <br />
            '''.format(clazz=_vulntype_for_result(srv))
        elif r.dynamic_analysis_has_been_run():
            return '''
            Dynamic analysis could not show that the app is vulnerable to a Man-in-the-Middle attack.<br />
            No requests could be successfully intercepted.<br />
            Note that the app might still not be secure.
            '''
        elif r.crashed_on_setup() or r.crashed_on_run():
            return '''
            Dynamic analysis has crashed.
            '''
        else:
            return '''
            Dynamic analysis was not run, because no statical vulnerabilities have been found.
            '''

    return dict(
        display_comma_joined=display_comma_joined,
        row_class_for_result=row_class_for_result,
        glyphicon_for_static_result=glyphicon_for_static_result,
        glyphicon_for_dynamic_result=glyphicon_for_dynamic_result,
        vulntype_for_result=vulntype_for_result,
        vulntype_tooltip_for_result=vulntype_tooltip_for_result,
        vulntype_tooltiptitle_for_result=vulntype_tooltiptitle_for_result,
        subresultrow_id_for_result=subresultrow_id_for_result,
        resultrow_id_for_result=resultrow_id_for_result,
        resultrow_class_for_result=resultrow_class_for_result,
        activityselect_id_for_result=activityselect_id_for_result,
        activityselect_class_for_result=activityselect_class_for_result,
        connected_hostnames_for_result=connected_hostnames_for_result,
        connected_hostnames_tooltip_for_result=connected_hostnames_tooltip_for_result,
        connected_hostnames_tooltiptitle_for_result=connected_hostnames_tooltiptitle_for_result)
