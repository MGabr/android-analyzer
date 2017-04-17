def context_processor():

    def display_comma_joined(set):
        return ", ".join(set)

    def display_br_joined(set):
        return "<br />".join(set)

    def display_nl_joined(set):
        return "\n".join(set)

    def row_class_for_result(lar):
        if lar.is_vulnerable():
            return "danger"
        elif lar.is_statically_vulnerable():
            return "warning"
        else:
            return "success"
            # TODO: for crashed analysis

    def glyphicon_for_static_result(lar):
        if lar.is_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        elif lar.is_statically_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        else:
            return "glyphicon glyphicon-ok text-success"
            # TODO: for crashed analysis

    def glyphicon_for_dynamic_result(lar):
        if lar.is_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        elif lar.is_statically_vulnerable():
            return "glyphicon glyphicon-ok text-success"
        else:
            return "glyphicon glyphicon-minus text-muted"
            # TODO: for crashed analysis

    def _vulntype_for_result(lar):
        return lar.dynamic_analysis_result.scenario.scenario_settings.vuln_type.value

    def vulntype_for_result(lar):
        return _vulntype_for_result(lar)

    def vulntype_tooltiptitle_for_result(lar):
        if lar.is_statically_vulnerable():
            return "App might be vulnerable!"
        else:
            return "App not vulnerable"

    # TODO: check for definitive static vulnerabilities, not just custom implementations
    # TODO: check if custom implementations in framework code are detected
    def vulntype_tooltip_for_result(lar):
        if lar.is_statically_vulnerable():
            return '''
            The app has a custom implementation of the {clazz} class.<br />
            Such implementations are often vulnerable to MITM attacks.
            '''.format(clazz=_vulntype_for_result(lar))
        else:
            return '''
            The app has no custom implementation of the {clazz} class.<br />
            Vulnerabilities due to custom implementations of this class can be ruled out.
            '''.format(clazz=_vulntype_for_result(lar))

    def _display_connected_ips_hostnames(lar):
        return display_br_joined(
            [display_comma_joined(lar.connected_hostnames_ips[hostname]) + " (" + hostname + ")"
             for hostname in lar.connected_hostnames_ips])

    def connected_hostnames_for_result(lar):
        return display_nl_joined(
            lar.connected_hostnames_ips.keys()) or ""

    def connected_hostnames_tooltiptitle_for_result(lar):
        if lar.is_vulnerable():
            return "App successfully attacked!"
        elif lar.is_statically_vulnerable() or lar.dynamic_analysis_result.has_been_run():
            return "Attack unsuccessful"
        else:
            return "App was not attacked"

    # TODO: more detailed error message if only statically vulnerable
    # TODO: find out if an analysis crashed
    def connected_hostnames_tooltip_for_result(lar):
        if lar.is_vulnerable():
            return '''
            The app is vulnerable to a Man-in-the-Middle attack.<br />
            Requests to the following IPs/hostnames could be intercepted:<br />
            {ip_hns}
            '''.format(ip_hns=_display_connected_ips_hostnames(lar))
        elif lar.is_statically_vulnerable():
            return '''
            Dynamic analysis could not show that the app is vulnerable to a Man-in-the-Middle attack.<br />
            No requests could be successfully intercepted.<br />
            Note that the custom implementation of the {ip_hns} class might still not be secure.
            <br />
            '''.format(ip_hns=_display_connected_ips_hostnames(lar))
        elif lar.dynamic_analysis_result.has_been_run():
            return '''
            Dynamic analysis could not show that the app is vulnerable to a Man-in-the-Middle attack.<br />
            No requests could be successfully intercepted.<br />
            Note that the app might still not be secure.
            '''
        else:
            return '''
            Dynamic analysis was not run, because no statical vulnerabilities have been found.
            '''

    def certificate_name_for_result(lar):
        return lar.dynamic_analysis_result.scenario.scenario_settings.mitm_certificate.name or ""

    def trusted_certificate_names_for_result(lar):
        return display_nl_joined(
            [sc.name
             for sc
             in lar.dynamic_analysis_result.scenario.scenario_settings.sys_certificates]) or ""

    return dict(
        display_comma_joined=display_comma_joined,
        row_class_for_result=row_class_for_result,
        glyphicon_for_static_result=glyphicon_for_static_result,
        glyphicon_for_dynamic_result=glyphicon_for_dynamic_result,
        vulntype_for_result=vulntype_for_result,
        vulntype_tooltip_for_result=vulntype_tooltip_for_result,
        vulntype_tooltiptitle_for_result=vulntype_tooltiptitle_for_result,
        connected_hostnames_for_result=connected_hostnames_for_result,
        connected_hostnames_tooltip_for_result=connected_hostnames_tooltip_for_result,
        connected_hostnames_tooltiptitle_for_result=connected_hostnames_tooltiptitle_for_result,
        certificate_name_for_result=certificate_name_for_result,
        trusted_certificate_names_for_result=trusted_certificate_names_for_result)
