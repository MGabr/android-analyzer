$(document).ready(function(){

    $('.text-danger[data-toggle="popover"]').popover({
        html: true,
        template: '<div class="popover"><div class="arrow"></div><h3 class="popover-title popover-title-danger"></h3><div class="popover-content"></div></div>'
    });
    $('.text-success[data-toggle="popover"]').popover({
        html: true,
        template: '<div class="popover"><div class="arrow"></div><h3 class="popover-title popover-title-success"></h3><div class="popover-content"></div></div>'
    });
    $('.text-muted[data-toggle="popover"]').popover({
        html: true,
        template: '<div class="popover"><div class="arrow"></div><h3 class="popover-title popover-title-muted"></h3><div class="popover-content"></div></div>'
    });

    // for general ajax buttons
    function ajaxButtonClick(e) {
        e.preventDefault();
        e.defaultPrevented = true;
        formName = $(this).attr('ajax-form');
        $.ajax({
            type: $(this).attr('ajax-method'),
            url: $(this).attr('ajax-url'),
            data: formName ? $('#' + formName).serialize() : '',
            success: function(data) {
                if (data.redirect) {
                    window.location.href = data.redirect;
                }
            },
            error: function(data) {
                // TODO: handle error
            }
        });
    }

    // upload apk / start static analysis on server asynchronously
    // render first full result page
    // start polling static analysis
    function ajaxUploadForStaticAnalysis(e) {
        formName = $(this).attr('ajax-form');

        $.ajax({
            type: $(this).attr('ajax-method'),
            url: $(this).attr('ajax-url'),

            data: new FormData($('#' + formName)[0]),
            contentType: false,
            cache: false,
            processData: false,

            success: function (data) {
                console.log("ajaxUploadForStaticAnalysis success");

                if (data.error) {
                    // TODO: handle error
                } else if (data.poll_redirect) {

                    $("html").html(data.html);

                    setTimeout(function () {
                        pollStaticAnalysis(data.poll_redirect)
                    }, 10 * 1000);
                }
            },
            error: function (data) {
                console.log("ajaxUploadForStaticAnalysis error");
                // TODO: handle error
            }
        });
    }

    // poll static analysis asynchronously
    // replace all result rows matched by scenario settings id
    // start dynamic analysis asynchronously if static analysis successful
    function pollStaticAnalysis(poll_redirect) {
        console.log("pollStaticAnalysis");

        $.ajax({
            type: 'GET',
            url: poll_redirect,
            success: function (data) {
                console.log("pollStaticAnalysis success");

                updateHtml(data);

                if (data.error) {
                    // TODO: handle error
                } else if (data && data.dynamic_analysis_url && data.activities_dynamic_analysis_url) {
                    setActivityOnClickListeners(data.activities_dynamic_analysis_url);
                    startDynamicAnalysis(data.dynamic_analysis_url);
                } else {
                    setTimeout(function () {
                        pollStaticAnalysis(poll_redirect);
                    }, 10 * 1000);
                }

            },
            error: function (data) {
                console.log("pollStaticAnalysis error");
                // TODO: handle error
            }
        })
    }

    // start dynamic analysis asynchronously
    // start polling dynamic analysis results
    function startDynamicAnalysis(dynamic_analysis_url) {
        console.log("startDynamicAnalysis");

        $.ajax({
            type: 'POST',
            url: dynamic_analysis_url,
            success: function (data) {
                console.log("startDynamicAnalysis success");

                if (data.poll_redirect) {
                    setTimeout(function () {
                        pollDynamicAnalysis(data.poll_redirect)
                    }, 10 * 1000);
                }

            },
            error: function (data) {
                console.log("startDynamicAnalysis error");
                // TODO: handle error
            }
        })
    }

    // poll dynamic analysis results until success or crash of all dynamic analyses
    // replace all result rows matched by scenario settings id
    function pollDynamicAnalysis(poll_redirect) {
        console.log("pollDynamicAnalysis");

        $.ajax({
            type: 'GET',
            url: poll_redirect,
            success: function (data) {
                console.log("pollDynamicAnalysis success");

                updateHtml(data);

                if (!data.finished) {
                    setTimeout(function () {
                        pollDynamicAnalysis(poll_redirect);
                    }, 10 * 1000);
                }
            },
            error: function (data) {
                console.log("pollDynamicAnalysis error");
                // TODO: handle error
            }
        })
    }

    function selectActivityFn(activities_dynamic_analysis_url) {
        return function () {
            console.log("selectActivity");
            var parent = $(this).parent();

            var aselect_id = parent[0].id;
            var aselect_class = parent.attr('class');

            parent.addClass("aselected");
            parent.children('.span-discard').remove();

            submitActivitesIfAllDecided(aselect_id, aselect_class, activities_dynamic_analysis_url);
        }
    }

    function discardActivityFn(activities_dynamic_analysis_url) {
        return function () {
            console.log("discardActivity");
            var parent = $(this).parent();

            var aselect_id = parent[0].id;
            var aselect_class = parent.attr('class');

            parent.addClass("adiscarded");
            parent.children('.span-select').remove();

            submitActivitesIfAllDecided(aselect_id, aselect_class, activities_dynamic_analysis_url);
        }
    }

    // check if all activities of a scenario are either selected or discarded
    // if true then start dynamic analysis asynchronously
    // then start polling dynamic analysis results
    function submitActivitesIfAllDecided(aselect_id, aselect_class, activities_dynamic_analysis_url) {
        console.log("submitActivitiesIfAllDecided");
        var activities = $("." + aselect_class);
        var selected = activities.filter(".aselected");
        var discarded = activities.filter(".adiscarded");
        var num_undecided = activities.length - selected.length - discarded.length;
        if (num_undecided == 0) {
            scenario_settings_id = aselect_id.split('aselect')[1].split('-')[0];
            selected_names = selected.map(function () {
                return this.id.split('aselect')[1].split('-')[1];
            });

            $.ajax({
                type: 'POST',
                url: activities_dynamic_analysis_url.replace("replace", scenario_settings_id),
                data: JSON.stringify(selected_names.get()),
                contentType: 'application/json',
                success: function (data) {
                    console.log("selectActivity success");

                    discarded.parent().not(".resultrow" + scenario_settings_id).remove();
                    updateHtml(data);

                    if (data.poll_redirect) {
                        setTimeout(function () {
                            pollDynamicAnalysis(data.poll_redirect)
                        }, 10 * 1000);
                    }

                },
                error: function (data) {
                    console.log("selectActivity error");
                    // TODO: handle error
                }
            })
        }
    }

    function updateHtml(data) {
        if (data.html) {

            for (var id in data.html) {

                if (id == "single_resultrow") {
                    continue;
                }

                if (id.startsWith("resultrow")) {
                    var resultrow_class = id.split('-')[0];
                    if ($("#" + resultrow_class).length) {
                        // replace result row with result row containing subresult id (with activity name)
                        $("#" + resultrow_class).replaceWith(data.html[id]);
                    } else if ($(document.getElementById(id)).length) {
                        // replace result row with subresult id with new result row
                        $(document.getElementById(id)).replaceWith(data.html[id]);
                    } else if ("single_resultrow" in data.html && data.html["single_resultrow"]) {
                        // replace result row with subresult id with other result row with subresult id
                        $(document.getElementById(id.replace("resultrow", "subresultrow"))).remove();
                        $("." + resultrow_class).replaceWith(data.html[id]);
                    }
                    // else: this is not a result row, only redundant data, since server doesn't know

                } else if (id.startsWith("subresultrow")) {
                    if ($(document.getElementById(id)).length) {
                        // replace subresult row
                        $(document.getElementById(id)).replaceWith(data.html[id]);
                    } else if (!$(document.getElementById(id.replace("subresultrow", "resultrow"))).length) {
                        // insert after result row
                        var resultrow_class = id.replace("subresultrow", "resultrow").split('-')[0];
                        $("." + resultrow_class).after(data.html[id]);
                    }
                    // else: this is not a subresult row, only redundant data, since server doesn't know

                }
            }
        }
    }

    function setActivityOnClickListeners(activities_dynamic_analysis_url) {
        $('.span-select').click(selectActivityFn(activities_dynamic_analysis_url));
        $('.span-discard').click(discardActivityFn(activities_dynamic_analysis_url));
    }

    $('#add-btn').click(ajaxButtonClick);
    $('#edit-btn').click(ajaxButtonClick);
    $('#delete-btn').click(ajaxButtonClick);
    $('#login-btn').click(ajaxButtonClick);
    $('#register-btn').click(ajaxButtonClick);
    $('#logout-btn').click(ajaxButtonClick);

    $('#analysis-btn').change(ajaxUploadForStaticAnalysis);

});

