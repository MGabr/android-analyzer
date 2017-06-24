$(document).ready(function(){

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

    var socket = null;

    // set up socket.io connection for receiving analysis results asynchronously
    // on successful setup, the APK is uploaded
    function ajaxUploadForAnalysis(e) {
        if (!socket) {
            socket = io.connect(null, {'port': location.port, rememberTransport: false});
            socket.on('html', updateHtml);
            socket.on('connect', doAjaxUploadForAnalysis.bind(this));
        } else {
            doAjaxUploadForAnalysis();
        }
    }

    // upload apk / start analysis on server asynchronously
    // render first full result page
    function doAjaxUploadForAnalysis() {
        formName = $(this).attr('ajax-form');
        $.ajax({
            type: $(this).attr('ajax-method'),
            url: $(this).attr('ajax-url'),

            data: new FormData($('#' + formName)[0]),
            contentType: false,
            cache: false,
            processData: false,

            success: function (data) {
                console.log("ajaxUploadForAnalysis success");
                if (data.html) {
                    $("html").html(data.html);
                }
            },
            error: function (data) {
                console.log("ajaxUploadForAnalysis error");
                // TODO: handle error
                socket.disconnect();
                socket = null;
            }
        });
    }

    function selectActivity() {
        console.log("selectActivity");
        var parent = $(this).parent();

        var aselect_id = parent[0].id;
        var aselect_class = parent.attr('class');

        parent.addClass("aselected");
        parent.children('.span-discard').remove();

        submitActivitesIfAllDecided(aselect_id, aselect_class);
    }

    function discardActivity() {
        console.log("discardActivity");
        var parent = $(this).parent();

        var aselect_id = parent[0].id;
        var aselect_class = parent.attr('class');

        parent.addClass("adiscarded");
        parent.children('.span-select').remove();

        submitActivitesIfAllDecided(aselect_id, aselect_class);
    }

    var updateHtmlCallbacks = [];

    // check if all activities of a scenario are either selected or discarded
    // if true then start dynamic analysis asynchronously
    // then start polling dynamic analysis results
    function submitActivitesIfAllDecided(aselect_id, aselect_class) {
        console.log("submitActivitiesIfAllDecided");
        var activities = $("." + aselect_class);
        var selected = activities.filter(".aselected");
        var discarded = activities.filter(".adiscarded");
        var num_undecided = activities.length - selected.length - discarded.length;
        if (num_undecided == 0) {
            if (selected.length > 0) {
                scenario_settings_id = aselect_id.split('aselect')[1].split('-')[0];
                selected_names = selected.map(function () {
                    return this.id.substring(this.id.lastIndexOf('-') + 1, this.id.length);
                }).get();

                apk_filename = aselect_id.split(scenario_settings_id + '-')[1];
                apk_filename = apk_filename.substring(0, apk_filename.lastIndexOf('-'));

                console.log("Emitting to socket");
                socket.emit("activities_analysis", {
                    "scenario_settings_id": scenario_settings_id,
                    "activities": selected_names,
                    "filename": apk_filename});
            }

            var updateHtmlCallbackClosure = function (scenario_settings_id, apk_filename) {
                return function () {
                    discarded.parent().not(".resultrow" + scenario_settings_id + "-" + apk_filename).remove();
                };
            };
            var updateHtmlCallback = updateHtmlCallbackClosure(scenario_settings_id, apk_filename);
            updateHtmlCallbacks.push(updateHtmlCallback);

        }
    }

    // update the rows in the table, handles many special cases
    function updateHtml(data) {
        if (data.html) {

            if (updateHtmlCallbacks) {
                for (var index in updateHtmlCallbacks) {
                    updateHtmlCallbacks[index]();
                }
                updateHtmlCallbacks = [];
            }

            for (var id in data.html) {

                if (id == "single_resultrow") {
                    continue;
                }

                if (id.startsWith("resultrow")) {
                    var resultrow_class = id.substring(0, id.lastIndexOf('-'));
                    if ($(document.getElementById(resultrow_class)).length) {
                        // replace result row with result row containing subresult id (with activity name)
                        $(document.getElementById(resultrow_class)).replaceWith(data.html[id]);
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
                        var resultrow_class = id.substring(0, id.lastIndexOf('-')).replace("subresultrow", "resultrow");
                        $("." + resultrow_class).after(data.html[id]);
                    }
                    // else: this is not a subresult row, only redundant data, since server doesn't know

                }
            }

            setActivityOnClickListeners();
            setPopovers();
        }
    }

    function setActivityOnClickListeners() {
        var select = $('.span-select');
        var discard = $('.span-discard');

        select.unbind('click');
        discard.unbind('click');

        select.bind('click', selectActivity);
        discard.bind('click', discardActivity);
    }

    function setPopovers() {
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
    }

    $('#add-btn').click(ajaxButtonClick);
    $('#edit-btn').click(ajaxButtonClick);
    $('#delete-btn').click(ajaxButtonClick);
    $('#login-btn').click(ajaxButtonClick);
    $('#register-btn').click(ajaxButtonClick);
    $('#logout-btn').click(ajaxButtonClick);

    $('#analysis-btn').change(ajaxUploadForAnalysis);

});

