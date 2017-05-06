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

    function ajaxUploadForStaticAnalysis(e) {
        formName = $(this).attr('ajax-form');

        console.log($('#' + formName)[0]);

        $.ajax({
            type: $(this).attr('ajax-method'),
            url: $(this).attr('ajax-url'),

            data: new FormData($('#' + formName)[0]),
            contentType: false,
            cache: false,
            processData: false,

            success: function (data) {
                console.log("ajaxUploadForStaticAnalysis success");
                console.log(JSON.stringify(data));
                if (data.poll_redirect) {
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

    function pollStaticAnalysis(poll_redirect) {
        console.log("pollStaticAnalysis");

        $.ajax({
            type: 'GET',
            url: poll_redirect,
            success: function (data) {
                console.log("pollStaticAnalysis success");
                console.log(JSON.stringify(data));
                if (data && data.dynamic_analysis_url) {
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

    function startDynamicAnalysis(dynamic_analysis_url) {
        console.log("startDynamicAnalysis");

        $.ajax({
            type: 'POST',
            url: dynamic_analysis_url,
            success: function (data) {
                console.log("startDynamicAnalysis success");
                console.log(JSON.stringify(data));
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

    function pollDynamicAnalysis(poll_redirect) {
        console.log("pollDynamicAnalysis");

        $.ajax({
            type: 'GET',
            url: poll_redirect,
            success: function (data) {
                console.log("pollDynamicAnalysis success");
                console.log(JSON.stringify(data));

                if (data.result_redirect) {
                    window.location.href = data.result_redirect;
                } else {
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

    $('#add-btn').click(ajaxButtonClick);
    $('#edit-btn').click(ajaxButtonClick);
    $('#delete-btn').click(ajaxButtonClick);
    $('#login-btn').click(ajaxButtonClick);
    $('#register-btn').click(ajaxButtonClick);
    $('#logout-btn').click(ajaxButtonClick);

    $('#analysis-btn').change(ajaxUploadForStaticAnalysis)
});

