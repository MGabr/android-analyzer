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
            data: formName ? $(formName).serialize() : '',
            success: function(data) {
                console.log(JSON.stringify(data));
                console.log("redirect: " + data.redirect);
                window.location.href = data.redirect;
            },
            error: function(data) {
                // TODO: handle error
            }
        });
    }

    $('#add-btn').click(ajaxButtonClick);
    $('#edit-btn').click(ajaxButtonClick);
    $('#delete-btn').click(ajaxButtonClick);
});

