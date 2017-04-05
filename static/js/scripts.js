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
});