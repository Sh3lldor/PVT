$(document).ready(function() {

    draw();

    this.addEventListener("keyup", function(event) {
        // Number 13 is the "Enter" key on the keyboard
        if (!$(".modern-input").is(":focus")) {
            if (event.key == "f") {
                showAll();
                $(".modern-input").focus();
            } else if (event.keyCode == 27) {
                hideAll();
                $(".modern-input").blur();
            } else if (event.key == 's') {
                viz.stabilize();
            } else {
                showAll();
            }

        } else {
            if (event.keyCode == 13) {
                queryValue = document.getElementById("query").value;
                if (queryValue == "") {
                    draw()
                } else {
                    draw(query = queryValue)
                }
                hideAll();
                $(".modern-input").blur();
            } else if (event.keyCode == 27) {
                hideAll();
                $(".modern-input").blur();
            }
        }
    });
});

function hideAll() {
    $(".up").animate({ "top": '-95px' });
    $(".right").animate({ "right": '-200px' });
    $(".left").animate({ "left": '-1000px' });
    $(".down").animate({ "bottom": '-200px' });
}

function showAll() {
    $(".up").animate({ "top": '0px' });
    $(".right").animate({ "right": '0px' });
    $(".left").animate({ "left": '0px' });
    $(".down").animate({ "bottom": '0px' });
}

$(".command").click(function() {
    queryValue = $(this).attr("title");
    if (queryValue.includes("{}")) {

        value = prompt("Source IP:");
        queryValue = queryValue.replace("{}", value)
        value = prompt("Destination IP:");
        queryValue = queryValue.replace("{x}", value)

        draw(query = queryValue);

    } else {
        draw(query = queryValue);
    }
});

$(".toggle-pcap").click(function(e) {
    if (e.target !== this)
        return;

    $(this).toggleClass("active");
    // TODO: View pcap in graph or not.
})

$(".remove-pcap").click(function() {
    confirm("Remove pcap?");
    var pcap = $(this).parent().text();

    // TODO: Remove pcap
})

$(".toggle-opt").click(function() {
    $(this).toggleClass("active");
    // TODO: View pcap in graph or not.
})

$(".import-btn").click(function() {
    /* start_loader(); */
    /* run start_loader after the new page has loaded in the right corner and add refresh button */
    $("#upload-file").click();
})

$(".opt.toggle-opt").click(function() {
    var protocol = $(this).attr("title");
    var index = matchQuery.indexOf("]")
    if ($(this).hasClass("active")) { // Filter turned on
        if (index == initialIndex) {
            matchQuery = matchQuery.substring(0, index) + protocol + matchQuery.substring(index)
        } else {
            matchQuery = matchQuery.substring(0, index) + "|" + protocol + matchQuery.substring(index)
        }
        draw(query = matchQuery)
    } else { // Filter turned off
        if (matchQuery.includes("|" + protocol)) {
            matchQuery = matchQuery.replace("|" + protocol, "")
            draw(query = matchQuery)
        } else if (matchQuery.includes(":" + protocol + "|")) {
            matchQuery = matchQuery.replace(protocol + "|", "")
            draw(query = matchQuery)
        } else if (matchQuery.includes(":" + protocol)) {
            matchQuery = matchQuery.replace(protocol, "")
            draw()
        }
    }
})

function start_loader() {
    $(".loader").show();
    $(".query").addClass("darken");
    $("#Graph").addClass("darken");
}

function stop_loader() {
    $(".loader").hide();
    $(".query").removeClass("darken");
    $("#Graph").removeClass("darken");
}


socket.on("update", (percent) => {
    //console.log(percent + "%")
    document.getElementById("percentage").innerHTML = percent
    if (percent == 100) {
        window.location.href = "/";
    }
});

socket.on("finish", () => {
    //window.location.href = "/";
    //alert("DONE!");
    start_loader();
});