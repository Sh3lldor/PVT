var viz;

function draw(query = "MATCH relations=()-->() RETURN relations") {
    var config = {
        container_id: "Graph",
        server_url: "bolt://localhost:7687",
        server_user: "neo4j",
        server_password: "test",
        labels: {
            "endpoints": {
                caption: "ip",
                "font": {
                    "size": 35,
                    "color": "black",
                    "face":'arial'
                }
            }
        },
        relationships: {
            "TCP": {
                caption: true,
                tickness: "weight"
            },
            "UDP": {
                caption: true,
                tickness: "weight"
            },
            "ICMP": {
                caption: true,
                tickness: "weight"
            },
            "ARP": {
                caption: true,
                tickness: "weight"
            },
            "HTTP_REQUEST": {
                caption: true,
                tickness: "weight"
            },

            [NeoVis.NEOVIS_DEFAULT_CONFIG]: {
                "thickness": "defaultThicknessProperty",
                "caption": "defaultCaption"
            }
        },
        initial_cypher: "MATCH (n)-[r:INTERACTS]->(m) RETURN n,r,m",

        initial_cypher: query,
        arrows: true,
        hierarchical_layout: true,
        hierarchical_sort_method: "directed",
        
    };

    viz = new NeoVis.default(config);
    viz.render();
}
var timeout;

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
}

function showAll() {
    $(".up").animate({ "top": '0px' });
    $(".right").animate({ "right": '0px' });
    $(".left").animate({ "left": '0px' });
}


$(".stabilize-graph").click(function() {
    //viz.();
})

$(".stabilize-graph").click(function() {
    viz.stabilize();
})

$(".command").click(function() {
    queryValue = $(this).attr("title");
    if (queryValue.includes("{}")) {

        value = prompt("Value:");
        queryValue = queryValue.replace("{}", value)
        draw(query = queryValue);

    } else {
        draw(query = queryValue);
    }
});

$(".toggle-pcap").click(function() {
    $(this).toggleClass("active");
    // View pcap in graph or not.
})