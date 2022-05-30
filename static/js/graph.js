var viz;
var timeout;

$(document).ready(function() {
    draw();
});

$(document).ready(function() {

    this.addEventListener("keyup", function(event) {
        // Number 13 is the "Enter" key on the keyboard
        if (!$(".modern-input").is(":focus"))
        {
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
                $(".modern-input").blur();
                hideAll();
            }
        }
    });
});

function hideAll() {
    $(".up").animate({"top": '-95px'});
    $(".right").animate({"right": '-200px'});
    $(".left").animate({"left": '-1000px'});
}

function showAll() {
    $(".up").animate({"top": '0px'});
    $(".right").animate({"right": '0px'});
    $(".left").animate({"left": '0px'});
}

$(".stabilize-graph").click(function() {
    viz.stabilize();
})


$(".modern-input").each(function() {
    this.addEventListener("keyup", function(event) {
        if (event.keyCode === 13) {
            queryValue = document.getElementById("query").value;
            if (queryValue == "") {
                draw()
            } else {
                draw(query = queryValue)
            }
        }
    })
})

$(".table").find("td:nth-child(2)").click(function() {
    queryValue = $(this).text();
    if (queryValue.includes("{}")) {

        value = prompt("Value:");
        queryValue = queryValue.replace("{}", value)
        draw(query = queryValue);

    } else {
        draw(query = queryValue);
    }
});

function draw(query = "MATCH relations=()-->() RETURN relations") {
    var config = {
        container_id: "Graph",
        server_url: "bolt://localhost:7687",
        server_user: "neo4j",
        server_password: "pass",
        labels: {
            "endpoints": {
                caption: "ip",
                "font": {
                    "size": 24,
                    "color": "black"
                }
            }
        },
        relationships: {
            "userTo": {
                caption: false,
                tickness: "weight",
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
        hierarchical_sort_method: "directed"
    };

    viz = new NeoVis.default(config);
    viz.render();
}