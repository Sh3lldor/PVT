var viz;
var socket = io('http://localhost:8443/');

var matchQuery = "MATCH p=()-[r:]->() RETURN p"
var initialIndex = 14;


function draw(query = "MATCH relations=()-->() RETURN relations") {
    var config = {
        container_id: "Graph",
        server_url: "bolt://localhost:7687",
        server_user: "neo4j",
        server_password: "test",
        labels: {
            "endpoints": {
                caption: "ip",
                "color": "#ffffff",
                "font": {
                    "size": 10,
                    "color": "black",
                    "face": 'arial'
                },
                "image": "static\\pics\\server.png"
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
            "HTTP_RESPONSE": {
                caption: true,
                tickness: "weight"
            },
            "DNS_QUERY": {
                caption: true,
                tickness: "weight"
            },
            "DNS_ANSWER": {
                caption: true,
                tickness: "weight"
            },
            "DHCP": {
                caption: true,
                tickness: "weight"
            },
            "HSRP": {
                caption: true,
                tickness: "weight"
            },
            "LLMNR_Query": {
                caption: true,
                tickness: "weight"
            },
            "LLMNR_Response": {
                caption: true,
                tickness: "weight"
            },
            "NBNS_Query": {
                caption: true,
                tickness: "weight"
            },
            "NBNS_Response": {
                caption: true,
                tickness: "weight"
            },
            "NTP_Symmetric_Active": {
                caption: true,
                tickness: "weight"
            },
            "NTP_SERVER": {
                caption: true,
                tickness: "weight"
            },
            "RADIUS_Request": {
                caption: true,
                tickness: "weight"
            },
            "RADIUS_Challenge": {
                caption: true,
                tickness: "weight"
            },
            "RIP_Request": {
                caption: true,
                tickness: "weight"
            },
            "RIP_Response": {
                caption: true,
                tickness: "weight"
            },
            "SNMP_v1": {
                caption: true,
                tickness: "weight"
            },
            "SNMP_v2": {
                caption: true,
                tickness: "weight"
            },
            "SNMP": {
                caption: true,
                tickness: "weight"
            },
            "TFTP": {
                caption: true,
                tickness: "weight"
            },

            [NeoVis.NEOVIS_DEFAULT_CONFIG]: {
                "thickness": "defaultThicknessProperty",
                "caption": true
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
    viz.registerOnEvent("completed", (e) => {
        viz["_network"].on("click", (event) => {
            if (event.nodes[0]) {
                console.log(viz["_nodes"][event.nodes[0]])
            } else if (event.edges[0]) {
                console.log(viz["_edges"][event.edges[0]])
            }
        });
    });
}
var timeout;

$(".stabilize-btn").click(function() {
    viz.stabilize();
})