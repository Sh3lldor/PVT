'use strict';

import Neo4j from 'neo4j-driver';
/*import * as vis from 'vis-network/standalone';*/
import * as vis from './neovis-with-dependencies.js';
import { defaults } from './defaults.js';
import { EventController, CompletionEvent, ClickEdgeEvent, ClickNodeEvent, ErrorEvent } from './events.js';

export const NEOVIS_DEFAULT_CONFIG = Symbol();

export default class NeoVis {
	_nodes = {};
	_edges = {};
	_data = {};
	_network = null;
	_events = new EventController();

	/**
	 * Get current vis nodes from the graph
	 */
	get nodes() {
		return this._data.nodes;
	}

	/**
	 * Get current vis edges from the graph
	 */
	get edges() {
		return this._data.edges;
	}

	/**
	 *
	 * @constructor
	 * @param {object} config - configures the visualization and Neo4j server connection
	 *  {
	 *    container:
	 *    server_url:
	 *    server_password?:
	 *    server_username?:
	 *    server_database?:
	 *    labels:
	 *
	 *  }
	 *
	 */
	constructor(config) {
		this._init(config);

		this._consoleLog(config);
		this._consoleLog(defaults);
	}

	_consoleLog(message, level = 'log') {
		if (level !== 'log' || this._config.console_debug) {
			// eslint-disable-next-line no-console
			console[level](message);
		}
	}

	_init(config) {
		if (config.labels && config.labels[NEOVIS_DEFAULT_CONFIG]) {
			for (let key of Object.keys(config.labels)) {
				// getting out of my for not changing the original config object
				config = {
					...config,
					labels: {
						...config.labels,
						[key]: { ...config.labels[NEOVIS_DEFAULT_CONFIG], ...config.labels[key] }
					}
				};
			}
		}
		if (config.relationships && config.relationships[NEOVIS_DEFAULT_CONFIG]) {
			// getting out of my for not changing the original config object
			for (let key of Object.keys(config.relationships)) {
				config = {
					...config,
					relationships: {
						...config.relationships,
						[key]: { ...config.relationships[NEOVIS_DEFAULT_CONFIG], ...config.relationships[key] }
					}
				};
			}
		}
		this._config = config;
		this._encrypted = config.encrypted || defaults.neo4j.encrypted;
		this._trust = config.trust || defaults.neo4j.trust;
		this._driver = Neo4j.driver(
			config.server_url || defaults.neo4j.neo4jUri,
			Neo4j.auth.basic(config.server_user || defaults.neo4j.neo4jUser, config.server_password || defaults.neo4j.neo4jPassword),
			{
				encrypted: this._encrypted,
				trust: this._trust,
				maxConnectionPoolSize: 100,
				connectionAcquisitionTimeout: 10000,
			}
		);
		this._database = config.server_database;
		this._query = config.initial_cypher || defaults.neo4j.initialQuery;
		this._container = document.getElementById(config.container_id);
	}

	_addNode(node) {
		this._nodes[node.id] = node;
	}

	_addEdge(edge) {
		this._edges[edge.id] = edge;
	}

	/**
	 * Build node object for vis from a neo4j Node
	 * FIXME: use config
	 * FIXME: move to private api
	 * @param neo4jNode
	 * @returns {{}}
	 */
	async buildNodeVisObject(neo4jNode) {
		let node = {};
		let label = neo4jNode.labels[0];

		let labelConfig = this._config && this._config.labels && (this._config.labels[label] || this._config.labels[NEOVIS_DEFAULT_CONFIG]);

		const captionKey = labelConfig && labelConfig['caption'];
		const sizeKey = labelConfig && labelConfig['size'];
		const sizeCypher = labelConfig && labelConfig['sizeCypher'];
		const communityKey = labelConfig && labelConfig['community'];
		const imageUrl = labelConfig && labelConfig['image'];
		const font = labelConfig && labelConfig['font'];

		const title_properties = (
			labelConfig && labelConfig.title_properties
		) || Object.keys(neo4jNode.properties);

		node.id = neo4jNode.identity.toInt();
		node.raw = neo4jNode;

		// node size

		if (sizeCypher) {
			// use a cypher statement to determine the size of the node
			// the cypher statement will be passed a parameter {id} with the value
			// of the internal node id
			// TODO: refactor and put all size cypher in one transaction to commit to improve efficiency
			node.value = 1.0;
			const session = this._driver.session(this._database && { database: this._database });
			try {
				const result = await session.readTransaction(tx => tx.run(sizeCypher, { id: Neo4j.int(node.id) }));
				for (let record of result.records) {
					record.forEach((v) => {
						if (typeof v === 'number') {
							node.value = v;
						} else if (Neo4j.isInt(v)) {
							node.value = v.toNumber();
						}
					});
				}
			} finally {
				session.close();
			}
		} else if (typeof sizeKey === 'number') {
			node.value = sizeKey;
		} else {
			let sizeProp = neo4jNode.properties[sizeKey];

			if (sizeProp && typeof sizeProp === 'number') {
				// property value is a number, OK to use
				node.value = sizeProp;
			} else if (sizeProp && typeof sizeProp === 'object' && Neo4j.isInt(sizeProp)) {
				// property value might be a Neo4j Integer, check if we can call toNumber on it:
				if (sizeProp.inSafeRange()) {
					node.value = sizeProp.toNumber();
				} else {
					// couldn't convert to Number, use default
					node.value = 1.0;
				}
			} else {
				node.value = 1.0;
			}
		}

		// node caption
		if (typeof captionKey === 'function') {
			node.label = captionKey(neo4jNode);
		} else if (captionKey && (typeof neo4jNode.properties[captionKey] === 'number' || Neo4j.isInt(neo4jNode.properties[captionKey]))) {
			node.label = neo4jNode.properties[captionKey].toString() || '';
		} else {
			node.label = neo4jNode.properties[captionKey] || label || '';
		}

		// community
		// behavior: color by value of community property (if set in config), then color by label
		if (!communityKey) {
			node.group = label;
		} else {
			try {
				if (neo4jNode.properties[communityKey]) {
					node.group = neo4jNode.properties[communityKey].toNumber() || label || 0;  // FIXME: cast to Integer

				} else {
					node.group = 0;
				}

			} catch (e) {
				node.group = 0;
			}
		}
		// set configured/all properties as tooltip
		node.title = '';
		for (const key of title_properties) {
			if (neo4jNode.properties.hasOwnProperty(key)) {
				node.title += this.propertyToString(key, neo4jNode.properties[key]);
			}
		}

		// set node shape and image url if a image url is provided in config
		if (imageUrl) {
			node.shape = 'image';
			node.image = imageUrl;
		} else {
			node.shape = 'dot';
		}

		// set node caption font if font setting is provided in config
		if (font) {
			node.font = font;
		}

		return node;
	}

	/**
	 * Build edge object for vis from a neo4j Relationship
	 * @param r
	 * @returns {{}}
	 */
	buildEdgeVisObject(r) {
		const nodeTypeConfig = this._config && this._config.relationships &&
			(this._config.relationships[r.type] || this._config.relationships[NEOVIS_DEFAULT_CONFIG]);
		let weightKey = nodeTypeConfig && nodeTypeConfig.thickness,
			captionKey = nodeTypeConfig && nodeTypeConfig.caption;

		let edge = {};
		edge.id = r.identity.toInt();
		edge.from = r.start.toInt();
		edge.to = r.end.toInt();
		edge.raw = r;

		// hover tooltip. show all properties in the format <strong>key:</strong> value
		edge.title = '';
		for (let key in r.properties) {
			if (r.properties.hasOwnProperty(key)) {
				edge['title'] += this.propertyToString(key, r.properties[key]);
			}
		}

		// set relationship thickness
		if (weightKey && typeof weightKey === 'string') {
			edge.value = r.properties[weightKey];
		} else if (weightKey && typeof weightKey === 'number') {
			edge.value = weightKey;
		} else {
			edge.value = 1.0;
		}

		// set caption


		if (typeof captionKey === 'boolean') {
			if (!captionKey) {
				edge.label = '';
			} else {
				edge.label = r.type;
			}
		} else if (captionKey && typeof captionKey === 'string') {
			if (typeof r.properties[captionKey] === 'number' || Neo4j.isInt(r.properties[captionKey])) {
				edge.label = r.properties[captionKey].toString() || '';
			} else {
				edge.label = r.properties[captionKey] || '';
			}
		} else {
			edge.label = r.type;
		}
		return edge;
	}

	propertyToString(key, value) {
		if (Array.isArray(value) && value.length > 1) {
			let out = `<strong>${key}:</strong><br /><ul>`;
			for (let val of value) {
				out += `<li>${val}</li>`;
			}
			return out + '</ul>';
		}
		return `<strong>${key}:</strong> ${value}<br>`;
	}

	// public API

	render(query) {

		// connect to Neo4j instance
		// run query
		let recordCount = 0;
		const _query = query || this._query;
		let session = this._driver.session(this._database && { database: this._database });
		const dataBuildPromises = [];
		session
			.run(_query, { limit: 30 })
			.subscribe({
				onNext: (record) => {
					recordCount++;

					this._consoleLog('CLASS NAME');
					this._consoleLog(record && record.constructor.name);
					this._consoleLog(record);

					const dataPromises = Object.values(record.toObject()).map(async (v) => {
						this._consoleLog('Constructor:');
						this._consoleLog(v && v.constructor.name);
						if (v instanceof Neo4j.types.Node) {
							let node = await this.buildNodeVisObject(v);
							try {
								this._addNode(node);
							} catch (e) {
								this._consoleLog(e, 'error');
							}

						} else if (v instanceof Neo4j.types.Relationship) {
							let edge = this.buildEdgeVisObject(v);
							this._addEdge(edge);

						} else if (v instanceof Neo4j.types.Path) {
							this._consoleLog('PATH');
							this._consoleLog(v);
							let startNode = await this.buildNodeVisObject(v.start);
							let endNode = await this.buildNodeVisObject(v.end);

							this._addNode(startNode);
							this._addNode(endNode);

							for (let obj of v.segments) {
								this._addNode(await this.buildNodeVisObject(obj.start));
								this._addNode(await this.buildNodeVisObject(obj.end));
								this._addEdge(this.buildEdgeVisObject(obj.relationship));
							}

						} else if (v instanceof Array) {
							for (let obj of v) {
								this._consoleLog('Array element constructor:');
								this._consoleLog(obj && obj.constructor.name);
								if (obj instanceof Neo4j.types.Node) {
									let node = await this.buildNodeVisObject(obj);
									this._addNode(node);

								} else if (obj instanceof Neo4j.types.Relationship) {
									let edge = this.buildEdgeVisObject(obj);

									this._addEdge(edge);
								}
							}
						}
					});
					dataBuildPromises.push(Promise.all(dataPromises));
				},
				onCompleted: async () => {
					await Promise.all(dataBuildPromises);
					session.close();

					if (this._network && this._network.body.data.nodes.length > 0) {
						this._data.nodes.update(Object.values(this._nodes));
						this._data.edges.update(Object.values(this._edges));
					} else {
						let options = {
							nodes: {
								//shape: 'dot',
								font: {
									size: 26,
									strokeWidth: 7
								},
								scaling: {
								}
							},
							edges: {
								arrows: {
									to: { enabled: this._config.arrows || false } // FIXME: handle default value
								},
								length: 200
							},
							layout: {
								improvedLayout: false,
								hierarchical: {
									enabled: this._config.hierarchical || false,
									sortMethod: this._config.hierarchical_sort_method || 'hubsize'
								}
							},
							physics: { // TODO: adaptive physics settings based on size of graph rendered
								// enabled: true,
								// timestep: 0.5,
								// stabilization: {
								//     iterations: 10
								// }

								adaptiveTimestep: true,
								// barnesHut: {
								//     gravitationalConstant: -8000,
								//     springConstant: 0.04,
								//     springLength: 95
								// },
								stabilization: {
									iterations: 200,
									fit: true
								}
							}
						};

						const container = this._container;
						this._data = {
							nodes: new vis.DataSet(Object.values(this._nodes)),
							edges: new vis.DataSet(Object.values(this._edges))
						};

						this._consoleLog(this._data.nodes);
						this._consoleLog(this._data.edges);

						// Create duplicate node for any this reference relationships
						// NOTE: Is this only useful for data model type data
						// this._data.edges = this._data.edges.map(
						//     function (item) {
						//          if (item.from == item.to) {
						//             const newNode = this._data.nodes.get(item.from)
						//             delete newNode.id;
						//             const newNodeIds = this._data.nodes.add(newNode);
						//             this._consoleLog("Adding new node and changing this-ref to node: " + item.to);
						//             item.to = newNodeIds[0];
						//          }
						//          return item;
						//     }
						// );
						this._network = new vis.Network(container, this._data, options);
					}
					this._consoleLog('completed');
					setTimeout(
						() => {
							this._network.stopSimulation();
						},
						10000
					);
					this._events.generateEvent(CompletionEvent, { record_count: recordCount });

					let neoVis = this;
					this._network.on('click', function (params) {
						if (params.nodes.length > 0) {
							let nodeId = this.getNodeAt(params.pointer.DOM);
							neoVis._events.generateEvent(ClickNodeEvent, { nodeId: nodeId, node: neoVis._nodes[nodeId] });
						} else if (params.edges.length > 0) {
							let edgeId = this.getEdgeAt(params.pointer.DOM);
							neoVis._events.generateEvent(ClickEdgeEvent, { edgeId: edgeId, edge: neoVis._edges[edgeId] });
						}
					});
				},
				onError: (error) => {
					this._consoleLog(error, 'error');
					this._events.generateEvent(ErrorEvent, { error_msg: error });
				}
			});
	}

	/**
	 * Clear the data for the visualization
	 */
	clearNetwork() {
		this._neo4jNodes = {};
		this._neo4jEdges = {};
		this._nodes = {};
		this._edges = {};
		this._network.setData([]);
	}


	/**
	 *
	 * @param {string} eventType Event type to be handled
	 * @param {callback} handler Handler to manage the event
	 */
	registerOnEvent(eventType, handler) {
		this._events.register(eventType, handler);
	}


	/**
	 * Reset the config object and reload data
	 * @param config
	 */
	reinit(config) {
		this._init(config);
		this.render();
	}

	/**
	 * Fetch live data form the server and reload the visualization
	 */
	reload() {
		this.clearNetwork();
		this.render();
	}

	/**
	 * Stabilize the visuzliation
	 */
	stabilize() {
		this._network.stopSimulation();
		this._consoleLog('Calling stopSimulation');
	}

	/**
	 * Execute an arbitrary Cypher query and re-render the visualization
	 * @param query
	 */
	renderWithCypher(query) {
		// this._config.initial_cypher = query;
		this.clearNetwork();
		this._query = query;
		this.render();
	}

	/**
	 * Execute an arbitrary Cypher query and update the current visualization, retaning current nodes
	 * This function will not change the original query given by renderWithCypher or the inital cypher.
	 * @param query 
	 */
	updateWithCypher(query) {
		this.render(query);
	}

	// configure exports based on environment (ie Node.js or browser)
	//if (typeof exports === 'object') {
	//    module.exports = NeoVis;
	//} else {
	//    define (function () {return NeoVis;})
	//}
}