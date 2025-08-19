/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_LINK_FORMAT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cloud.EndpointNetSocketObserver;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.server.ServerInterface;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.DtlsHealthLogger;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.upokecenter.cbor.CBORObject;

/**
 * CoAP resource for diagnose and request statistic.
 * <p>
 * Builds a diagnose root node with a list of endpoints as child nodes. Each
 * child nodes contains a list of endpoint specific statistics and the common
 * server statistics.
 * 
 * @since 3.12
 */
public class Diagnose extends ProtectedCoapResource {

	/**
	 * Resource name.
	 */
	public static final String RESOURCE_NAME = "diagnose";

	/**
	 * the logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Diagnose.class);
	/**
	 * Date format.
	 */
	private static final SimpleDateFormat ISO = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
	/**
	 * Start date.
	 */
	private static final String START_TIME = ISO.format(new Date());
	/**
	 * Filter empty statistics.
	 */
	private static final boolean FILTER_EMPTY_STATISTICS = true;
	/**
	 * List of servers.
	 */
	private final List<ServerInterface> serverList;
	/**
	 * Lists of overall statistics.
	 */
	private final List<CounterStatisticManager> serverHealth;

	/**
	 * Child node with list of endpoint specific statistics and the common
	 * server statistics.
	 * 
	 * @since 4.0
	 */
	private static class EndpointDiagnose extends ProtectedCoapResource {

		/**
		 * Lists of statistics of endpoint.
		 */
		private final List<CounterStatisticManager> endpointHealth;
		/**
		 * Endpoint.
		 */
		private final Endpoint endpoint;

		/**
		 * Creates diagnose child node for endpoint.
		 * 
		 * @param name name of child node
		 * @param title title of child node
		 * @param endpoint related endpoint of child node
		 * @param endpointHealth list of statistics of child node.
		 */
		public EndpointDiagnose(String name, String title, Endpoint endpoint,
				List<CounterStatisticManager> endpointHealth) {
			super(name, Type.DEVICE, Type.WEB);
			if (endpoint == null) {
				throw new NullPointerException("Endpoint must not be null!");
			}
			if (endpointHealth == null) {
				throw new NullPointerException("Endpoint health must not be null!");
			}
			getAttributes().setTitle(title);
			addSupportedContentFormats(TEXT_PLAIN, APPLICATION_JSON, APPLICATION_JSON);
			this.endpointHealth = endpointHealth;
			this.endpoint = endpoint;
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(CONTENT);
			Integer maxConnections = null;
			Integer nodeId = null;
			String scheme = endpoint.getUri().getScheme();
			if (CoAP.COAP_SECURE_URI_SCHEME.equalsIgnoreCase(scheme)) {
				Configuration config = endpoint.getConfig();
				maxConnections = config.get(DtlsConfig.DTLS_MAX_CONNECTIONS);
				nodeId = config.get(DtlsConfig.DTLS_CONNECTION_ID_NODE_ID);
				if (nodeId != null) {
					LOGGER.info("coaps: max {}, node-id {}", maxConnections, nodeId);
				} else {
					LOGGER.info("coaps: max {}", maxConnections);
				}
			} else {
				LOGGER.info("{}", scheme);
			}

			Principal principal = getPrincipal(exchange);
			switch (exchange.getRequestOptions().getAccept()) {
			case UNDEFINED:
			case TEXT_PLAIN:
				response.getOptions().setContentFormat(TEXT_PLAIN);
				response.setPayload(toText(maxConnections, nodeId, endpointHealth, principal));
				break;

			case APPLICATION_JSON:
				response.getOptions().setContentFormat(APPLICATION_JSON);
				response.setPayload(toJson(maxConnections, nodeId, endpointHealth, principal));
				break;

			case APPLICATION_CBOR:
				response.getOptions().setContentFormat(APPLICATION_CBOR);
				response.setPayload(toCbor(maxConnections, nodeId, endpointHealth, principal));
				break;

			default:
				response = new Response(NOT_ACCEPTABLE);
				break;
			}

			exchange.respond(response);
		}

		/**
		 * Generate statistics as text.
		 * 
		 * @param maxConnections maximum connections, or {@code null}
		 * @param nodeId (DTLS CID cluster) node ID, or {@code null}
		 * @param healths list of endpoints statistics
		 * @param principal principal
		 * @return statistics as text
		 */
		public String toText(Integer maxConnections, Integer nodeId, List<CounterStatisticManager> healths,
				Principal principal) {
			String eol = System.lineSeparator();
			StringBuilder builder = new StringBuilder();
			builder.append("systemstart: ").append(START_TIME).append(eol);
			if (nodeId != null) {
				builder.append("node-id: ").append(nodeId).append(eol);
			}
			if (maxConnections != null) {
				builder.append("max. connnections: ").append(maxConnections).append(eol);
			}
			if (healths != null && !healths.isEmpty()) {
				CounterStatisticManager first = healths.get(0);
				long lastTransfer = ClockUtil.nanoRealtime() - first.getLastTransferTime();
				builder.append("since: ").append(TimeUnit.NANOSECONDS.toSeconds(lastTransfer)).append("s").append(eol);
				int counter = 0;
				for (CounterStatisticManager manager : healths) {
					boolean counts = !FILTER_EMPTY_STATISTICS;
					int mark = builder.length();
					String tag = manager.getTag();
					if (tag != null && !tag.isEmpty()) {
						builder.append(tag).append(eol);
					} else {
						builder.append(++counter).append(eol);
					}
					String head = "   ";
					String head2 = head;
					String section = "";
					for (String key : manager.getKeys(principal)) {
						SimpleCounterStatistic statistic = manager.getByKey(key);
						if (statistic != null) {
							long[] pair = statistic.getCountersPair();
							String name = key;
							if (manager.useSections()) {
								String header = statistic.getHead(key);
								if (!header.equals(section)) {
									section = header;
									head2 = "      ";
									builder.append(head).append(section).append(':').append(eol);
								}
								name = statistic.getName();
							}
							builder.append(head2).append(name).append(",").append(pair[0]).append(",").append(pair[1])
									.append(eol);
							if (pair[1] > 0 || pair[0] > 0) {
								counts = true;
							}
						}
					}
					if (!counts) {
						// no counts => reset to mark
						builder.setLength(mark);
					}
				}
			}
			return builder.toString();
		}

		/**
		 * Generate statistics as Json.
		 * 
		 * @param maxConnections maximum connections, or {@code null}
		 * @param nodeId (DTLS CID cluster) node ID, or {@code null}
		 * @param healths list of endpoints statistics
		 * @param principal principal
		 * @return statistics as Json
		 */
		public String toJson(Integer maxConnections, Integer nodeId, List<CounterStatisticManager> healths,
				Principal principal) {
			JsonObject element = new JsonObject();
			element.addProperty("systemstart", START_TIME);
			if (nodeId != null) {
				element.addProperty("node-id", nodeId);
			}
			if (maxConnections != null) {
				element.addProperty("max-connections", maxConnections);
			}
			if (healths != null && !healths.isEmpty()) {
				CounterStatisticManager first = healths.get(0);
				long lastTransfer = ClockUtil.nanoRealtime() - first.getLastTransferTime();
				element.addProperty("since", TimeUnit.NANOSECONDS.toSeconds(lastTransfer) + "s");
				int counter = 0;
				for (CounterStatisticManager manager : healths) {
					boolean counts = !FILTER_EMPTY_STATISTICS;
					JsonObject group = new JsonObject();
					for (String key : manager.getKeys(principal)) {
						SimpleCounterStatistic statistic = manager.getByKey(key);
						if (statistic != null) {
							long[] pair = statistic.getCountersPair();
							JsonObject info = new JsonObject();
							info.addProperty("cur", pair[0]);
							info.addProperty("all", pair[1]);
							group.add(key, info);
							if (pair[1] > 0) {
								counts = true;
							}
						}
					}
					if (counts) {
						String tag = manager.getTag();
						if (tag != null && !tag.isEmpty()) {
							element.add(tag, group);
						} else {
							element.add(Integer.toString(++counter), group);
						}
					}
				}
			}
			GsonBuilder builder = new GsonBuilder();
			Gson gson = builder.create();
			return gson.toJson(element);
		}

		/**
		 * Generate statistics as cbor.
		 * 
		 * @param maxConnections maximum connections, or {@code null}
		 * @param nodeId (DTLS CID cluster) node ID, or {@code null}
		 * @param healths list of endpoints statistics
		 * @param principal principal
		 * @return statistics as cbor
		 */
		public byte[] toCbor(Integer maxConnections, Integer nodeId, List<CounterStatisticManager> healths,
				Principal principal) {
			CBORObject map = CBORObject.NewOrderedMap();
			map.set("systemstart", CBORObject.FromObject(START_TIME));
			if (nodeId != null) {
				map.set("node-id", CBORObject.FromObject(nodeId));
			}
			if (maxConnections != null) {
				map.set("max-connections", CBORObject.FromObject(maxConnections));
			}
			if (healths != null && !healths.isEmpty()) {
				CounterStatisticManager first = healths.get(0);
				long lastTransfer = ClockUtil.nanoRealtime() - first.getLastTransferTime();
				map.set("since", CBORObject.FromObject(TimeUnit.NANOSECONDS.toSeconds(lastTransfer) + "s"));
				int counter = 0;
				for (CounterStatisticManager manager : healths) {
					boolean counts = !FILTER_EMPTY_STATISTICS;
					CBORObject group = CBORObject.NewOrderedMap();
					for (String key : manager.getKeys(principal)) {
						SimpleCounterStatistic statistic = manager.getByKey(key);
						if (statistic != null) {
							long[] pair = statistic.getCountersPair();
							CBORObject info = CBORObject.NewOrderedMap();
							info.set("cur", CBORObject.FromObject(pair[0]));
							info.set("all", CBORObject.FromObject(pair[1]));
							group.set(key, info);
							if (pair[1] > 0) {
								counts = true;
							}
						}
					}
					if (counts) {
						String tag = manager.getTag();
						if (tag != null && !tag.isEmpty()) {
							map.set(tag, group);
						} else {
							map.set(Integer.toString(++counter), group);
						}
					}
				}
			}
			return map.EncodeToBytes();
		}
	}

	/**
	 * Creates diagnose root node.
	 * 
	 * @param server server
	 */
	public Diagnose(ServerInterface server) {
		this(RESOURCE_NAME, "Resource for diagnose statistics", server);
	}

	/**
	 * Creates diagnose root node.
	 * 
	 * @param name name of root node
	 * @param title title of root node
	 * @param server server
	 */
	public Diagnose(String name, String title, ServerInterface server) {
		super(name, Type.DEVICE, Type.WEB);
		getAttributes().setTitle(title);
		addSupportedContentFormats(TEXT_PLAIN, APPLICATION_JSON, APPLICATION_JSON, APPLICATION_LINK_FORMAT);
		this.serverList = new ArrayList<>();
		if (server != null) {
			this.serverList.add(server);
		}
		this.serverHealth = new CopyOnWriteArrayList<>();
	}

	/**
	 * Adds additional server.
	 * 
	 * @param server server to add.
	 */
	public void add(ServerInterface server) {
		if (server != null) {
			serverList.add(server);
		}
	}

	/**
	 * Updates list of general statistics.
	 * <p>
	 * Refresh child nodes.
	 * 
	 * @param serverHealth list of general statistics.
	 */
	public void update(List<CounterStatisticManager> serverHealth) {
		for (Resource child : getChildren()) {
			delete(child);
		}
		this.serverHealth.clear();
		serverHealth.forEach((health) -> {
			// remove endpoint related statistics
			if (health instanceof DtlsHealthLogger) {
				return;
			}
			if (health instanceof HealthStatisticLogger) {
				return;
			}
			this.serverHealth.add(health);
		});
		for (ServerInterface server : serverList) {
			for (Endpoint ep : server.getEndpoints()) {
				String scheme = ep.getUri().getScheme();
				if (CoAP.isUdpScheme(scheme)) {
					addChildDiagnose(ep, this.serverHealth);
				}
			}
		}
	}

	/**
	 * Adds diagnose child node.
	 * 
	 * @param endpoint endpoint of sub node
	 * @param serverHealth list of general statistics
	 * @since 4.0 (was)
	 */
	public void addChildDiagnose(Endpoint endpoint, List<CounterStatisticManager> serverHealth) {
		List<CounterStatisticManager> endpointHealth = new ArrayList<>(serverHealth);
		String key = getKeyFromEndpoint(endpoint);
		CounterStatisticManager statistic = EndpointNetSocketObserver.getDtlsStatisticManager(endpoint);
		if (statistic != null) {
			endpointHealth.add(statistic);
		}
		for (MessageInterceptor interceptor : endpoint.getInterceptors()) {
			if (interceptor instanceof CounterStatisticManager) {
				endpointHealth.add((CounterStatisticManager) interceptor);
			}
		}
		for (MessageInterceptor interceptor : endpoint.getPostProcessInterceptors()) {
			if (interceptor instanceof CounterStatisticManager) {
				endpointHealth.add((CounterStatisticManager) interceptor);
			}
		}
		if (!endpointHealth.isEmpty()) {
			EndpointDiagnose child = new EndpointDiagnose(key, "Resource for diagnose statistic of " + key, endpoint,
					endpointHealth);
			add(child);
			LOGGER.info("added {}/{} diagnose for {}", endpointHealth.size(), serverHealth.size(), key);
		}
	}

	/**
	 * Gets key from endpoint
	 * 
	 * @param endpoint endpoint
	 * @return key from endpoint
	 * @since 4.0
	 */
	private static String getKeyFromEndpoint(Endpoint endpoint) {
		String protocol = CoAP.getProtocolForScheme(endpoint.getUri().getScheme());
		InetSocketAddress local = endpoint.getAddress();
		return protocol + ":" + StringUtil.toString(local);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		int accept = exchange.getRequestOptions().getAccept();
		if (accept != APPLICATION_LINK_FORMAT) {
			Endpoint endpoint = exchange.advanced().getEndpoint();
			if (endpoint != null) {
				String key = getKeyFromEndpoint(endpoint);
				Resource child = getChild(key);
				if (child instanceof EndpointDiagnose) {
					((EndpointDiagnose) child).handleGET(exchange);
					return;
				}
			}
		}
		if (accept == APPLICATION_LINK_FORMAT || accept == UNDEFINED) {
			List<String> query = exchange.getRequestOptions().getUriQueryStrings();
			if (query.size() > 1) {
				exchange.respond(ResponseCode.BAD_OPTION, "only one search query is supported!",
						MediaTypeRegistry.TEXT_PLAIN);
				return;
			}
			Set<WebLink> subTree = LinkFormat.getSubTree(this, query);
			Response response = new Response(CONTENT);
			response.setPayload(LinkFormat.serialize(subTree));
			response.getOptions().setContentFormat(APPLICATION_LINK_FORMAT);
			exchange.respond(response);
			return;
		}
		exchange.respond(new Response(ResponseCode.NOT_ACCEPTABLE, true));
	}

}
