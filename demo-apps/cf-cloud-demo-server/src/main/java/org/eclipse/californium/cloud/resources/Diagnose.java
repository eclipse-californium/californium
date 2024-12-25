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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cloud.EndpointNetSocketObserver;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.server.ServerInterface;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.upokecenter.cbor.CBORObject;

/**
 * CoAP resource for request statistic.
 * 
 * @since 3.12
 */
public class Diagnose extends ProtectedCoapResource {

	public static final String RESOURCE_NAME = "diagnose";

	private static final Logger LOGGER = LoggerFactory.getLogger(Diagnose.class);
	private static final SimpleDateFormat ISO = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

	private static final String START_TIME = ISO.format(new Date());
	private static final boolean FILTER_EMPTY_STATISTICS = true;

	private final List<ServerInterface> serverList = new ArrayList<>();
	private final ConcurrentMap<InetSocketAddress, List<CounterStatisticManager>> endpointsHealth;
	private final List<CounterStatisticManager> endpointHealth;
	private final Endpoint endpoint;

	public Diagnose(ServerInterface server) {
		this(RESOURCE_NAME, "Resource for diagnose statistics", server);
	}

	public Diagnose(String name, String title, ServerInterface server) {
		super(name, Type.WEB);
		init(title);
		if (server != null) {
			this.serverList.add(server);
		}
		this.endpointsHealth = new ConcurrentHashMap<>();
		this.endpointHealth = null;
		this.endpoint = null;
	}

	public Diagnose(String name, String title, Endpoint endpoint, List<CounterStatisticManager> endpointHealth) {
		super(name, Type.DEVICE, Type.WEB);
		init(title);
		this.endpointsHealth = null;
		this.endpointHealth = endpointHealth;
		this.endpoint = endpoint;
	}

	private void init(String title) {
		getAttributes().setTitle(title);
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_JSON);
		getAttributes().addContentType(APPLICATION_CBOR);
	}

	public void add(ServerInterface server) {
		if (server != null) {
			serverList.add(server);
		}
	}

	public void update(List<CounterStatisticManager> serverHealth) {
		endpointsHealth.clear();
		for (Resource child : getChildren()) {
			delete(child);
		}
		for (ServerInterface server : serverList) {
			for (Endpoint ep : server.getEndpoints()) {
				String scheme = ep.getUri().getScheme();
				if (CoAP.isUdpScheme(scheme)) {
					addHealth(ep, serverHealth);
				}
			}
		}
	}

	public void addHealth(Endpoint endpoint, List<CounterStatisticManager> serverHealth) {
		List<CounterStatisticManager> health = new ArrayList<>(serverHealth);
		String protocol = CoAP.getProtocolForScheme(endpoint.getUri().getScheme());
		InetSocketAddress local = endpoint.getAddress();
		String key = protocol + ":" + StringUtil.toString(local);
		CounterStatisticManager statistic = EndpointNetSocketObserver.getDtlsStatisticManager(endpoint);
		if (statistic != null) {
			health.add(statistic);
		}
		for (MessageInterceptor interceptor : endpoint.getInterceptors()) {
			if (interceptor instanceof CounterStatisticManager) {
				health.add((CounterStatisticManager) interceptor);
			}
		}
		for (MessageInterceptor interceptor : endpoint.getPostProcessInterceptors()) {
			if (interceptor instanceof CounterStatisticManager) {
				health.add((CounterStatisticManager) interceptor);
			}
		}
		if (!health.isEmpty()) {
			this.endpointsHealth.put(local, health);
			Diagnose child = new Diagnose(key, "Resource for diagnose statistic of " + key, endpoint, health);
			add(child);
			LOGGER.debug("added {} diagnose for {}", health.size(), key);
		}
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		Response response = new Response(CONTENT);
		Integer maxConnections = null;
		Integer nodeId = null;
		List<CounterStatisticManager> healths = endpointHealth;
		Endpoint endpoint = this.endpoint;
		if (endpoint == null) {
			endpoint = exchange.advanced().getEndpoint();
		}
		if (endpoint != null) {
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
			if (endpointsHealth != null) {
				healths = endpointsHealth.get(endpoint.getAddress());
			}
		} else if (healths == null) {
			List<String> query = exchange.getRequestOptions().getUriQueryStrings();
			if (query.size() > 1) {
				exchange.respond(ResponseCode.BAD_OPTION, "only one search query is supported!",
						MediaTypeRegistry.TEXT_PLAIN);
				return;
			}
			Set<WebLink> subTree = LinkFormat.getSubTree(this, query);
			response.setPayload(LinkFormat.serialize(subTree));
			response.getOptions().setContentFormat(APPLICATION_LINK_FORMAT);
			exchange.respond(response);
			return;
		}

		Principal principal = getPrincipal(exchange);
		switch (exchange.getRequestOptions().getAccept()) {
		case UNDEFINED:
		case TEXT_PLAIN:
			response.getOptions().setContentFormat(TEXT_PLAIN);
			response.setPayload(toText(maxConnections, nodeId, healths, principal));
			break;

		case APPLICATION_JSON:
			response.getOptions().setContentFormat(APPLICATION_JSON);
			response.setPayload(toJson(maxConnections, nodeId, healths, principal));
			break;

		case APPLICATION_CBOR:
			response.getOptions().setContentFormat(APPLICATION_CBOR);
			response.setPayload(toCbor(maxConnections, nodeId, healths, principal));
			break;

		default:
			response = new Response(NOT_ACCEPTABLE);
			break;
		}

		exchange.respond(response);
	}

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
				for (String key : manager.getKeys(principal)) {
					SimpleCounterStatistic statistic = manager.getByKey(key);
					if (statistic != null) {
						long[] pair = statistic.getCountersPair();
						builder.append(head).append(key).append(",").append(pair[0]).append(",").append(pair[1])
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
