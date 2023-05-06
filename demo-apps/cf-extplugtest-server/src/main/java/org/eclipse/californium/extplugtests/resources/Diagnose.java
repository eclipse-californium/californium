/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
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
import org.eclipse.californium.plugtests.EndpointNetSocketObserver;
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
 * @since 3.1
 */
public class Diagnose extends CoapResource {

	public static final String RESOURCE_NAME = "diagnose";

	private static final Logger LOGGER = LoggerFactory.getLogger(Diagnose.class);

	private static final long START_TIME = System.currentTimeMillis();

	private final List<ServerInterface> serverList = new ArrayList<>();
	private final ConcurrentMap<InetSocketAddress, List<CounterStatisticManager>> endpointsHealth;
	private final List<CounterStatisticManager> endpointHealth;

	public Diagnose(ServerInterface server) {
		this(RESOURCE_NAME, "Resource for diagnose statistics", server);
	}

	public Diagnose(String name, String title, ServerInterface server) {
		super(name);
		init(title);
		if (server != null) {
			this.serverList.add(server);
		}
		this.endpointsHealth = new ConcurrentHashMap<>();
		this.endpointHealth = null;
	}

	public Diagnose(String name, String title, List<CounterStatisticManager> endpointHealth) {
		super(name);
		init(title);
		this.endpointsHealth = null;
		this.endpointHealth = endpointHealth;
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
				addHealth(ep, serverHealth);
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
			health.add((CounterStatisticManager) statistic);
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
			Diagnose child = new Diagnose(key, "Resource for diagnose statistic of " + key, health);
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
		Endpoint endpoint = exchange.advanced().getEndpoint();
		if (endpoint != null) {
			if (CoAP.COAP_SECURE_URI_SCHEME.equalsIgnoreCase(endpoint.getUri().getScheme())) {
				Configuration config = endpoint.getConfig();
				maxConnections = config.get(DtlsConfig.DTLS_MAX_CONNECTIONS);
				nodeId = config.get(DtlsConfig.DTLS_CONNECTION_ID_NODE_ID);
			}
			if (endpointsHealth != null) {
				healths = endpointsHealth.get(endpoint.getAddress());
			}
		}

		switch (exchange.getRequestOptions().getAccept()) {
		case UNDEFINED:
		case TEXT_PLAIN:
			response.getOptions().setContentFormat(TEXT_PLAIN);
			response.setPayload(toText(maxConnections, nodeId, healths));
			break;

		case APPLICATION_JSON:
			response.getOptions().setContentFormat(APPLICATION_JSON);
			response.setPayload(toJson(maxConnections, nodeId, healths));
			break;

		case APPLICATION_CBOR:
			response.getOptions().setContentFormat(APPLICATION_CBOR);
			response.setPayload(toCbor(maxConnections, nodeId, healths));
			break;

		default:
			response = new Response(NOT_ACCEPTABLE);
			break;
		}

		exchange.respond(response);
	}

	public String toText(Integer maxConnections, Integer nodeId, List<CounterStatisticManager> healths) {
		String eol = System.lineSeparator();
		StringBuilder builder = new StringBuilder();
		builder.append("systemstart:").append(START_TIME).append(eol);
		if (nodeId != null) {
			builder.append("node-id:").append(nodeId).append(eol);
		}
		if (maxConnections != null) {
			builder.append("max. connnections:").append(maxConnections).append(eol);
		}
		if (healths != null && !healths.isEmpty()) {
			CounterStatisticManager first = healths.get(0);
			long lastTransfer = ClockUtil.nanoRealtime() - first.getLastTransferTime();
			builder.append("since: ").append(TimeUnit.NANOSECONDS.toSeconds(lastTransfer)).append("s").append(eol);
			int counter = 0;
			for (CounterStatisticManager manager : healths) {
				String tag = manager.getTag();
				if (tag != null && !tag.isEmpty()) {
					builder.append(tag).append(eol);
				} else {
					builder.append(++counter).append(eol);
				}
				String head = "   ";
				for (String key : manager.getKeys()) {
					SimpleCounterStatistic statistic = manager.getByKey(key);
					if (statistic != null) {
						long[] pair = statistic.getCountersPair();
						builder.append(head).append(key).append(",").append(pair[0]).append(",").append(pair[1])
								.append(eol);
					}
				}
			}
		}
		return builder.toString();
	}

	public String toJson(Integer maxConnections, Integer nodeId, List<CounterStatisticManager> healths) {
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
				JsonObject group = new JsonObject();
				for (String key : manager.getKeys()) {
					SimpleCounterStatistic statistic = manager.getByKey(key);
					if (statistic != null) {
						long[] pair = statistic.getCountersPair();
						JsonObject info = new JsonObject();
						info.addProperty("cur", pair[0]);
						info.addProperty("all", pair[1]);
						group.add(key, info);
					}
				}
				String tag = manager.getTag();
				if (tag != null && !tag.isEmpty()) {
					element.add(tag, group);
				} else {
					element.add(Integer.toString(++counter), group);
				}
			}
		}
		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.create();
		return gson.toJson(element);
	}

	public byte[] toCbor(Integer maxConnections, Integer nodeId, List<CounterStatisticManager> healths) {
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
				CBORObject group = CBORObject.NewOrderedMap();
				for (String key : manager.getKeys()) {
					SimpleCounterStatistic statistic = manager.getByKey(key);
					if (statistic != null) {
						long[] pair = statistic.getCountersPair();
						CBORObject info = CBORObject.NewOrderedMap();
						info.set("cur", CBORObject.FromObject(pair[0]));
						info.set("all", CBORObject.FromObject(pair[1]));
						group.set(key, info);
					}
				}
				String tag = manager.getTag();
				if (tag != null && !tag.isEmpty()) {
					map.set(tag, group);
				} else {
					map.set(Integer.toString(++counter), group);
				}
			}
		}
		return map.EncodeToBytes();
	}
}
