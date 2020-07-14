/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.upokecenter.cbor.CBORObject;

/**
 * CoAP resource for request statistic.
 * 
 * Intended use:
 * 
 * <pre>
 * POST {@code <host>/requests?dev=<devid>&rid=<requestid>}
 * </pre>
 * 
 * or 
 * 
 * <pre>
 * POST {@code <host>/requests?dev=<devid>&rid=<requestid>&ep}
 * </pre>
 * 
 * if the source endpoint should be included in the statistic.
 * 
 * Response: History of request with same devid of at most {@link #MAX_HISTORY}
 * entries:
 * 
 * <pre>
 * TEXT:
 *  systemstart: {@code <system time millis>}
 * {@code <requestid[n]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-1]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-2]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-3]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-4]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-5]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-6]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-7]>}  : {@code <system time millis>} of that request
 * </pre>
 * 
 * e.g.:
 * 
 * <pre>
 * systemstart:1512577466765
 * RID1512577566713:1512577566727
 * RID1512577564778:1512577564791
 * RID1512577562631:1512577562647
 * RID1512577561137:1512577561149
 * RID1512577559806:1512577559819
 * RID1512577558402:1512577558415
 * RID1512577556514:1512577556528
 * RID1512577550360:1512577550374
 * </pre>
 * 
 * or equivalent in JSON.
 * 
 * <pre>
 * [
 *   {
 *     "systemstart": 1512577466765
 *   },
 *   {
 *     "rid": "RID1512577680858",
 *     "time": 1512577680872
 *   },
 *   {
 *     "rid": "RID1512577566713",
 *     "time": 1512577566727
 *   },
 *   {
 *     "rid": "RID1512577564778",
 *     "time": 1512577564791
 *   },
 *   {
 *     "rid": "RID1512577562631",
 *     "time": 1512577562647
 *   },
 *   {
 *     "rid": "RID1512577561137",
 *     "time": 1512577561149
 *   },
 *   {
 *     "rid": "RID1512577559806",
 *     "time": 1512577559819
 *   },
 *   {
 *     "rid": "RID1512577558402",
 *     "time": 1512577558415
 *   },
 *   {
 *     "rid": "RID1512577556514",
 *     "time": 1512577556528
 *   }
 * ]
 * </pre>
 */
public class RequestStatistic extends CoapResource {

	private static final String RESOURCE_NAME = "requests";
	private static final String TEXT_SEPARATER = ":";
	private static final String URI_QUERY_OPTION_DEV_ID = "dev";
	private static final String URI_QUERY_OPTION_REQUEST_ID = "rid";
	private static final String URI_QUERY_OPTION_ENDPOINT = "ep";
	private static final String URI_QUERY_OPTION_RESPONSE_LENGTH = "rlen";
	private static final long START_TIME = System.currentTimeMillis();
	/**
	 * Maximum entries in the request history.
	 */
	private static final int MAX_HISTORY = 24;
	/**
	 * Maximum payload length.
	 */
	private static final int DEFAULT_MAX_PAYLOAD_LENGTH = 500;

	private final LeastRecentlyUsedCache<String, List<RequestInformation>> requests = new LeastRecentlyUsedCache<String, List<RequestInformation>>(
			1024 * 16, 0);

	public RequestStatistic() {
		super(RESOURCE_NAME);
		getAttributes().setTitle("Resource that collects requests for client statistics");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_JSON);
		requests.setEvictingOnReadAccess(false);
	}

	@Override
	public void handlePOST(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		List<String> uriQuery = request.getOptions().getUriQuery();

		String error = null;
		String rid = null;
		String dev = null;
		Integer rlen = null;
		boolean endpoint = false;
		for (String query : uriQuery) {
			if (query.startsWith(URI_QUERY_OPTION_REQUEST_ID + "=")) {
				rid = query.substring(4);
				if (rid.contains(TEXT_SEPARATER)) {
					error = "URI-query-option " + URI_QUERY_OPTION_REQUEST_ID + " contains " + TEXT_SEPARATER + "!";
					break;
				}
			} else if (query.startsWith(URI_QUERY_OPTION_DEV_ID + "=")) {
				dev = query.substring(4);
			} else if (query.startsWith(URI_QUERY_OPTION_RESPONSE_LENGTH + "=")) {
				try {
					rlen = Integer.valueOf(query.substring(5));
					if (rlen < 1 || rlen > 1023) {
						error = "URI-query-option " + URI_QUERY_OPTION_RESPONSE_LENGTH + " '" + query
								+ "' is not in range [1-1023]!";
						break;
					}
				} catch (NumberFormatException ex) {
					error = "URI-query-option " + URI_QUERY_OPTION_RESPONSE_LENGTH + " in no number!";
					break;
				}
			} else if (query.equals(URI_QUERY_OPTION_ENDPOINT)) {
				endpoint = true;
			} else {
				error = "URI-query-option " + query + " is not supported!";
				break;
			}
		}

		if (error == null) {
			if (rid == null && dev == null) {
				error = "missing URI-query-options for " + URI_QUERY_OPTION_DEV_ID + " and "
						+ URI_QUERY_OPTION_REQUEST_ID + "!";
			} else if (rid == null) {
				error = "missing URI-query-option for " + URI_QUERY_OPTION_REQUEST_ID + "!";
			} else if (dev == null) {
				error = "missing URI-query-option for " + URI_QUERY_OPTION_DEV_ID + "!";
			}
		}
		if (error != null) {
			Response response = Response.createResponse(request, BAD_OPTION);
			response.setPayload(error);
			exchange.respond(response);
			return;
		}
	
		List<RequestInformation> history;
		synchronized (requests) {
			history = requests.get(dev);
			if (history == null) {
				history = new ArrayList<RequestInformation>();
				requests.put(dev, history);
			}
		}

		if (history != null) {
			InetSocketAddress source = endpoint ? request.getSourceContext().getPeerAddress() : null;
			RequestInformation information = new RequestInformation(rid, System.currentTimeMillis(), source);
			synchronized (history) {
				history.add(0, information);
				if (history.size() > MAX_HISTORY) {
					history.remove(MAX_HISTORY);
				}
				history = new ArrayList<RequestInformation>(history);
			}
		}

		Response response = new Response(CHANGED);
		int maxPayloadLength = rlen == null ? DEFAULT_MAX_PAYLOAD_LENGTH : rlen;
		switch (exchange.getRequestOptions().getAccept()) {
		case UNDEFINED:
		case TEXT_PLAIN:
			response.getOptions().setContentFormat(TEXT_PLAIN);
			StringBuilder builder = new StringBuilder();
			builder.append("systemstart:").append(START_TIME).append(System.lineSeparator());
			int last = builder.length();
			for (RequestInformation entry : history) {
				builder.append(entry.requestId).append(":").append(entry.requestTime).append(System.lineSeparator());
				int length = builder.length();
				if (length > maxPayloadLength) {
					break;
				}
				last = length;
			}
			builder.setLength(last);
			response.setPayload(builder.toString());
			break;

		case APPLICATION_JSON:
			response.getOptions().setContentFormat(APPLICATION_JSON);
			response.setPayload(toJson(history, maxPayloadLength));
			break;

		case APPLICATION_CBOR:
			response.getOptions().setContentFormat(APPLICATION_CBOR);
			response.setPayload(toCbor(history, maxPayloadLength));
			break;

		default:
			response = new Response(NOT_ACCEPTABLE);
			break;
		}

		exchange.respond(response);
	}

	/**
	 * Convert history list into JSON format.
	 * 
	 * @param history history list.
	 * @return JSON content
	 */
	public String toJson(List<RequestInformation> history, int maxPayloadLength) {
		JsonArray array = new JsonArray();
		JsonObject element = new JsonObject();
		element.addProperty("systemstart", START_TIME);
		array.add(element);
		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.create();
		String response = gson.toJson(array);
		for (RequestInformation entry : history) {
			element = new JsonObject();
			element.addProperty("rid", entry.requestId);
			element.addProperty("time", entry.requestTime);
			if (entry.sourceAddress != null) {
				try {
					InetAddress address = InetAddress.getByAddress(entry.sourceAddress);
					element.addProperty("ep", address.getHostAddress());
					element.addProperty("port", entry.sourcePort & 0xffff);
				} catch (UnknownHostException e) {
				}
			}
			array.add(element);
			String payload = gson.toJson(array);
			if (payload.length() > maxPayloadLength) {
				break;
			}
			response = payload;
		}
		return response;
	}

	/**
	 * Convert history list into CBOR format.
	 * 
	 * @param history history list.
	 * @return CBOR content
	 */
	public byte[] toCbor(List<RequestInformation> history, int maxPayloadLength) {
		CBORObject list = CBORObject.NewArray();
		CBORObject map = CBORObject.NewMap();
		map.set("systemstart", CBORObject.FromObject(START_TIME));
		list.Add(map);
		byte[] response = list.EncodeToBytes();

		for (RequestInformation entry : history) {
			map = CBORObject.NewMap();
			map.set("rid", CBORObject.FromObject(entry.requestId));
			map.set("time", CBORObject.FromObject(entry.requestTime));
			if (entry.sourceAddress != null) {
				map.set("ep", CBORObject.FromObject(entry.sourceAddress));
				map.set("port", CBORObject.FromObject(entry.sourcePort));
			}
			list.Add(map);
			byte[] payload = list.EncodeToBytes();
			if (payload.length > maxPayloadLength) {
				break;
			}
			response = payload;
		}
		return response;
	}
}
