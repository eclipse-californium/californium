/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

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

/**
 * CoAP resource for request statistic.
 * 
 * Intended use:
 * 
 * <pre>
 * POST {@code<host>/requests?dev=<devid>&rid=<requestid>}
 * </pre>
 * 
 * Response: History of request with same devid of at most {@link #MAX_HISTORY}
 * entries:
 * 
 * <pre>
 * TEXT:
 *  systemstart: {@code <system time millis>}
 * {@code <requestid[n-7]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-6]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-5]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-4]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-3]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-2]>}: {@code <system time millis>} of that request
 * {@code <requestid[n-1]>}: {@code <system time millis>} of that request
 * {@code <requestid[n]>}  : {@code <system time millis>} of that request
 * </pre>
 * 
 * e.g.:
 * 
 * <pre>
 * systemstart:1512577466765
 * RID1512577550360:1512577550374
 * RID1512577556514:1512577556528
 * RID1512577558402:1512577558415
 * RID1512577559806:1512577559819
 * RID1512577561137:1512577561149
 * RID1512577562631:1512577562647
 * RID1512577564778:1512577564791
 * RID1512577566713:1512577566727
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
 *     "rid": "RID1512577556514",
 *     "time": 1512577556528
 *   },
 *   {
 *     "rid": "RID1512577558402",
 *     "time": 1512577558415
 *   },
 *   {
 *     "rid": "RID1512577559806",
 *     "time": 1512577559819
 *   },
 *   {
 *     "rid": "RID1512577561137",
 *     "time": 1512577561149
 *   },
 *   {
 *     "rid": "RID1512577562631",
 *     "time": 1512577562647
 *   },
 *   {
 *     "rid": "RID1512577564778",
 *     "time": 1512577564791
 *   },
 *   {
 *     "rid": "RID1512577566713",
 *     "time": 1512577566727
 *   },
 *   {
 *     "rid": "RID1512577680858",
 *     "time": 1512577680872
 *   }
 * ]
 * </pre>
 */
public class RequestStatistic extends CoapResource {

	private static final String RESOURCE_NAME = "requests";
	private static final String TEXT_SEPARATER = ":";
	private static final String URI_QUERY_OPTION_DEV_ID = "dev";
	private static final String URI_QUERY_OPTION_REQUEST_ID = "rid";
	private static final long START_TIME = System.currentTimeMillis();
	private static final int MAX_HISTORY = 8;

	private final LeastRecentlyUsedCache<String, List<RequestInformation>> requests = new LeastRecentlyUsedCache<String, List<RequestInformation>>(
			1024 * 16, 0);

	public RequestStatistic() {
		super(RESOURCE_NAME);
		getAttributes().setTitle("Resource that collects requests for client staistics");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_JSON);
		requests.setEvictingOnReadAccess(false);
	}

	@Override
	public void handlePOST(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		List<String> uriQuery = request.getOptions().getUriQuery();

		String rid = null;
		String dev = null;
		for (String query : uriQuery) {
			if (query.startsWith(URI_QUERY_OPTION_REQUEST_ID + "=")) {
				rid = query.substring(4);
				if (rid.contains(TEXT_SEPARATER)) {
					Response response = Response.createResponse(request, BAD_OPTION);
					response.setPayload(
							"URI-query-option " + URI_QUERY_OPTION_REQUEST_ID + " contains " + TEXT_SEPARATER + "!");
					exchange.respond(response);
					return;
				}
			} else if (query.startsWith(URI_QUERY_OPTION_DEV_ID + "=")) {
				dev = query.substring(4);
			} else {
				Response response = Response.createResponse(request, BAD_OPTION);
				response.setPayload("URI-query-option " + query + " is not supported!");
				exchange.respond(response);
				return;
			}
		}

		if (rid == null && dev == null) {
			Response response = Response.createResponse(request, BAD_OPTION);
			response.setPayload("missing URI-query-options for " + URI_QUERY_OPTION_DEV_ID + " and "
					+ URI_QUERY_OPTION_REQUEST_ID + "!");
			exchange.respond(response);
			return;
		} else if (rid == null) {
			Response response = Response.createResponse(request, BAD_OPTION);
			response.setPayload("missing URI-query-option for " + URI_QUERY_OPTION_REQUEST_ID + "!");
			exchange.respond(response);
			return;
		} else if (dev == null) {
			Response response = Response.createResponse(request, BAD_OPTION);
			response.setPayload("missing URI-query-option for " + URI_QUERY_OPTION_DEV_ID + "!");
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
			RequestInformation information = new RequestInformation(rid, System.currentTimeMillis());
			synchronized (history) {
				history.add(information);
				if (history.size() > MAX_HISTORY) {
					history.remove(0);
				}
				history = new ArrayList<RequestInformation>(history);
			}
		}

		Response response = new Response(CONTENT);

		switch (exchange.getRequestOptions().getAccept()) {
		case UNDEFINED:
		case TEXT_PLAIN:
			response.getOptions().setContentFormat(TEXT_PLAIN);
			StringBuilder builder = new StringBuilder();
			builder.append("systemstart:").append(START_TIME).append(System.lineSeparator());
			for (RequestInformation entry : history) {
				builder.append(entry.requestId).append(":").append(entry.requestTime).append(System.lineSeparator());
			}
			response.setPayload(builder.toString());
			break;

		case APPLICATION_JSON:
			response.getOptions().setContentFormat(APPLICATION_JSON);
			response.setPayload(toJson(history));
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
	public String toJson(List<RequestInformation> history) {
		JsonArray array = new JsonArray();
		JsonObject element = new JsonObject();
		element.addProperty("systemstart", START_TIME);
		array.add(element);
		for (RequestInformation entry : history) {
			element = new JsonObject();
			element.addProperty("rid", entry.requestId);
			element.addProperty("time", entry.requestTime);
			array.add(element);
		}
		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.create();
		return gson.toJson(array);
	}

}
