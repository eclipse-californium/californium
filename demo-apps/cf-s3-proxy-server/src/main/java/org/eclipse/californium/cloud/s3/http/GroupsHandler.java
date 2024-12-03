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
package org.eclipse.californium.cloud.s3.http;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.cloud.http.EtagGenerator;
import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.Authorization;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.WebAppAuthorization;
import org.eclipse.californium.cloud.s3.util.DeviceGroupProvider;
import org.eclipse.californium.cloud.s3.util.WebAppUser;
import org.eclipse.californium.cloud.util.DeviceIdentifier;
import org.eclipse.californium.cloud.util.Formatter;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * Device groups handler using AWS4-HMAC-SHA256 authorization.
 * <p>
 * Returns a map with device-names and labels of devices in the groups of the
 * associated web-user.
 * 
 * <pre>
 * <code>
 * GET https://${host}/groups
 * 
 * Response 200:
 * {
 *   "groups" :
 *     { "${device-name1}": "${label1}",
 *       "${device-name2}": "${label2}" ...
 *     }
 * }
 * </code>
 * </pre>
 * 
 * @since 3.13
 */
@SuppressWarnings("restriction")
public class GroupsHandler implements HttpHandler {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(GroupsHandler.class);
	/**
	 * Ban topic to report authorization failures.
	 */
	protected static final String BAN = "LOGIN";
	/**
	 * AWS4-HMAC-SHA256 authorizer.
	 */
	protected final Aws4Authorizer authorizer;
	/**
	 * Device groups.
	 */
	protected final DeviceGroupProvider groups;

	/**
	 * Creates http groups handler.
	 * 
	 * @param authorizer AWS4-HMAC-SHA256 authorizer to check for valid
	 *            credentials.
	 * @param groups device groups provider
	 */
	public GroupsHandler(Aws4Authorizer authorizer, DeviceGroupProvider groups) {
		if (authorizer == null) {
			throw new NullPointerException("authorizer must not be null!");
		}
		if (groups == null) {
			throw new NullPointerException("groups must not be null!");
		}
		this.authorizer = authorizer;
		this.groups = groups;
	}

	@Override
	public void handle(final HttpExchange httpExchange) throws IOException {
		final URI uri = httpExchange.getRequestURI();
		final Object logRemote = StringUtil.toLog(httpExchange.getRemoteAddress());
		LOGGER.info("groups-request: {} {} from {}", httpExchange.getRequestMethod(), uri, logRemote);
		String contentType = null;
		byte[] payload = null;
		int httpCode = 404;
		if (HttpService.strictPathCheck(httpExchange)) {
			String method = httpExchange.getRequestMethod();
			if (method.equals("GET")) {
				if (!authorizer.precheckBan(httpExchange)) {
					return;
				}
				httpCode = 401;
				Authorization authorization = authorizer.checkSignature(httpExchange, BAN);
				if (authorization instanceof WebAppAuthorization && authorization.isInTime()) {
					try {
						httpCode = 200;
						payload = getDeviceList((WebAppAuthorization) authorization);
						if (EtagGenerator.setEtag(httpExchange, payload)) {
							httpCode = 304;
							payload = null;
						}
						contentType = "application/json; charset=utf-8";
						httpExchange.getResponseHeaders().add("Cache-Control", "no-cache");
					} catch (Throwable t) {
						LOGGER.info("groups from {}:", logRemote, t);
						httpCode = 500;
						HttpService.ban(httpExchange, BAN);
					}
				}
				LOGGER.info("groups-response: {} {} from {}", httpCode,
						authorization == null ? "" : authorization.getName(), logRemote);
			} else if (method.equals("HEAD")) {
				if (!authorizer.precheckBan(httpExchange)) {
					return;
				}
			} else {
				httpCode = 405;
			}
		}
		if (httpExchange.getResponseCode() == -1) {
			HttpService.respond(httpExchange, httpCode, contentType, payload);
		}
		if (!authorizer.updateBan(httpExchange)) {
			HttpService.ban(httpExchange, BAN);
		}
	}

	/**
	 * Gets list with devices of groups.
	 * <p>
	 * Creates response with:
	 * 
	 * <code>
	 * Response 200:
	 * {
	 *   "groups" :
	 *     { "${device-name1}": "${label1}",
	 *       "${device-name2}": "${label2}" ...
	 *     }
	 * }
	 * </code>
	 * 
	 * @param authorization authorization
	 * @return payload of response.
	 */
	private byte[] getDeviceList(WebAppAuthorization authorization) {
		Formatter formatter = new Formatter.Json();
		getDeviceList(authorization, groups, formatter);
		return formatter.getPayload();
	}

	/**
	 * Writes device list.
	 * 
	 * @param authorization authorization
	 * @param groups device groups provider
	 * @param formatter formatter for resulting list.
	 */
	public static void getDeviceList(WebAppAuthorization authorization, DeviceGroupProvider groups,
			Formatter formatter) {
		if (groups != null) {
			WebAppUser credentials = authorization.getWebAppUser();
			String domain = authorization.getDomain();
			if (credentials.groups != null && domain != null) {
				Map<String, String> allDevices = new HashMap<>();
				for (String group : credentials.groups) {
					Set<DeviceIdentifier> devices = groups.getGroup(domain, group);
					for (DeviceIdentifier device : devices) {
						String label = device.getLabel();
						allDevices.put(device.getName(), label != null ? label : "");
					}
				}
				if (!allDevices.isEmpty()) {
					formatter.addMap("groups", allDevices);
				}
			}
		}
	}

}
