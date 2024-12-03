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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

import org.eclipse.californium.cloud.http.EtagGenerator;
import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.http.HttpService.CoapProxyHandler;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.Authorization;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.WebAppAuthorization;
import org.eclipse.californium.cloud.s3.util.WebAppConfigProvider;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.server.resources.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;

/**
 * HTTP-CoAP proxy handler with AWS4-HMAC-SHA256 authorization.
 * 
 * @since 3.12
 */
@SuppressWarnings("restriction")
public class AuthorizedCoapProxyHandler extends CoapProxyHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizedCoapProxyHandler.class);
	/**
	 * Ban topic to report authorization failures.
	 */
	private static final String BAN = "HTTPS";

	/**
	 * AWS4-HMAC-SHA256 authorizer.
	 */
	private final Aws4Authorizer authorizer;
	/**
	 * Web application configuration provider.
	 */
	private final WebAppConfigProvider webAppConfigs;
	/**
	 * Bucket name for proxy itself.
	 */
	private final String bucket;
	/**
	 * Bucket name as HTTP path.
	 */
	private final String bucketPath;
	/**
	 * Valid CoAP resource for http proxy.
	 */
	private final String[] resources;
	/**
	 * CoAP root resource,
	 */
	private final Resource root;

	/**
	 * Create proxy handler.
	 * <p>
	 * <b>Note:</b> requires web application configuration {@code config.diagnose}!
	 * 
	 * @param bucket bucket name for proxy. Used for list.
	 * @param authorizer AWS4-HMAC-SHA256 authorizer to check for valid
	 *            credentials.
	 * @param webAppConfigs web application configuration provider.
	 * @param server coap-server
	 * @param executor executor
	 * @param resources list of valid coap resources for proxy.
	 */
	public AuthorizedCoapProxyHandler(String bucket, Aws4Authorizer authorizer, WebAppConfigProvider webAppConfigs,
			CoapServer server, Executor executor, String... resources) {
		super(server.getMessageDeliverer(), executor, bucket);
		this.authorizer = authorizer;
		this.webAppConfigs = webAppConfigs;
		this.bucket = bucket;
		this.bucketPath = "/" + bucket + "/";
		this.resources = resources;
		this.root = server.getRoot();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Checks, if path is in {@link #resources}.
	 */
	@Override
	public boolean checkResourcePath(String path) {
		for (String resource : resources) {
			if (path.startsWith(resource)) {
				int resourceLength = resource.length();
				return path.length() > resourceLength ? path.charAt(resourceLength) == '/' : true;
			}
		}
		return false;
	}

	@Override
	public void handle(final HttpExchange httpExchange) throws IOException {
		if (!authorizer.precheckBan(httpExchange)) {
			return;
		}
		boolean permission = false;

		Authorization authorization = authorizer.checkSignature(httpExchange, BAN);
		if (authorization instanceof WebAppAuthorization && authorization.isInTime()) {
			WebAppAuthorization web = (WebAppAuthorization) authorization;
			permission = webAppConfigs.isEnabled(web.getDomain(),
					web.getWebAppUser().webAppConfig + WebAppConfigProvider.CONFIGURATION_PREFIX,
					WebAppConfigProvider.DIAGNOSE_NAME);
		}
		if (permission) {
			final String method = httpExchange.getRequestMethod();
			final URI uri = httpExchange.getRequestURI();
			LOGGER.info("http-proxy-request: {} {}", method, uri);
			httpExchange.setAttribute(HttpService.ATTRIBUTE_PRINCIPAL, authorization);
			if (method.equals("GET") || method.equals("HEAD")) {
				URI requestURI = httpExchange.getRequestURI();
				String path = requestURI.getPath();
				if (path.equals(bucketPath)) {
					String query = requestURI.getRawQuery();
					int httpCode = 200;
					byte[] payload = null;
					if (query.equals("location")) {
						payload = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
								+ "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">null</LocationConstraint>")
										.getBytes(StandardCharsets.UTF_8);
					} else {
						String list = list(query);
						payload = list.getBytes(StandardCharsets.UTF_8);
					}
					HttpService.respond(httpExchange, httpCode, "application/xml", payload);
					if (!authorizer.updateBan(httpExchange)) {
						HttpService.ban(httpExchange, BAN);
					}
					return;
				}
			}
			super.handle(httpExchange);
		} else {
			if (httpExchange.getResponseCode() == -1) {
				HttpService.respond(httpExchange, 401, null, null);
			}
			if (!authorizer.updateBan(httpExchange)) {
				HttpService.ban(httpExchange, BAN);
			}
		}
	}

	@Override
	public void respond(HttpExchange httpExchange, int httpCode, String contentType, byte[] payload)
			throws IOException {
		String dateTime = DateTimeFormatter.RFC_1123_DATE_TIME.format(OffsetDateTime.now(ZoneId.of("GMT")));
		httpExchange.getResponseHeaders().set("last-modified", dateTime);
		if (EtagGenerator.setEtag(httpExchange, payload)) {
			HttpService.respond(httpExchange, 304, contentType, null);
		} else {
			HttpService.respond(httpExchange, httpCode, contentType, payload);
		}
	}

	@Override
	public boolean updateBan(final HttpExchange httpExchange) {
		return authorizer.updateBan(httpExchange);
	}

	/**
	 * List proxy resources.
	 * 
	 * @param childs list to add coap child resources.
	 * @param node coap resource to list
	 * @param prefix prefix to filter added child resources
	 * @param delimiter {@code true}, if delimiter is used. In that case, don't
	 *            include sub-resources of included resources.
	 */
	public void list(List<Resource> childs, Resource node, String prefix, boolean delimiter) {
		for (Resource resource : node.getChildren()) {
			String uri = resource.getURI();
			if (checkResourcePath(uri)) {
				boolean add = uri.startsWith(prefix);
				boolean sub = prefix.startsWith(uri);
				if (add) {
					childs.add(resource);
					LOGGER.info("add {} {}", prefix, uri);
				} else if (!sub) {
					LOGGER.info("not in prefix {} {}", prefix, uri);
				}
				if (sub && (!add || !delimiter)) {
					list(childs, resource, prefix, delimiter);
				}
			} else {
				LOGGER.info("not enabled {}", uri);
			}
		}
	}

	/**
	 * List resources.
	 * 
	 * @param query query part of http request
	 * @return xml list of resources.
	 */
	public String list(String query) {
		Map<String, List<String>> queryMap = parseQuery(query);
		String prefix = getQueryParameter(queryMap, "prefix");
		String delimiter = getQueryParameter(queryMap, "delimiter");
		String startAfter = getQueryParameter(queryMap, "start-after");
		Integer maxKeys = getQueryParameterInteger(queryMap, "max-keys");
		int count = maxKeys == null ? 1000 : maxKeys;
		int index = 0;

		if (prefix == null) {
			prefix = "";
		}

		List<Resource> filteredChilds = new ArrayList<>();
		list(filteredChilds, root, "/" + prefix, delimiter != null);
		filteredChilds = LinkFormat.sort(filteredChilds);
		if (startAfter != null) {
			for (; index < filteredChilds.size(); ++index) {
				if (filteredChilds.get(index).getURI().compareTo(startAfter) > 0) {
					break;
				}
			}
		}

		if (count > filteredChilds.size() - index) {
			count = filteredChilds.size() - index;
		}

		filteredChilds = filteredChilds.subList(index, index + count);

		String dateTime = DateTimeFormatter.RFC_1123_DATE_TIME.format(OffsetDateTime.now(ZoneId.of("GMT")));
		StringBuilder list = new StringBuilder();
		list.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		list.append("<ListBucketResult>\n");
		list.append("<IsTruncated>false</IsTruncated>\n");
		list.append("<Name>" + bucket + "</Name>\n");
		list.append("<Prefix>" + prefix + "</Prefix>\n");
		if (delimiter != null) {
			list.append("<Delimiter>" + delimiter + "</Delimiter>\n");
		}
		if (maxKeys != null) {
			list.append("<MaxKeys>" + maxKeys + "</MaxKeys>\n");
		}
		list.append("<KeyCount>" + filteredChilds.size() + "</KeyCount>\n");
		for (Resource node : filteredChilds) {
			list.append("<Contents>\n");
			list.append("<Key>" + node.getURI().substring(1) + "</Key>\n");
			list.append("<LastModified>" + dateTime + "</LastModified>\n");
			list.append("<Size>" + 1500 + "</Size>\n");
			list.append("<StorageClass>STANDARD</StorageClass>\n");
			list.append("</Contents>\n");
		}
		list.append("</ListBucketResult>\n");
		return list.toString();

	}

	/**
	 * Parse http query.
	 * 
	 * @param query http query
	 * @return map of query parameter with value lists.
	 */
	public static Map<String, List<String>> parseQuery(String query) {
		if (query == null || query.isEmpty()) {
			return Collections.emptyMap();
		}
		Map<String, List<String>> result = new HashMap<>();
		for (String param : query.split("&")) {
			String[] entry = param.split("=");
			String name = entry[0];
			List<String> list = result.get(name);
			if (list == null) {
				list = new ArrayList<>(5);
				result.put(name, list);
			}
			String value = "";
			if (entry.length > 1) {
				value = entry[1];
				try {
					value = URLDecoder.decode(value, StandardCharsets.UTF_8.name());
				} catch (UnsupportedEncodingException ex) {

				}
			}
			list.add(value);
		}
		return result;
	}

	/**
	 * Get query parameter
	 * 
	 * @param map map of query parameter
	 * @param name name of query parameter
	 * @return first none empty parameter value, or {@code ""}, if parameter has
	 *         no value. {@code null}, if parameter is not available.
	 */
	public static String getQueryParameter(Map<String, List<String>> map, String name) {
		List<String> values = map.get(name);
		if (values != null) {
			for (String value : values) {
				if (!value.isEmpty()) {
					return value;
				}
			}
			return "";
		}
		return null;
	}

	/**
	 * Get query parameter as {@link Integer}.
	 * 
	 * @param map map of query parameter
	 * @param name name of query parameter
	 * @return first none empty parameter value as {@link Integer}, or
	 *         {@code 0}, if parameter has no value. {@code null}, if parameter
	 *         is not available.
	 */
	public static Integer getQueryParameterInteger(Map<String, List<String>> map, String name) {
		String value = getQueryParameter(map, name);
		if (value == null) {
			return null;
		}
		if (value.isEmpty()) {
			return 0;
		}
		return Integer.valueOf(value);
	}
}
