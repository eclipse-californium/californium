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
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.Authorization;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.WebAppAuthorization;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.util.DeviceGroupProvider;
import org.eclipse.californium.cloud.s3.util.WebAppConfigProvider;
import org.eclipse.californium.cloud.s3.util.WebAppUser;
import org.eclipse.californium.cloud.util.Formatter;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * Login handler using AWS4-HMAC-SHA256 authorization.
 * <p>
 * Returns the S3 credentials, maps with the values of the web-configuration,
 * and a map with device-names and labels of devices in the groups of the
 * associated web-user.
 * 
 * <pre>
 * <code>
 * GET https://${host}/login
 * 
 * Response 200:
 * 
 * {
 *   "id" : "S3 access key ID",
 *   "${date}" : "S3 signing key",
 *   ("${nextDaydate}" : "S3 signing key",)
 *   "base" : "external S3 https endpoint",
 *   "region" : "S3 region",
 *   "config" :
 *     { "${name1}": "${value1}",
 *       "${name2}": "${value2}" ...
 *     },
 *   "groups" :
 *     { "${device-name1}": "${label1}",
 *       "${device-name2}": "${label2}" ...
 *     }
 * }
 * </code>
 * </pre>
 * 
 * The "${nextDaydate}" is only included on day change time (last hour of UTC
 * day).
 * 
 * @since 3.12
 */
@SuppressWarnings("restriction")
public class S3Login implements HttpHandler {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(S3Login.class);
	/**
	 * Ban topic to report authorization failures.
	 */
	protected static final String BAN = "LOGIN";
	/**
	 * AWS4-HMAC-SHA256 authorizer.
	 */
	protected final Aws4Authorizer authorizer;
	/**
	 * Web application configuration provider.
	 */
	protected final WebAppConfigProvider webAppConfigs;
	/**
	 * Device groups.
	 */
	protected final DeviceGroupProvider groups;
	/**
	 * S3 client provider.
	 */
	protected final S3ProxyClientProvider clientProvider;

	/**
	 * Indicates to forward the diagnose configuration.
	 * 
	 * @since 4.0
	 */
	private final boolean withDiagnose;

	/**
	 * Creates http S3 Login.
	 * 
	 * @param authorizer AWS4-HMAC-SHA256 authorizer to check for valid
	 *            credentials.
	 * @param clientProvider S3 client provider.
	 * @param webAppConfigs web application configuration provider.
	 * @param groups device groups provider
	 * @param withDiagnose {@code true} to conditionally include
	 *            "config.diagnose" in the response, {@code false} to not use
	 *            "config.diagnose"
	 */
	public S3Login(Aws4Authorizer authorizer, S3ProxyClientProvider clientProvider, WebAppConfigProvider webAppConfigs,
			DeviceGroupProvider groups, boolean withDiagnose) {
		if (authorizer == null) {
			throw new NullPointerException("authorizer must not be null!");
		}
		if (clientProvider == null) {
			throw new NullPointerException("client provider must not be null!");
		}
		this.authorizer = authorizer;
		this.webAppConfigs = webAppConfigs;
		this.groups = groups;
		this.clientProvider = clientProvider;
		this.withDiagnose = withDiagnose;
	}

	@Override
	public void handle(final HttpExchange httpExchange) throws IOException {
		final URI uri = httpExchange.getRequestURI();
		final Object logRemote = StringUtil.toLog(httpExchange.getRemoteAddress());
		LOGGER.info("login-request: {} {} from {}", httpExchange.getRequestMethod(), uri, logRemote);
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
				if (authorization instanceof WebAppAuthorization) {
					String amzNow = Aws4Authorizer.formatDateTime(System.currentTimeMillis());
					LOGGER.info("Response, x-amz-date: {}", amzNow);
					httpExchange.getResponseHeaders().add("x-amz-date", amzNow);
					if (authorization.isInTime()) {
						try {
							httpCode = 200;
							payload = getLoginResponse((WebAppAuthorization) authorization);
							contentType = "application/json; charset=utf-8";
							httpExchange.getResponseHeaders().add("Cache-Control", "no-cache");
						} catch (Throwable t) {
							LOGGER.info("login from {}:", logRemote, t);
							httpCode = 500;
							HttpService.ban(httpExchange, BAN);
						}
					}
				}
				LOGGER.info("login-response: {} {} from {}", httpCode,
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
	 * Gets login response.
	 * <p>
	 * Includes S3 credentials, generic maps of web application configurations
	 * (subsections) and a map of device names and labels.
	 * 
	 * @param authorization authorization
	 * @return payload of response.
	 * @throws InvalidKeyException if generated signature key is inappropriate.
	 */
	private byte[] getLoginResponse(WebAppAuthorization authorization) throws InvalidKeyException {
		long now = System.currentTimeMillis();
		String date = Aws4Authorizer.formatDate(now);
		String date2 = Aws4Authorizer.formatDate(now + TimeUnit.HOURS.toMillis(1));
		List<String> scope = new ArrayList<>(authorization.getScope());
		WebAppUser credentials = authorization.getWebAppUser();
		String domain = authorization.getDomain();
		String region = S3ProxyClient.DEFAULT_REGION;
		String externalEndpoint = "";
		ExternalEndpointProvider externalEndpointProvider = clientProvider.getProxyClient(domain);
		if (externalEndpointProvider != null) {
			externalEndpoint = externalEndpointProvider.getExternalEndpoint();
			if (!externalEndpoint.isEmpty() && !externalEndpoint.endsWith("/")) {
				externalEndpoint += "/";
			}
			region = externalEndpointProvider.getRegion();
			LOGGER.info("User: {}, Domain: {}, {}, {}", credentials.name, domain, region, externalEndpoint);
		} else {
			LOGGER.info("User: {}, Domain: {} => not found", credentials.name, domain);
		}
		scope.set(0, date);
		scope.set(1, region);
		// create the signing key for access the S3 bucket by this user
		// uses the assigned API key, secret, and region the S3 bucket
		byte[] skey = Aws4Authorizer.getSigningKey(credentials.accessKeySecret, scope);
		Formatter formatter = new Formatter.Json();
		formatter.add("id", credentials.accessKeyId);
		formatter.add(date, StringUtil.byteArray2Hex(skey));
		if (!date.equals(date2)) {
			// day switch, create the signing key for the next day
			scope.set(0, date2);
			byte[] skey2 = Aws4Authorizer.getSigningKey(credentials.accessKeySecret, scope);
			formatter.add(date2, StringUtil.byteArray2Hex(skey2));
		}
		formatter.add("base", externalEndpoint);
		formatter.add("region", region);
		GroupsHandler.getDeviceList(authorization, groups, formatter);
		if (webAppConfigs != null && credentials.webAppConfig != null) {
			if (!withDiagnose) {
				// remove diagnose configuration.
				webAppConfigs.remove(domain, credentials.webAppConfig + WebAppConfigProvider.CONFIGURATION_PREFIX,
						WebAppConfigProvider.DIAGNOSE_NAME);
			}
			Map<String, Map<String, String>> config = webAppConfigs.getSubSections(domain, credentials.webAppConfig);
			for (String section : config.keySet()) {
				Map<String, String> values = config.get(section);
				if (values != null && !values.isEmpty()) {
					formatter.addMap(section, values);
				}
			}
		}
		return formatter.getPayload();
	}
}
