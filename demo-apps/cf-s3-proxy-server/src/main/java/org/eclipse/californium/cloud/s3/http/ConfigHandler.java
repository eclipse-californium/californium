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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.InvalidKeyException;
import java.util.Set;

import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.Authorization;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.WebAppAuthorization;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.proxy.S3PutRequest;
import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.cloud.s3.proxy.S3Response;
import org.eclipse.californium.cloud.s3.util.DeviceGroupProvider;
import org.eclipse.californium.cloud.s3.util.WebAppConfigProvider;
import org.eclipse.californium.cloud.s3.util.WebAppUser;
import org.eclipse.californium.cloud.util.DeviceIdentifier;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;

/**
 * Login handler using AWS4-HMAC-SHA256 authorization.
 * 
 * @since 3.12
 */
@SuppressWarnings("restriction")
public class ConfigHandler extends S3Login {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ConfigHandler.class);

	private final int maxConfigSize;

	/**
	 * Create http S3 Login.
	 * 
	 * @param maxConfigSize maximum size of device configuration.
	 * @param authorizer AWS4-HMAC-SHA256 authorizer to check for valid
	 *            credentials.
	 * @param clientProvider S3 client provider.
	 * @param webAppConfigs web application configuration provider.
	 * @param groups device groups provider
	 */
	public ConfigHandler(int maxConfigSize, Aws4Authorizer authorizer, S3ProxyClientProvider clientProvider,
			WebAppConfigProvider webAppConfigs, DeviceGroupProvider groups) {
		super(authorizer, clientProvider, webAppConfigs, groups, false);
		this.maxConfigSize = maxConfigSize;
	}

	@Override
	public void handle(final HttpExchange httpExchange) throws IOException {
		final URI uri = httpExchange.getRequestURI();
		final Object logRemote = StringUtil.toLog(httpExchange.getRemoteAddress());
		LOGGER.info("config-request: {} {} from {}", httpExchange.getRequestMethod(), uri, logRemote);
		String contentType = null;
		byte[] payload = null;
		int httpCode = 404;
		String method = httpExchange.getRequestMethod();
		if (method.equals("PUT")) {
			if (!authorizer.precheckBan(httpExchange)) {
				return;
			}
			httpCode = 401;
			Authorization authorization = authorizer.checkSignature(httpExchange, BAN);
			if (authorization instanceof WebAppAuthorization && authorization.isInTime()) {
				try {
					httpCode = checkPermissions((WebAppAuthorization) authorization, httpExchange);
					if (httpCode == 200) {
						writeConfig((WebAppAuthorization) authorization, httpExchange);
						return;
					}
				} catch (Throwable t) {
					LOGGER.info("config from {}:", logRemote, t);
					httpCode = 500;
					HttpService.ban(httpExchange, BAN);
				}
			}
			LOGGER.info("config-response: {} {} from {}", httpCode,
					authorization == null ? "" : authorization.getName(), logRemote);
		} else {
			httpCode = 405;
		}
		if (httpExchange.getResponseCode() == -1) {
			HttpService.respond(httpExchange, httpCode, contentType, payload);
		}
		if (!authorizer.updateBan(httpExchange)) {
			HttpService.ban(httpExchange, BAN);
		}
	}

	private int checkPermissions(WebAppAuthorization authorization, HttpExchange httpExchange)
			throws InvalidKeyException {
		WebAppUser credentials = authorization.getWebAppUser();
		String domain = authorization.getDomain();
		if (!webAppConfigs.isEnabled(domain, credentials.webAppConfig + WebAppConfigProvider.CONFIGURATION_PREFIX,
				WebAppConfigProvider.CONFIGWRITE_NAME)) {
			LOGGER.info("{}@{} has no ConfigWrite permission!", authorization.getName(), domain);
			return 403;
		}
		if (groups != null && credentials.groups != null) {
			String contextPath = httpExchange.getHttpContext().getPath();
			String configDevice = httpExchange.getRequestURI().getPath().substring(contextPath.length());
			for (String group : credentials.groups) {
				Set<DeviceIdentifier> devices = groups.getGroup(domain, group);
				for (DeviceIdentifier device : devices) {
					if (configDevice.equals(device.getName())) {
						return 200;
					}
				}
			}
			LOGGER.info("{}@{} has no permission for device {}!", authorization.getName(), domain, configDevice);
			return 403;
		}
		return 500;
	}

	private void writeConfig(WebAppAuthorization authorization, final HttpExchange httpExchange)
			throws InvalidKeyException {
		String contextPath = httpExchange.getHttpContext().getPath();
		String configDevice = httpExchange.getRequestURI().getPath().substring(contextPath.length());
		String contentType = httpExchange.getRequestHeaders().getFirst("Content-Type");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (InputStream in = httpExchange.getRequestBody()) {
			byte[] buffer = new byte[maxConfigSize];
			int len;
			int all = 0;

			while ((len = in.read(buffer)) >= 0) {
				if (len > 0) {
					all += len;
					if (all > maxConfigSize) {
						HttpService.respond(httpExchange, 413, null, null);
						return;
					}
					out.write(buffer, 0, len);
				}
			}
		} catch (IOException e) {
			LOGGER.info("Config read request", e);
		}
		S3ProxyClient proxyClient = clientProvider.getProxyClient(authorization.getDomain());
		S3PutRequest s3PutRequest = S3PutRequest.builder().key("devices/" + configDevice + "/config")
				.cacheMode(CacheMode.NONE).content(out.toByteArray()).contentType(contentType).build();
		proxyClient.save(s3PutRequest, (res) -> ready(httpExchange, res));
	}

	private void ready(HttpExchange httpExchange, S3Response response) {
		String contentType = response.getContentType();
		int httpCode = response.getHttpStatusCode();
		try {
			HttpService.respond(httpExchange, httpCode, contentType, null);
		} catch (IOException e) {
			LOGGER.info("Config send response", e);
		}
	}
}
