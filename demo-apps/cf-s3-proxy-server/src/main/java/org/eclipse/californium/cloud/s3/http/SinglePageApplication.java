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
import java.nio.charset.StandardCharsets;

import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.s3.proxy.S3AsyncProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyRequest;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * Single page application handler.
 * <p>
 * Initial page, which loads the related java-script application.
 * 
 * @since 3.12
 */
@SuppressWarnings("restriction")
public class SinglePageApplication implements HttpHandler {

	/**
	 * Scheme for https.
	 */
	public static final String HTTPS_SCHEME = "https";
	/**
	 * Scheme for s3.
	 */
	public static final String S3_SCHEME = "s3";

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(SinglePageApplication.class);

	/**
	 * Title of single page application.
	 */
	private final String singlePageApplicationTitle;
	/**
	 * CSS for single page application.
	 */
	private final String singlePageApplicationCss;
	/**
	 * Javascripts for single page application.
	 */
	private final String[] singlePageApplicationScripts;
	/**
	 * External https endpoint provider for S3 buckets.
	 */
	private final ExternalEndpointProvider provider;

	/**
	 * Create single page application instance.
	 * 
	 * @param title title of single page application
	 * @param client S3 client
	 * @param css Cascading Style Sheet
	 * @param scripts java-scripts
	 */
	public SinglePageApplication(String title, S3ProxyClient client, String css, String... scripts) {
		if (scripts == null || scripts.length == 0) {
			throw new IllegalArgumentException("At least one javascript is required!");
		}
		this.singlePageApplicationTitle = title;
		this.singlePageApplicationCss = css;
		this.singlePageApplicationScripts = scripts;
		if (client != null) {
			String key = null;
			if (getScheme(css, S3_SCHEME).equals(S3_SCHEME)) {
				key = css;
			} else {
				for (String script : singlePageApplicationScripts) {
					if (getScheme(script, S3_SCHEME).equals(S3_SCHEME)) {
						key = script;
						break;
					}
				}
			}
			if (key != null) {
				Request get = Request.newGet();
				S3ProxyRequest request = S3ProxyRequest.builder(get).key(key).build();
				client.get(request, S3AsyncProxyClient.NOP);
			} else {
				client = null;
			}
		}
		this.provider = client;
	}

	@Override
	public void handle(final HttpExchange httpExchange) throws IOException {
		final URI uri = httpExchange.getRequestURI();
		LOGGER.info("/request: {} {}", httpExchange.getRequestMethod(), uri);
		String contentType = "text/html; charset=utf-8";
		byte[] payload = null;
		int httpCode = 404;
		if (HttpService.strictPathCheck(httpExchange)) {
			String method = httpExchange.getRequestMethod();
			if (method.equals("GET")) {
				String page = createPage();
				httpCode = 200;
				payload = page.toString().getBytes(StandardCharsets.UTF_8);
				httpExchange.getResponseHeaders().add("Cache-Control", "no-cache");
			} else if (method.equals("HEAD")) {
				String page = createPage();
				httpCode = 200;
				payload = page.toString().getBytes(StandardCharsets.UTF_8);
				httpExchange.getResponseHeaders().add("Cache-Control", "no-cache");
			} else {
				httpCode = 405;
			}
		} else {
			HttpService.ban(httpExchange, "HTTPS");
		}
		HttpService.respond(httpExchange, httpCode, contentType, payload);
	}

	/**
	 * Creates initial web page loading the javascript app.
	 * 
	 * @return initial web page
	 */
	private String createPage() {
		String base = getBase();
		StringBuilder page = new StringBuilder();
		page.append("<!DOCTYPE html>\n");
		page.append("<html>\n");
		page.append("<head>\n");
		String css = getUrl(base, singlePageApplicationCss);
		if (css != null) {
			page.append("<link rel=\"stylesheet\" href=\"").append(css).append("\" crossorigin>\n");
		}
		String javascript = getUrl(base, singlePageApplicationScripts[0]);
		page.append("<meta charset=\"utf-8\"/>\n");
		page.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
		page.append("<title>");
		page.append(singlePageApplicationTitle);
		page.append("</title>\n");
		page.append("</head>\n");
		page.append("<body>\n");
		page.append("<h2><div id=\"logo\"></div><div id=\"title\">").append(singlePageApplicationTitle + ":")
				.append("</div></h2>\n");
		page.append("<div id=\"app\"></div>\n");
		page.append("<script>");
		page.append("const app = document.querySelector('#app');");
		page.append("app.innerText = 'Loading \"" + javascript
				+ "\" failed! Maybe caused by the security settings of your browser.';");
		page.append("</script>");
		for (String script : singlePageApplicationScripts) {
			page.append("<script type=\"text/javascript\" src=\"").append(getUrl(base, script))
					.append("\" crossorigin></script>\n");
		}
		page.append("<noscript>JavaScript is required! Please enable it!</noscript>\n");
		page.append("</body>\n");
		page.append("</html>\n");
		return page.toString();
	}

	/**
	 * Adds base to relative URL.
	 * <p>
	 * If provided URL is not relative (contains a scheme), return the URL
	 * unmodified.
	 * 
	 * @param base base URL
	 * @param url URL
	 * @return base URL + relative URL or absolute URL
	 */
	private String getUrl(String base, String url) {
		if (CoAP.getSchemeFromUri(url) == null) {
			return base + url;
		} else {
			return url;
		}
	}

	/**
	 * Gets base URL.
	 * 
	 * @return base URL.
	 */
	private String getBase() {
		String base = "";
		if (provider != null) {
			base = provider.getExternalEndpoint();
			if (base != null && !base.isEmpty() && !base.endsWith("/")) {
				base += "/";
			}
		}
		return base;
	}

	/**
	 * Gets scheme.
	 * 
	 * @param url URL
	 * @param defaultScheme default scheme
	 * @return scheme of URL, or default scheme, if URL doesn't contain the
	 *         scheme.
	 */
	public static String getScheme(String url, String defaultScheme) {
		String scheme = CoAP.getSchemeFromUri(url);
		if (scheme == null) {
			scheme = defaultScheme;
		}
		return scheme;
	}
}
