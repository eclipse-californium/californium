/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/

package org.eclipse.californium.examples;

import java.io.IOException;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.StatusLine;
import org.eclipse.californium.proxy2.http.server.ProxyHttpServer;

/**
 * Class ExampleProxyHttpClient.
 * 
 * Example proxy Http client which sends a request via {@link ProxyHttpServer}
 * to a coap-server.
 * 
 * Http2Coap Uri:
 * <a href="http://localhost:8080/proxy/coap://localhost:5685/coap-target">
 * http://localhost:8080/proxy/coap://localhost:5685/coap-target</a>.
 */
public class ExampleProxy2HttpClient {

	private static int printResponse(HttpResponse response) throws ParseException, IOException {
		System.out.println(new StatusLine(response));
		Header[] headers = response.getHeaders();
		for (Header header : headers) {
			System.out.println(header.getName() + ": " + header.getValue());
		}
		if (response instanceof ClassicHttpResponse) {
			HttpEntity entity = ((ClassicHttpResponse) response).getEntity();
			if (entity != null) {
				System.out.println(EntityUtils.toString(entity));
			} else {
				System.out.println("<empty>");
			}
		}
		return response.getCode();
	}

	private static void requestGet(HttpClient client, String uri) {
		try {
			System.out.println("=== GET " + uri + " ===");
			HttpGet request = new HttpGet(uri);
			client.execute(request, (res) -> {
				return printResponse(res);
			});
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void requestPut(HttpClient client, String uri, String payload) {
		try {
			String p = payload != null ? "'" + payload + "'" : "(no payload)";
			System.out.println("=== PUT " + uri + " === " + p);
			HttpPut request = new HttpPut(uri);
			if (payload != null) {
				HttpEntity entity = new StringEntity(payload);
				request.setEntity(entity);
			}
			client.execute(request, (res) -> {
				return printResponse(res);
			});
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void requestPost(HttpClient client, String uri, String payload) {
		try {
			String p = payload != null ? "'" + payload + "'" : "(no payload)";
			System.out.println("=== POST " + uri + " === " + p);
			HttpPost request = new HttpPost(uri);
			if (payload != null) {
				HttpEntity entity = new StringEntity(payload);
				request.setEntity(entity);
			}
			client.execute(request, (res) -> {
				return printResponse(res);
			});
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static final String EXTERNAL_HOST = "californium.eclipseprojects.io:5683";

	public static void main(String[] args) {
		String externalHost = args.length > 0 ? args[0] : EXTERNAL_HOST;
		HttpClient client = HttpClientBuilder.create().build();

		// simple request to proxy as http-server (no proxy function)
		requestGet(client, "http://localhost:8080");

		requestGet(client, "http://localhost:8080/proxy/coap://localhost:5685/coap-target");
		// keep the "coap://" after normalize the URI requires to use %2f%2f
		// instead of //
		requestGet(client, "http://localhost:8080/proxy/coap:%2f%2flocalhost:5685/coap-target");
		requestGet(client, "http://localhost:8080/proxy?target_uri=coap://localhost:5685/coap-target");

		// not really intended, http2http
		requestGet(client, "http://localhost:8080/proxy/http:%2f%2flocalhost:8000/http-target");

		// request to local (in same process) coap-server
		requestGet(client, "http://localhost:8080/local/target");

		// http-request via proxy
		HttpHost proxy = new HttpHost("http", "localhost", 8080);
		client = HttpClientBuilder.create().setProxy(proxy).build();
		requestGet(client, "http://localhost:5685/coap-target/coap:");
		requestGet(client, "http://localhost:5685/coap-empty/coap:");

		requestGet(client, "http://" + externalHost + "/test/coap:");
		requestPut(client, "http://" + externalHost + "/test/coap:", null);
		requestPut(client, "http://" + externalHost + "/test/coap:", "");
		requestPut(client, "http://" + externalHost + "/test/coap:", "1234");

		requestPost(client, "http://" + externalHost + "/echo/coap:?id=me&keep", "");
		requestGet(client, "http://" + externalHost + "/echo/me/coap:");

		requestPost(client, "http://" + externalHost + "/echo/coap:?id=me&keep", "123");
		requestGet(client, "http://" + externalHost + "/echo/me/coap:");
	}

	public static void main1(String[] args) {
		HttpHost proxy = new HttpHost("http", "localhost", 8080);
		HttpClient client = HttpClientBuilder.create().setProxy(proxy).build();

		requestPost(client, "http://californium.eclipseprojects.io:5683/echo/coap:?id=me&keep", "123");
		requestGet(client, "http://californium.eclipseprojects.io:5683/echo/me/coap:");
	}
}
