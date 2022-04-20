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
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
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

	private static void request(HttpClient client, String uri) {
		try {
			System.out.println("=== " + uri + " ===");
			HttpGet request = new HttpGet(uri);
			HttpResponse response = client.execute(request);
			System.out.println(new StatusLine(response));
			Header[] headers = response.getHeaders();
			for (Header header : headers) {
				System.out.println(header.getName() + ": " + header.getValue());
			}
			if (response instanceof ClassicHttpResponse) {
				HttpEntity entity = ((ClassicHttpResponse) response).getEntity();
				System.out.println(EntityUtils.toString(entity));
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		HttpClient client = HttpClientBuilder.create().build();

		// simple request to proxy as httpp-server (no proxy function)
		request(client, "http://localhost:8080");

		request(client, "http://localhost:8080/proxy/coap://localhost:5685/coap-target");
		// keep the "coap://" after normalize the URI requires to use %2f%2f
		// instead of //
		request(client, "http://localhost:8080/proxy/coap:%2f%2flocalhost:5685/coap-target");
		request(client, "http://localhost:8080/proxy?target_uri=coap://localhost:5685/coap-target");

		// not really intended, http2http
		request(client, "http://localhost:8080/proxy/http:%2f%2flocalhost:8000/http-target");

		// request to local (in same process) coap-server
		request(client, "http://localhost:8080/local/target");

		// http-request via proxy
		HttpHost proxy = new HttpHost("http", "localhost", 8080);
		client = HttpClientBuilder.create().setProxy(proxy).build();
		request(client, "http://localhost:5685/coap-target/coap:");

		request(client, "http://californium.eclipseprojects.io:5683/test/coap:");
	}
}
