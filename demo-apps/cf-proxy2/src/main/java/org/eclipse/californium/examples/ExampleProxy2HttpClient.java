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

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.eclipse.californium.proxy2.ProxyHttpServer;

/**
 * Class ExampleProxyHttpClient.<br/>
 * 
 * Example proxy Http client which sends a request via {@link ProxyHttpServer}
 * to a coap-server.<br/>
 * 
 * Http2Coap Uri:<br/>
 * <a href=
 * "http://localhost:8080/proxy/coap://localhost:5685/coap-target">http://localhost:8080/proxy/coap://localhost:5685/coap-target</a>.
 */
public class ExampleProxy2HttpClient {

	private static void request(HttpClient client, String uri) {
		try {
			HttpGet request = new HttpGet(uri);
			HttpResponse response = client.execute(request);
			System.out.println(EntityUtils.toString(response.getEntity()));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		HttpClient client = HttpClientBuilder.create().build();
		request(client, "http://localhost:8080/proxy/coap://localhost:5685/coap-target");
		// keep the "coap://" after normalize the URI requires to use %2f%2f instead of //
		request(client, "http://localhost:8080/proxy/coap:%2f%2flocalhost:5685/coap-target");
		request(client, "http://localhost:8080/proxy?target_uri=coap://localhost:5685/coap-target");

		// not really intended, http2http
		request(client, "http://localhost:8080/proxy/http:%2f%2flocalhost:8000/http-target");

		// request to local (in same process) coap-server
		request(client, "http://localhost:8080/local/target");

		// http-request via proxy
		HttpHost proxy = new HttpHost("localhost", 8080, "http");
		client = HttpClientBuilder.create().setProxy(proxy).build();
		request(client, "http://localhost:5685/coap-target/coap:");
	}
}
