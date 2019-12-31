/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.eclipse.californium.proxy.ProxyHttpServer;

/**
 * Class ExampleProxyHttpClient.<br/>
 * Example proxy Http client which sends a request via {@link ProxyHttpServer}
 * to a coap-server.<br/>
 * Http2Coap Uri:<br/>
 * <a href=
 * "http://localhost:8080/proxy/coap://localhost:5683/coap-target">http://localhost:8080/proxy/coap://localhost:5683/coap-target</a>.
 */
public class ExampleProxyHttpClient {

	private static void request(HttpClient client, String uri) {
		try {
			HttpResponse response = client.execute(new HttpGet(uri));
			String responseString = new BasicResponseHandler().handleResponse(response);
			System.out.println(responseString);
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		HttpClient client = HttpClientBuilder.create().build();
		request(client, "http://localhost:8080/proxy/coap://localhost:5683/coap-target");
		request(client, "http://localhost:8080/proxy/http://localhost:8000/http-target");
		request(client, "http://localhost:8080/local/coap://localhost/internal");
	}
}
