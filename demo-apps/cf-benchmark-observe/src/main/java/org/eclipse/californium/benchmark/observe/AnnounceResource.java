/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and initial implementation
 *    Martin Dzieżyc - implementation of observable resources
 ******************************************************************************/

package org.eclipse.californium.benchmark.observe;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class AnnounceResource extends CoapResource {

	private HashMap<InetSocketAddress, CoapObserveRelation> relationStorage;
	private CoapHandler handler;
	private ExecutorService executor;
	private ScheduledThreadPoolExecutor secondaryExecutor;

	public AnnounceResource(String name, ExecutorService executor, ScheduledThreadPoolExecutor secondaryExecutor) {
		super(name);
		this.executor = executor;
		this.secondaryExecutor = secondaryExecutor;
		relationStorage = new HashMap<InetSocketAddress, CoapObserveRelation>();
		handler = new CoapHandler() {
			private AtomicBoolean testdump = new AtomicBoolean(false);

			@Override
			public void onLoad(CoapResponse response) {
				if (response.getCode() == ResponseCode.NOT_FOUND) {
					synchronized (relationStorage) {
						if (!testdump.get()) {
							testdump.set(true);
							System.out.println("Used Memory: "
									+ (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024
									+ "kb (" + relationStorage.size() + " clients).");
						}
						InetSocketAddress peerAddress = response.advanced().getSourceContext().getPeerAddress();
						CoapObserveRelation cor = relationStorage.remove(peerAddress);
						if (cor != null) {
							cor.reactiveCancel();
							cor = null;
						}
						if (relationStorage.isEmpty())
							testdump.set(false);
					}
					return;
				}
			}

			@Override
			public void onError() {
			}
		};
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		Response response = new Response(ResponseCode.CONTENT);
		response.setPayload(new Integer(0).toString());
		exchange.respond(response);
	}

	@Override
	public void handlePOST(CoapExchange exchange) {
		CoapClient client = this.createClient(exchange);
		client.setURI(exchange.getRequestText());
		CoapObserveRelation relation = client.observe(handler);
		synchronized (relationStorage) {
			relationStorage.put(exchange.getSourceSocketAddress(), relation);
		}

		Response response = new Response(ResponseCode.VALID);
		exchange.respond(response);
	}

	/**
	 * Creates a {@link CoapClient} that uses the same executor as this resource and
	 * the endpoint of the incoming exchange. The {@link CoapClient} is detached
	 * from the executors of this resource, a {@link CoapClient#shutdown()} will
	 * therefore not shutdown the resources executor.
	 * 
	 * @param incoming incoming exchange to determine the endpoint for outgoing
	 *                 requests
	 * @return the CoAP client.
	 * @throws IllegalStateException if executors are not available
	 * @since 3.0
	 */
	public CoapClient createClient(CoapExchange incoming) {
		return createClient(incoming.advanced().getEndpoint());
	}

	/**
	 * Creates a {@link CoapClient} that uses the same executor as this resource and
	 * the provided endpoint. The endpoint may be accessed by
	 * {@link Exchange#getEndpoint()}. The {@link CoapClient} is detached from the
	 * executors of this resource, a {@link CoapClient#shutdown()} will therefore
	 * not shutdown the resources executor.
	 * 
	 * @param outgoing endpoint for outgoing request.
	 * @return the CoAP client.
	 * @throws IllegalStateException if executors are not available
	 * @since 3.0
	 */
	public CoapClient createClient(Endpoint outgoing) {
		CoapClient client = new CoapClient();
		try {
			client.setExecutors(executor, secondaryExecutor, true);
		} catch (NullPointerException ex) {
			throw new IllegalStateException("At least one executor is not availabe!");
		}
		client.setEndpoint(outgoing);
		return client;
	}
}
