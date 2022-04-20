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

import java.io.File;
import java.io.IOException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.server.HttpServer;

/**
 * Example HTTP server for proxy demonstration.
 * 
 * {@code http://localhost:8000/http-target}
 */
public class ExampleHttpServer {

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumHttpDemo3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium HTTP Properties file for Proxy Demo-Server";

	public static final ThreadGroup HTTP_THREAD_GROUP = new ThreadGroup("http"); //$NON-NLS-1$

	public static final int DEFAULT_PORT = 8000;
	public static final String RESOURCE = "/http-target";

	static {
		Proxy2Config.register();
	}

	private SimpleCounterStatistic requests = new SimpleCounterStatistic("http-requests");
	private AtomicLong requestCounter = new AtomicLong();
	private long lastRequestCounterSync;

	public ExampleHttpServer(Configuration config, final int httpPort) throws IOException {
		HttpServer server = new HttpServer(config, httpPort);
		server.setSimpleResource(RESOURCE, "Hi! I am the Http Server on %s. Request %d.", requestCounter);
		server.start();
		System.out.println("==================================================");
		System.out.println("== Started HTTP server on port " + httpPort);
		System.out.println("== Request: http://<host>:" + httpPort + RESOURCE);
		System.out.println("==================================================");
	}

	public void dumpStatistic() {
		long count = requestCounter.get();
		long delta = count - lastRequestCounterSync;
		lastRequestCounterSync = count;
		if (delta > 0) {
			requests.increment((int) delta);
		}
		System.out.println(requests.dump(0));
	}

	public static Configuration init() {
		return Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, null);
	}

	public static void main(String arg[]) throws IOException {
		// NetworkConfig HTTP_PORT is used for proxy
		Configuration config = init();
		int port = DEFAULT_PORT;
		if (arg.length > 0) {
			port = Integer.parseInt(arg[0]);
		}
		final ExampleHttpServer server = new ExampleHttpServer(config, port);
		ScheduledExecutorService executor = ExecutorsUtil
				.newSingleThreadScheduledExecutor(new NamedThreadFactory("statistic"));
		executor.scheduleAtFixedRate(new Runnable() {

			@Override
			public void run() {
				server.dumpStatistic();
			}
		}, 10, 10, TimeUnit.SECONDS);
	}
}
