/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - derived from org.eclipse.californium.examples.ExampleCrossProxy
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Date;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.proxy2.ClientEndpoints;
import org.eclipse.californium.proxy2.ClientSingleEndpoint;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.EndpointPool;
import org.eclipse.californium.proxy2.Http2CoapTranslator;
import org.eclipse.californium.proxy2.HttpClientFactory;
import org.eclipse.californium.proxy2.ProxyHttpServer;
import org.eclipse.californium.proxy2.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;
import org.eclipse.californium.proxy2.resources.ProxyHttpClientResource;
import org.eclipse.californium.proxy2.resources.StatsResource;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.eclipse.californium.proxy2.resources.CacheResource;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.eclipse.californium.proxy2.resources.ProxyCacheResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Demonstrates the examples for cross proxy functionality of CoAP.
 * 
 * Http2CoAP: Insert in browser: URI:
 * http://localhost:8080/proxy/coap://localhost:PORT/target
 * 
 * Http2LocalCoAPResource: Insert in browser: URI:
 * http://localhost:8080/local/target
 * 
 * Http2CoAP: configure browser to use the proxy "localhost:8080". Insert in
 * browser: ("localhost" requests are not send to a proxy, so use the hostname
 * or none-local-ip-address) URI: http://<hostname>:5683/target/coap:
 * 
 * CoAP2CoAP: Insert in Copper: 
 * <pre>
 * URI: coap://localhost:PORT/coap2coap 
 * Proxy: coap://localhost:PORT/targetA
 * </pre>
 *
 * CoAP2Http: Insert in Copper:
 * <pre>
 * URI: coap://localhost:PORT/coap2http 
 * Proxy: http://lantersoft.ch/robots.txt
 * </pre>
 */
public class CrossExampleProxy2 {

	private static final Logger STATISTIC_LOGGER = LoggerFactory.getLogger("org.eclipse.californium.proxy.statistics");

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("Californium.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Example Proxy";
	/**
	 * Default maximum resource size.
	 */
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	/**
	 * Default block size.
	 */
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	/**
	 * Special network configuration defaults handler.
	 */
	private static final NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_ACTIVE_PEERS, 20000);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setString(Keys.DEDUPLICATOR, Keys.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60 * 60 * 24); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 10); // 10s
			config.setInt(Keys.TCP_CONNECT_TIMEOUT, 15 * 1000); // 15s
			config.setInt(Keys.TLS_HANDSHAKE_TIMEOUT, 30 * 1000); // 30s
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 8192);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 8192);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 60);
		}

	};

	private static final String COAP2COAP = "coap2coap";
	private static final String COAP2HTTP = "coap2http";

	private static String start;

	private CoapServer coapProxyServer;
	private boolean useEndpointsPool;
	private ClientEndpoints endpoints;
	private ProxyHttpServer httpServer;
	private int coapPort;
	private int httpPort;
	private CacheResource cache;

	public CrossExampleProxy2(NetworkConfig config, boolean accept, boolean cache) throws IOException {
		HttpClientFactory.setNetworkConfig(config);
		coapPort = config.getInt(Keys.COAP_PORT);
		httpPort = config.getInt(Keys.HTTP_PORT);
		int threads = config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT);
		ScheduledExecutorService mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads,
				new DaemonThreadFactory("Proxy#"));
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
		Coap2CoapTranslator translater = new Coap2CoapTranslator();
		NetworkConfig outgoingConfig = new NetworkConfig(config);
		if (useEndpointsPool) {
			outgoingConfig.setInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, 1);
			outgoingConfig.setInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, 1);
			endpoints = new EndpointPool(1000, 250, outgoingConfig, mainExecutor, secondaryExecutor);
		} else {
			outgoingConfig.setString(Keys.MID_TRACKER, "NULL");
			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			builder.setNetworkConfig(outgoingConfig);
			endpoints = new ClientSingleEndpoint(builder.build());
		}
		ProxyCacheResource cacheResource = null;
		StatsResource statsResource = null;
		if (cache) {
			cacheResource = new ProxyCacheResource(true);
			statsResource = new StatsResource(cacheResource);
		}
		ProxyCoapResource coap2coap = new ProxyCoapClientResource(COAP2COAP, false, accept, translater, endpoints);
		ProxyCoapResource coap2http = new ProxyHttpClientResource(COAP2HTTP, false, accept, new Coap2HttpTranslator());
		if (cache) {
			coap2coap.setCache(cacheResource);
			coap2coap.setStatsResource(statsResource);
			coap2http.setCache(cacheResource);
			coap2http.setStatsResource(statsResource);
		}
		// Forwards requests Coap to Coap or Coap to Http server
		coapProxyServer = new CoapServer(config, coapPort);
		MessageDeliverer local = coapProxyServer.getMessageDeliverer();
		ForwardProxyMessageDeliverer proxyMessageDeliverer = new ForwardProxyMessageDeliverer(coapProxyServer.getRoot(),
				translater);
		proxyMessageDeliverer.addProxyCoapResources(coap2coap, coap2http);
		proxyMessageDeliverer.addExposedServiceAddresses(new InetSocketAddress(coapPort));
		coapProxyServer.setMessageDeliverer(proxyMessageDeliverer);
		coapProxyServer.setExecutors(mainExecutor, secondaryExecutor, false);
		coapProxyServer.add(coap2http);
		coapProxyServer.add(coap2coap);
		if (cache) {
			coapProxyServer.add(statsResource);
		}
		coapProxyServer.add(new SimpleCoapResource("target",
				"Hi! I am the local coap server on port " + coapPort + ". Request %d."));

		CoapResource targets = new CoapResource("targets");
		coapProxyServer.add(targets);

		// HTTP Proxy which forwards http request to coap server and forwards
		// translated coap response back to http client
		httpServer = new ProxyHttpServer(config, 8080);
		httpServer.setHttpTranslator(new Http2CoapTranslator());
		httpServer.setLocalCoapDeliverer(local);
		httpServer.setProxyCoapDeliverer(proxyMessageDeliverer);
		httpServer.start();
		System.out.println("** HTTP Local at: http://localhost:" + httpPort + "/local/");
		System.out.println("** HTTP Proxy at: http://localhost:" + httpPort + "/proxy/");

		coapProxyServer.start();
		System.out.println("** CoAP Proxy at: coap://localhost:" + coapPort + "/coap2http");
		System.out.println("** CoAP Proxy at: coap://localhost:" + coapPort + "/coap2coap");
		this.cache = cacheResource;
	}

	public static void main(String args[]) throws IOException {
		NetworkConfig proxyConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CrossExampleProxy2 proxy = new CrossExampleProxy2(proxyConfig, false, true);
		ExampleHttpServer httpServer = null;
		NetworkConfig config = ExampleCoapServer.init();
		for (int index = 0; index < args.length; ++index) {
			Integer port = parse(args[index], "coap", ExampleCoapServer.DEFAULT_COAP_PORT, config,
					NetworkConfig.Keys.COAP_PORT);
			if (port != null) {
				new ExampleCoapServer(config, port);

				// reverse proxy: add a proxy resource with a translator
				// returning a fixed destination URI
				// don't add this to the ProxyMessageDeliverer
				URI destination = URI.create("coap://localhost:" + port + "/coap-target");
				ProxyCoapResource reverseProxy = ProxyCoapResource.createReverseProxy("destination1", true, true, true,
						destination, proxy.endpoints);
				reverseProxy.setCache(proxy.cache);
				proxy.coapProxyServer.getRoot().getChild("targets").add(reverseProxy);
				System.out.println("CoAP Proxy at: coap://localhost:" + proxy.coapPort
						+ "/coap2coap and demo-server at coap://localhost:" + port + ExampleCoapServer.RESOURCE);
				System.out.println("HTTP Proxy at: http://localhost:" + proxy.httpPort + "/proxy/coap://localhost:"
						+ port + ExampleCoapServer.RESOURCE);
			} else {
				port = parse(args[index], "http", ExampleHttpServer.DEFAULT_PORT, null, null);
				if (port != null) {
					httpServer = new ExampleHttpServer(config, port);
					// reverse proxy: add a proxy resource with a translator
					// returning a fixed destination URI
					// don't add this to the ProxyMessageDeliverer
					URI destination = URI.create("http://localhost:" + port + "/http-target");
					ProxyCoapResource reverseProxy = ProxyCoapResource.createReverseProxy("destination2", true, true, true,
							destination, proxy.endpoints);
					reverseProxy.setCache(proxy.cache);
					proxy.coapProxyServer.getRoot().getChild("targets").add(reverseProxy);
					System.out.println("CoAP Proxy at: coap://localhost:" + proxy.coapPort
							+ "/coap2http and demo server at http://localhost:" + port + ExampleHttpServer.RESOURCE);
				}
			}
		}
		startManagamentStatistic();
		Runtime runtime = Runtime.getRuntime();
		long max = runtime.maxMemory();
		System.out.println(
				CrossExampleProxy2.class.getSimpleName() + " started (" + max / (1024 * 1024) + "MB heap) ...");
		long lastGcCount = 0;
		NetStatLogger netstat = new NetStatLogger("udp");
		for (;;) {
			try {
				Thread.sleep(15000);
			} catch (InterruptedException e) {
				break;
			}
			long used = runtime.totalMemory() - runtime.freeMemory();
			int fill = (int) ((used * 100L) / max);
			if (fill > 80) {
				System.out.println("Maxium heap size: " + max / (1024 * 1024) + "M " + fill + "% used.");
				System.out.println("Heap may exceed! Enlarge the maxium heap size.");
				System.out.println("Or consider to reduce the value of " + Keys.EXCHANGE_LIFETIME);
				System.out.println("in \"" + CONFIG_FILE + "\" or set");
				System.out.println(Keys.DEDUPLICATOR + " to " + Keys.NO_DEDUPLICATOR + " there.");
				break;
			}
			long gcCount = 0;
			for (GarbageCollectorMXBean gcMXBean : ManagementFactory.getGarbageCollectorMXBeans()) {
				long count = gcMXBean.getCollectionCount();
				if (0 < count) {
					gcCount += count;
				}
			}
			if (lastGcCount < gcCount) {
				printManagamentStatistic();
				lastGcCount = gcCount;
				netstat.dump();
				if (httpServer != null) {
					httpServer.dumpStatistic();
				}
			}
		}

	}

	private static Integer parse(String arg, String prefix, int defaultValue, NetworkConfig config, String key) {
		Integer result = null;
		if (arg.startsWith(prefix)) {
			arg = arg.substring(prefix.length());
			if (arg.isEmpty()) {
				if (config == null || key == null) {
					result = defaultValue;
				} else {
					result = config.getInt(key, defaultValue);
				}
			} else if (arg.startsWith("=")) {
				arg = arg.substring(1);
				result = Integer.decode(arg);
			}
		}
		return result;
	}

	private static class SimpleCoapResource extends CoapResource {

		private final String value;

		private final AtomicInteger counter = new AtomicInteger();

		public SimpleCoapResource(String name, String value) {
			// set the resource hidden
			super(name);
			getAttributes().setTitle("Simple local coap resource.");
			this.value = value;
		}

		public void handleGET(CoapExchange exchange) {
			exchange.setMaxAge(0);
			exchange.respond(ResponseCode.CONTENT, String.format(value, counter.incrementAndGet()),
					MediaTypeRegistry.TEXT_PLAIN);
		}
	}

	private static void startManagamentStatistic() {
		ThreadMXBean mxBean = ManagementFactory.getThreadMXBean();
		if (mxBean.isThreadCpuTimeSupported() && !mxBean.isThreadCpuTimeEnabled()) {
			mxBean.setThreadCpuTimeEnabled(true);
		}
		RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
		start = new Date(runtimeMXBean.getStartTime()).toString();
	}

	private static void printManagamentStatistic() {
		OperatingSystemMXBean osMxBean = ManagementFactory.getOperatingSystemMXBean();
		int processors = osMxBean.getAvailableProcessors();
		RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
		Logger logger = STATISTIC_LOGGER;
		logger.info("{} processors, started {}, up {}", processors, start, formatTime(runtimeMXBean.getUptime()));
		ThreadMXBean threadMxBean = ManagementFactory.getThreadMXBean();
		if (threadMxBean.isThreadCpuTimeSupported() && threadMxBean.isThreadCpuTimeEnabled()) {
			long alltime = 0;
			long[] ids = threadMxBean.getAllThreadIds();
			for (long id : ids) {
				long time = threadMxBean.getThreadCpuTime(id);
				if (0 < time) {
					alltime += time;
				}
			}
			long pTime = alltime / processors;
			logger.info("cpu-time: {} ms (per-processor: {} ms)", TimeUnit.NANOSECONDS.toMillis(alltime),
					TimeUnit.NANOSECONDS.toMillis(pTime));
		}
		long gcCount = 0;
		long gcTime = 0;
		for (GarbageCollectorMXBean gcMxBean : ManagementFactory.getGarbageCollectorMXBeans()) {
			long count = gcMxBean.getCollectionCount();
			if (0 < count) {
				gcCount += count;
			}
			long time = gcMxBean.getCollectionTime();
			if (0 < time) {
				gcTime += time;
			}
		}
		logger.info("gc: {} ms, {} calls", gcTime, gcCount);
		double loadAverage = osMxBean.getSystemLoadAverage();
		if (!(loadAverage < 0.0d)) {
			logger.info("average load: {}", String.format("%.2f", loadAverage));
		}
	}

	private static String formatTime(long millis) {
		long time = millis;
		if (time < 10000) {
			return time + " [ms]";
		}
		time /= 100; // 1/10s
		if (time < 10000) {
			return (time / 10) + "." + (time % 10) + " [s]";
		}
		time /= 10;
		long seconds = time % 60;
		time /= 60;
		long minutes = time % 60;
		time /= 60;
		long hours = time % 24;
		time /= 24; // days
		if (time > 0) {
			return String.format("%d:%02d:%02d:%02d [d:hh:mm:ss]", time, hours, minutes, seconds);
		} else {
			return String.format("%d:%02d:%02d [h:mm:ss]", hours, minutes, seconds);
		}
	}
}
