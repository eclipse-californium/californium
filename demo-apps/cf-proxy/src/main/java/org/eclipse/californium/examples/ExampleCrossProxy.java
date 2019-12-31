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
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.net.URI;
import java.util.Date;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.proxy.ProxyHttpServer;
import org.eclipse.californium.proxy.TranslationException;
import org.eclipse.californium.proxy.UriTranslator;
import org.eclipse.californium.proxy.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy.resources.ProxyHttpClientResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class ExampleCrossProxy. This class demonstrates the examples for cross proxy
 * functionality of CoAP.
 * <p>
 * Http2CoAP: <br>
 * Insert URI in browser:
 * {@link http://localhost:8080/proxy/coap://localhost:5683/coap-target}
 * <p>
 * CoAP2CoAP: <br>
 * Insert in Copper: URI: {@link coap://localhost:5685/coap2coap} <br>
 * Proxy: {@link coap://localhost:5683/coap-target}
 * <p>
 * CoAP2Http: <br>
 * Insert in Copper: URI: {@link coap://localhost:5685/coap2http} <br>
 * Proxy: {@link http://localhost:8000/http-target}
 */
public class ExampleCrossProxy {
	private static final Logger STATISTIC_LOGGER = LoggerFactory.getLogger("org.eclipse.californium.proxy.statistics");

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumProxy.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Proxy";
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
			config.setInt(Keys.COAP_PORT, 5685);
			config.setInt(Keys.HTTP_PORT, 8080);
			config.setInt(Keys.MAX_ACTIVE_PEERS, 20000);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.EXCHANGE_LIFETIME, 24700); // 24.7s instead of 247s
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60 * 60 * 24); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 60 * 60 * 12); // 12h
			config.setInt(Keys.TCP_CONNECT_TIMEOUT, 30 * 1000); // 20s
			config.setInt(Keys.TLS_HANDSHAKE_TIMEOUT, 30 * 1000); // 20s
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 8192);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 8192);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 60);
		}

	};
	private static final String COAP2COAP = "coap2coap";
	private static final String COAP2HTTP = "coap2http";

	private static String start;

	private CoapServer coapProxyServer;
	private int coapPort;
	private int httpPort;

	public ExampleCrossProxy(NetworkConfig config) throws IOException {
		coapPort = config.getInt(Keys.COAP_PORT);
		httpPort = config.getInt(Keys.HTTP_PORT);
		int threads = config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT);
		ScheduledExecutorService mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads, new DaemonThreadFactory("Proxy#"));
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
		final CoapResource coap2coap = new ProxyCoapClientResource(config, COAP2COAP, mainExecutor, secondaryExecutor);
		final CoapResource coap2http = new ProxyHttpClientResource(COAP2HTTP);
		// HTTP Proxy which forwards http request to coap server and forwards
		// translated coap response back to http client
		boolean proxy = true;
		boolean local = true;
		ProxyHttpServer proxyHttpServer = new ProxyHttpServer(httpPort, proxy, local);

		// Forwards requests Coap to Coap or Coap to Http server
		coapProxyServer = new CoapServer(config, coapPort);
		coapProxyServer.setExecutors(mainExecutor, secondaryExecutor, false);
		coapProxyServer.add(coap2http);
		coapProxyServer.add(coap2coap);
		coapProxyServer
				.add(new SimpleCoapResource("internal", "Hi! I am the local Coap Server on port " + coapPort + "."));
		coapProxyServer.setMessageDeliverer(new ProxyMessageDeliverer(coapProxyServer.getRoot()));
		coapProxyServer.add(proxyHttpServer.getStatistics());
		coapProxyServer.start();
		System.out.println("** CoAP Proxy at: coap://localhost:" + coapPort + "/coap2http");
		System.out.println("** CoAP Proxy at: coap://localhost:" + coapPort + "/coap2coap");
		if (proxy) {
			proxyHttpServer.setProxyCoapDeliverer(coapProxyServer.getMessageDeliverer());
			System.out.println("** HTTP Proxy at: http://localhost:" + httpPort + "/proxy/");
		}
		if (local) {
			proxyHttpServer.setLocalCoapDeliverer(new ServerMessageDeliverer(coapProxyServer.getRoot()));
			System.out.println("** HTTP Local at: http://localhost:" + httpPort + "/local/");
		}
	}

	public static void main(String args[]) throws IOException {
		NetworkConfig proxyConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		ExampleCrossProxy proxy = new ExampleCrossProxy(proxyConfig);
		NetworkConfig config = NetworkConfig.getStandard();
		for (int index = 0; index < args.length; ++index) {
			Integer port = parse(args[index], "coap", ExampleCoapServer.DEFAULT_PORT, config, NetworkConfig.Keys.COAP_PORT);
			if (port != null) {
				new ExampleCoapServer(config, port);
				System.out.println("CoAP Proxy at: coap://localhost:" + proxy.coapPort
						+ "/coap2coap and coap://localhost:" + port + ExampleCoapServer.RESOURCE);
				System.out.println("HTTP Proxy at: http://localhost:" + proxy.httpPort + "/proxy/coap://localhost:"
						+ port + ExampleCoapServer.RESOURCE);
			} else {
				port = parse(args[index], "http", ExampleHttpServer.DEFAULT_PORT, null, null);
				if (port != null) {
					new ExampleHttpServer(config, port);
					System.out.println("CoAP Proxy at: coap://localhost:" + proxy.coapPort
							+ "/coap2http and http://localhost:" + port + ExampleHttpServer.RESOURCE);
				}
			}
		}
		startManagamentStatistic();
		Runtime runtime = Runtime.getRuntime();
		long max = runtime.maxMemory();
		System.out
				.println(ExampleCrossProxy.class.getSimpleName() + " started (" + max / (1024 * 1024) + "MB heap) ...");
		long lastGcCount = 0;
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

	private static class ProxyMessageDeliverer extends ServerMessageDeliverer {

		private ProxyMessageDeliverer(Resource root) {
			super(root);
		}

		@Override
		protected Resource findResource(Request request) {
			Resource resource = super.findResource(request);
			if (resource == getRootResource()
					&& (request.getOptions().hasProxyUri() || request.getOptions().hasProxyScheme())) {
				resource = null;
			}
			if (resource == null) {
				try {
					URI uri = UriTranslator.getDestinationURI(request);
					String scheme = uri.getScheme();
					if (scheme != null) {
						scheme = scheme.toLowerCase();
						if (scheme.equals("http") || scheme.equals("https")) {
							resource = getRootResource().getChild(COAP2HTTP);
						} else if (CoAP.isSupportedScheme(scheme)) {
							resource = getRootResource().getChild(COAP2COAP);
						}
					}
				} catch (TranslationException e) {
				}
			}
			return resource;
		}
	}

	private static class SimpleCoapResource extends CoapResource {

		private final String value;

		public SimpleCoapResource(String name, String value) {
			// set the resource hidden
			super(name);
			getAttributes().setTitle("Simple local coap resource.");
			this.value = value;
		}

		public void handleGET(CoapExchange exchange) {
			exchange.respond(value);
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
