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
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.examples.util.SecureEndpointPool;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.EndpointPool;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.eclipse.californium.proxy2.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Demonstrates the examples for a secure proxy functionality of CoAP.
 * 
 * CoAP2CoAP: Insert in Copper: URI: coap://localhost:PORT/coap2coap Proxy:
 * coaps://californium.eclipseprojects.io:5684/test
 *
 */
public class ExampleSecureProxy2 {

	private static final Logger STATISTIC_LOGGER = LoggerFactory.getLogger("org.eclipse.californium.proxy.statistics");

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumSecureProxy3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Secure Example Proxy";
	/**
	 * Default maximum resource size.
	 */
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	/**
	 * Default block size.
	 */
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	public static final IntegerDefinition OUTGOING_MAX_ACTIVE_PEERS = new IntegerDefinition("OUTGOING_MAX_ACTIVE_PEERS",
			"Maximum number of outgoing peers per endpoint.", 32, 8);

	public static final IntegerDefinition OUTGOING_DTLS_MAX_CONNECTIONS = new IntegerDefinition(
			"OUTGOING_DTLS_MAX_CONNECTIONS", "Maximum number of outgoing DTLS connections per endpoint.", 32, 8);

	public static final IntegerDefinition MAX_CONNECTION_POOL_SIZE = new IntegerDefinition("MAX_CONNECTION_POOL_SIZE",
			"Maximum size of connection pool.", 1000, 32);

	public static final IntegerDefinition INIT_CONNECTION_POOL_SIZE = new IntegerDefinition("INIT_CONNECTION_POOL_SIZE",
			"Initial size of connection pool.", 250, 16);

	static {
		CoapConfig.register();
		UdpConfig.register();
		DtlsConfig.register();
		TcpConfig.register();
		Proxy2Config.register();
	}

	/**
	 * Special configuration defaults handler.
	 */
	private static final DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 20000);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 24, TimeUnit.HOURS);
			config.set(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, 10, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTP_CONNECT_TIMEOUT, 15, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTPS_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(UdpConfig.UDP_RECEIVE_BUFFER_SIZE, 8192);
			config.set(UdpConfig.UDP_SEND_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_RECEIVE_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_SEND_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1);
			config.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 1);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 60, TimeUnit.SECONDS);
			config.set(OUTGOING_MAX_ACTIVE_PEERS, 32);
			config.set(OUTGOING_DTLS_MAX_CONNECTIONS, 32);
			config.set(MAX_CONNECTION_POOL_SIZE, 1000);
			config.set(INIT_CONNECTION_POOL_SIZE, 250);
		}

	};

	private static final String COAP2COAP = "coap2coap";

	private static String start;

	private CoapServer coapProxyServer;
	private EndpointPool pool;
	private int coapPort;

	public ExampleSecureProxy2(Configuration config) throws IOException, GeneralSecurityException {
		coapPort = config.get(CoapConfig.COAP_PORT);
		int threads = config.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT);
		ScheduledExecutorService mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads,
				new DaemonThreadFactory("Proxy#"));
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
		Coap2CoapTranslator translater = new Coap2CoapTranslator();
		Configuration outgoingConfig = new Configuration(config);
		outgoingConfig.set(CoapConfig.MAX_ACTIVE_PEERS, config.get(OUTGOING_MAX_ACTIVE_PEERS));
		outgoingConfig.set(DtlsConfig.DTLS_MAX_CONNECTIONS, config.get(OUTGOING_DTLS_MAX_CONNECTIONS));
		outgoingConfig.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1);
		outgoingConfig.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 1);
		DtlsConnectorConfig.Builder builder = SecureEndpointPool.setupClient(outgoingConfig);
		pool = new SecureEndpointPool(config.get(MAX_CONNECTION_POOL_SIZE), config.get(INIT_CONNECTION_POOL_SIZE),
				outgoingConfig, mainExecutor, secondaryExecutor, builder.build());
		ProxyCoapResource coap2coap = new ProxyCoapClientResource(COAP2COAP, false, false, translater, pool);
		coap2coap.setMaxResourceBodySize(config.get(CoapConfig.MAX_RESOURCE_BODY_SIZE));

		// Forwards requests Coap to Coap or Coap to Http server
		coapProxyServer = new CoapServer(config, coapPort);
		ForwardProxyMessageDeliverer proxyMessageDeliverer = new ForwardProxyMessageDeliverer(coapProxyServer.getRoot(),
				translater, config);
		proxyMessageDeliverer.addProxyCoapResources(coap2coap);
		proxyMessageDeliverer.addExposedServiceAddresses(new InetSocketAddress(coapPort));
		coapProxyServer.setMessageDeliverer(proxyMessageDeliverer);
		coapProxyServer.setExecutors(mainExecutor, secondaryExecutor, false);
		coapProxyServer.add(coap2coap);

		CoapResource targets = new CoapResource("targets");
		coapProxyServer.add(targets);

		// HTTP Proxy which forwards http request to coap server and forwards
		// translated coap response back to http client
		coapProxyServer.start();
		System.out.println("** CoAP Proxy at: coap://localhost:" + coapPort + "/coap2coap");
	}

	public static void main(String args[]) throws IOException, GeneralSecurityException {
		Configuration proxyConfig = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		ExampleSecureProxy2 proxy = new ExampleSecureProxy2(proxyConfig);
		Configuration config = ExampleCoapServer.init();
		for (int index = 0; index < args.length; ++index) {
			Integer port = parse(args[index], "coaps", ExampleCoapServer.DEFAULT_COAP_SECURE_PORT, config,
					CoapConfig.COAP_SECURE_PORT);
			if (port != null) {
				DtlsConnectorConfig.Builder builder = SecureEndpointPool.setupServer(config);
				builder.setAddress(new InetSocketAddress(port));
				DTLSConnector connector = new DTLSConnector(builder.build());
				CoapEndpoint endpoint = CoapEndpoint.builder().setConfiguration(config).setConnector(connector).build();
				new ExampleCoapServer(endpoint);

				// reverse proxy: add a proxy resource with a translator
				// returning a fixed destination URI
				// don't add this to the ProxyMessageDeliverer
				URI destination = URI.create("coaps://localhost:" + port + "/coap-target");
				CoapResource reverseProxy = ProxyCoapResource.createReverseProxy("destination1", true, true, true,
						destination, proxy.pool);
				proxy.coapProxyServer.getRoot().getChild("targets").add(reverseProxy);
				System.out.println("CoAP Proxy at: coap://localhost:" + proxy.coapPort
						+ "/coap2coap and demo-server at coaps://localhost:" + port + ExampleCoapServer.RESOURCE);
			}
		}
		startManagamentStatistic();
		Runtime runtime = Runtime.getRuntime();
		long max = runtime.maxMemory();
		System.out.println(
				ExampleSecureProxy2.class.getSimpleName() + " started (" + max / (1024 * 1024) + "MB heap) ...");
		long lastGcCount = 0;
		NetStatLogger netstat = new NetStatLogger("udp", false);
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
				System.out.println("Or consider to reduce the value of " + CoapConfig.EXCHANGE_LIFETIME);
				System.out.println("in \"" + CONFIG_FILE + "\" or set");
				System.out.println(CoapConfig.DEDUPLICATOR + " to " + CoapConfig.NO_DEDUPLICATOR + " there.");
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
			}
		}

	}

	private static Integer parse(String arg, String prefix, int defaultValue, Configuration config,
			IntegerDefinition key) {
		Integer result = null;
		if (arg.startsWith(prefix)) {
			arg = arg.substring(prefix.length());
			if (arg.isEmpty()) {
				if (config != null && key != null) {
					result = config.get(key);
				}
				if (result == null) {
					result = defaultValue;
				}
			} else if (arg.startsWith("=")) {
				arg = arg.substring(1);
				result = Integer.decode(arg);
			}
		}
		return result;
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
