/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
import java.util.Date;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.http.HttpClientFactory;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.eclipse.californium.proxy2.resources.ProxyCacheResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;
import org.eclipse.californium.proxy2.resources.ProxyHttpClientResource;
import org.eclipse.californium.proxy2.resources.StatsResource;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic coap to http proxy.
 * 
 * Supports outgoing http and https.
 * 
 * @since 3.7
 */
public class ExampleCoapToHttpProxy2 {

	private static final Logger STATISTIC_LOGGER = LoggerFactory.getLogger("org.eclipse.californium.proxy.statistics");

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumProxy3.properties");
	/**
	 * Header for configuration.
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

	static {
		CoapConfig.register();
		UdpConfig.register();
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
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 24, TimeUnit.HOURS);
			config.set(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, 10, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTP_CONNECT_TIMEOUT, 15, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTPS_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(UdpConfig.UDP_RECEIVE_BUFFER_SIZE, 8192);
			config.set(UdpConfig.UDP_SEND_BUFFER_SIZE, 8192);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 60, TimeUnit.SECONDS);
		}

	};

	private static final String COAP2HTTP = "coap2http";

	private static String start;

	private CoapServer coapProxyServer;
	private int coapPort;

	public ExampleCoapToHttpProxy2(Configuration config, boolean accept, boolean cache) throws IOException {
		HttpClientFactory.setNetworkConfig(config);
		coapPort = config.get(CoapConfig.COAP_PORT);
		int threads = config.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT);
		ScheduledExecutorService mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads,
				new DaemonThreadFactory("Proxy#"));
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
		Coap2CoapTranslator translater = new Coap2CoapTranslator();
		ProxyCacheResource cacheResource = null;
		StatsResource statsResource = null;
		if (cache) {
			cacheResource = new ProxyCacheResource(config, true);
			statsResource = new StatsResource(cacheResource);
		}
		ProxyCoapResource coap2http = new ProxyHttpClientResource(COAP2HTTP, false, accept, new Coap2HttpTranslator(),
				"http", "https");
		coap2http.setMaxResourceBodySize(config.get(CoapConfig.MAX_RESOURCE_BODY_SIZE));
		if (cache) {
			coap2http.setCache(cacheResource);
			coap2http.setStatsResource(statsResource);
		}
		// Forwards requests Coap to Coap or Coap to Http server
		coapProxyServer = new CoapServer(config, coapPort);
		ForwardProxyMessageDeliverer proxyMessageDeliverer = new ForwardProxyMessageDeliverer(coapProxyServer.getRoot(),
				translater, config);
		proxyMessageDeliverer.addProxyCoapResources(coap2http);
		proxyMessageDeliverer.addExposedServiceAddresses(new InetSocketAddress(coapPort));
		coapProxyServer.setMessageDeliverer(proxyMessageDeliverer);
		coapProxyServer.setExecutors(mainExecutor, secondaryExecutor, false);
		coapProxyServer.add(coap2http);
		if (cache) {
			coapProxyServer.add(statsResource);
		}
		coapProxyServer.start();
		System.out.println("** CoAP Proxy at: coap://localhost:" + coapPort + "/coap2http");
		// receiving on any address => enable LocalAddressResolver
		proxyMessageDeliverer.startLocalAddressResolver();
	}

	public static void main(String args[]) throws IOException {
		Configuration proxyConfig = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		new ExampleCoapToHttpProxy2(proxyConfig, false, true);
	
		startManagamentStatistic();
		Runtime runtime = Runtime.getRuntime();
		long max = runtime.maxMemory();
		System.out.println(
				ExampleCoapToHttpProxy2.class.getSimpleName() + " started (" + max / (1024 * 1024) + "MB heap) ...");
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
			}
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
