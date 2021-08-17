/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cluster;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.server.ServersSerializationUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * K8s Monitor service.
 * 
 * <dl>
 * <dt>{@code http://<pod>:8080/ready}</dt>
 * <dd>service indicating the readiness of the assigned dtls connector.</dd>
 * <dt>{@code https://<pod>:5884/restore}</dt>
 * <dd>service to download the connections from the assigned dtls
 * connector.</dd>
 * </dl>
 * 
 * @since 3.0
 */
@SuppressWarnings("restriction")
public class JdkK8sMonitorService {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(JdkK8sMonitorService.class);

	private static final String DTLS_MAX_QUIET_IN_S = "DTLS_MAX_QUIET_IN_S";

	/**
	 * Indicates, that the CoAP servers has been stopped by
	 * {@link RestoreHttpClient}.
	 */
	private final AtomicBoolean stopped = new AtomicBoolean();

	/**
	 * Local (non secure) address-
	 */
	private final InetSocketAddress localAddress;
	/**
	 * Local secure address.
	 */
	private final InetSocketAddress localSecureAddress;
	/**
	 * sSsl context for https.
	 */
	private final SSLContext context;
	/**
	 * List of related coap servers.
	 */
	private final List<CoapServer> coapServers = new ArrayList<>();
	/**
	 * List of ready components.
	 */
	private final List<Readiness> components = new ArrayList<>();
	/**
	 * Maximum quiet period in seconds to save the dtls context.
	 * 
	 * @since 3.0
	 */
	private final long maxQuietPeriodInSeconds;
	/**
	 * Executor for http server.
	 */
	private ExecutorService executor;
	/**
	 * Http server.
	 */
	private HttpServer server;
	/**
	 * Https server.
	 */
	private HttpsServer secureServer;

	/**
	 * Create k8s service.
	 * 
	 * @param localAddress local address for non secure endpoint (http).
	 * @param localSecureAddress local address for secure endpoint (https).
	 * @param context server ssl context
	 */
	public JdkK8sMonitorService(InetSocketAddress localAddress, InetSocketAddress localSecureAddress,
			SSLContext context) {
		this.localAddress = localAddress;
		this.localSecureAddress = localSecureAddress;
		this.context = context;
		Long quiet = StringUtil.getConfigurationLong(DTLS_MAX_QUIET_IN_S);
		if (quiet == null) {
			quiet = TimeUnit.HOURS.toSeconds(12);
		}
		maxQuietPeriodInSeconds = quiet;
	}

	/**
	 * Add CoapServer to monitor.
	 * 
	 * @param coapServer coap server
	 * @throws NullPointerException if coap server is {@code null}
	 */
	public void addServer(CoapServer coapServer) {
		if (coapServer == null) {
			throw new NullPointerException("CoapServer must not be null!");
		}
		coapServers.add(coapServer);
	}

	/**
	 * Remove CoapServer from monitor.
	 * 
	 * @param coapServer coap server
	 * @throws NullPointerException if coap server is {@code null}
	 */
	public void removeServer(CoapServer coapServer) {
		if (coapServer == null) {
			throw new NullPointerException("CoapServer must not be null!");
		}
		coapServers.remove(coapServer);
	}

	/**
	 * Remove all CoapServer from monitor.
	 */
	public void clearServer() {
		coapServers.clear();
	}

	/**
	 * Add ready component to monitor.
	 * 
	 * @param component ready component
	 * @throws NullPointerException if component is {@code null}
	 */
	public void addComponent(Readiness component) {
		if (component == null) {
			throw new NullPointerException("Component must not be null!");
		}
		components.add(component);
	}

	/**
	 * Remove ready component from monitor.
	 * 
	 * @param component ready component
	 * @throws NullPointerException if component is {@code null}
	 */
	public void removeComponent(Readiness component) {
		if (component == null) {
			throw new NullPointerException("Component must not be null!");
		}
		components.remove(component);
	}

	/**
	 * Remove all ready components from monitor.
	 */
	public void clearComponents() {
		components.clear();
	}

	/**
	 * Check, if at least one CoAP server is available and all CoAP servers are
	 * running and all components are ready.
	 * 
	 * @return {@code true}, if the CoAP servers are running and the components
	 *         are ready, {@code false}, otherwise.
	 */
	public boolean isReady() {
		if (coapServers.isEmpty()) {
			return false;
		}
		for (CoapServer server : coapServers) {
			if (!server.isRunning()) {
				return false;
			}
		}
		for (Readiness component : components) {
			if (!component.isReady()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Start monitor service.
	 */
	public void start() {
		executor = java.util.concurrent.Executors.newCachedThreadPool();
		if (localAddress != null) {
			try {
				server = HttpServer.create(localAddress, 10);
				server.createContext("/alive", new AliveHandler());
				server.createContext("/ready", new ReadyHandler());
				// Thread control is given to executor service.
				server.setExecutor(executor);
				server.start();
			} catch (IOException ex) {
				LOGGER.warn("starting http-server {} failed!", localAddress);
			}
		}
		if (localSecureAddress != null && context != null) {
			try {
				secureServer = HttpsServer.create(localSecureAddress, 10);
				secureServer.setHttpsConfigurator(new HttpsConfigurator(context) {

					@Override
					public void configure(HttpsParameters parameters) {
						parameters.setNeedClientAuth(true);
					}

				});
				secureServer.createContext("/restore", new RestoreHandler());
				// Thread control is given to executor service.
				secureServer.setExecutor(executor);
				secureServer.start();
			} catch (IOException ex) {
				LOGGER.warn("starting {} failed!", localAddress);
			}
		}
	}

	/**
	 * Stop monitor service.
	 */
	public void stop() {
		if (server != null) {
			server.stop(2);
		}
		if (secureServer != null) {
			secureServer.stop(2);
		}
		if (executor != null) {
			executor.shutdown();
		}
	}

	class ReadyHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			LOGGER.info("request: {} {}", exchange.getRequestMethod(), exchange.getRequestURI());
			byte[] response;
			if (isReady()) {
				response = "OK\n".getBytes();
				exchange.sendResponseHeaders(200, response.length);
			} else {
				response = "DOWN\n".getBytes();
				exchange.sendResponseHeaders(503, response.length);
			}
			try (OutputStream os = exchange.getResponseBody()) {
				os.write(response);
			} catch (IOException e) {
				LOGGER.warn("write response to {} failed!", exchange.getRemoteAddress(), e);
			}
		}
	}

	class RestoreHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			LOGGER.info("request: {} {}", exchange.getRequestMethod(), exchange.getRequestURI());
			exchange.sendResponseHeaders(200, 0);
			try (OutputStream out = exchange.getResponseBody()) {
				int count = ServersSerializationUtil.saveServers(out, maxQuietPeriodInSeconds, coapServers);
				LOGGER.info("response: {} connections", count);
			} catch (IOException e) {
				LOGGER.warn("write response to {} failed!", exchange.getRemoteAddress(), e);
			} finally {
				stopped.set(true);
			}
		}
	}

	class AliveHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			LOGGER.info("request: {} {}", exchange.getRequestMethod(), exchange.getRequestURI());
			byte[] response;
			if (stopped.get()) {
				response = "SHUTDOWN\n".getBytes();
				exchange.sendResponseHeaders(503, response.length);
			} else {
				response = "OK\n".getBytes();
				exchange.sendResponseHeaders(200, response.length);
			}
			try (OutputStream os = exchange.getResponseBody()) {
				os.write(response);
			} catch (IOException e) {
				LOGGER.warn("write response to {} failed!", exchange.getRemoteAddress(), e);
			}
		}
	}
}
