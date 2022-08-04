/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 *                    was JdkK8sMonitorService
 ******************************************************************************/
package org.eclipse.californium.cluster;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.PersistentComponentUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * Monitor service.
 * 
 * <dl>
 * <dt>{@code http://<pod>:8080/ready}</dt>
 * <dd>service indicating the readiness of the assigned dtls connector.</dd>
 * <dt>{@code https://<pod>:5884/restore}</dt>
 * <dd>service to download the connections from the assigned dtls
 * connector.</dd>
 * </dl>
 * 
 * Usable with k8s to monitor the pod.
 * 
 * {@link #addServer(CoapServer)} all {@link CoapServer} and all other
 * {@link Readiness} components with {@link #addComponent(Readiness)} before
 * {@link #start()}. If {@link RestoreJdkHttpClient} is used to download the
 * state from the double on green/blue update, add that client as component as
 * well.
 * 
 * @since 3.4 (was JdkK8sMonitorService)
 */
@SuppressWarnings("restriction")
public class JdkMonitorService {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(JdkMonitorService.class);

	private static final long DELAY_IN_SECONDS = 4;

	/**
	 * State with delay switching to off.
	 * 
	 * @since 3.4
	 */
	private static class State {

		/**
		 * Name of the state for logging.
		 */
		private final String name;
		/**
		 * State, {@code true} for active, {@code false}, for not active.
		 */
		private boolean state;
		/**
		 * Realtime nanos, when state is pending. {@code -1}, if not pending.
		 * During the pending phase, the {@link #state} is already not active,
		 * but {@link #get()} and {@link #set(boolean, long, TimeUnit)} will
		 * still return {@code true}.
		 */
		private long pending = -1;

		/**
		 * Create state.
		 * 
		 * @param name name for logging
		 */
		private State(String name) {
			this.name = name;
		}

		/**
		 * Set state.
		 * 
		 * Switching to active without delay, switching to inactive with delay.
		 * 
		 * @param state {@code true} for active, {@code false}, for not active.
		 * @param delay delay in to switch from active to not active.
		 * @param unit time unit of delay
		 * @return delayed state, {@code true} for active, {@code false}, for
		 *         not active.
		 */
		private boolean set(boolean state, long delay, TimeUnit unit) {
			boolean result = state;
			String msg = "none";
			long now = ClockUtil.nanoRealtime();
			synchronized (this) {
				if (state) {
					this.state = true;
					this.pending = -1;
					msg = "active";
				} else if (this.state) {
					state = false;
					pending = now + unit.toNanos(delay);
					if (delay > 0) {
						msg = "shutdown";
					} else {
						msg = "down";
						result = false;
					}
				} else if (pending > -1) {
					msg = "shutdown";
					result = (pending - now) > 0;
					if (!result) {
						msg = "down";
					}
				}
			}
			LOGGER.info("{}: {}", name, msg);
			return result;
		}

		/**
		 * Get state.
		 * 
		 * @return delayed state, {@code true} for active, {@code false}, for
		 *         not active.
		 */
		private boolean get() {
			boolean result;
			long now = ClockUtil.nanoRealtime();
			synchronized (this) {
				if (state) {
					result = true;
				} else if (pending > -1) {
					result = (pending - now) > 0;
				} else {
					result = false;
				}
			}
			return result;
		}

		/**
		 * Get left pending time of active, before switching to inactive.
		 * 
		 * @param unit time unit
		 * @return left pending time in units. {@code -1}, not pending.
		 */
		private long left(TimeUnit unit) {
			long left = -1;
			long now = ClockUtil.nanoRealtime();
			synchronized (this) {
				if (pending > -1) {
					left = (pending - now);
					if (left < 0) {
						left = 0;
					}
				}
			}
			return unit.convert(left, TimeUnit.NANOSECONDS);
		}
	}

	/**
	 * Ready state.
	 * 
	 * Indicates to connect the pods network to the associated service. In order
	 * to prevent the connectors to send messages after the pod signals "not
	 * ready", the state is switched delayed from active to not active.
	 * Therefore unexpected messages pending after the connectors shutdown will
	 * still be sent in state "ready".
	 * 
	 * @see JdkMonitorService#DELAY_IN_SECONDS
	 * @since 3.4
	 */
	private final State stateReady = new State("ready");

	/**
	 * Alive state.
	 * 
	 * Indicates, that an other pod overtake the states.
	 * 
	 * @since 3.4
	 */
	private final State stateAlive = new State("alive");

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
	 * Stale threshold in seconds.
	 * 
	 * e.g. Connections without traffic for that time are skipped during
	 * serialization.
	 * 
	 * @since 3.4 (was maxQuietPeriodInSeconds)
	 */
	private final long staleThresholdInSeconds;
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
	 * @param staleThresholdInSeconds stale threshold in seconds. e.g.
	 *            Connections without traffic for that time are skipped during
	 *            serialization.
	 * @param context server ssl context
	 * @since 3.4 (added maxQuietPeriodInSeconds)
	 */
	public JdkMonitorService(InetSocketAddress localAddress, InetSocketAddress localSecureAddress,
			long staleThresholdInSeconds, SSLContext context) {
		this.localAddress = localAddress;
		this.localSecureAddress = localSecureAddress;
		this.context = context;
		this.staleThresholdInSeconds = staleThresholdInSeconds;
		this.stateAlive.set(true, 0, TimeUnit.SECONDS);
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
				LOGGER.warn("starting {} failed!", localSecureAddress);
			}
		}
	}

	/**
	 * Stop monitor service.
	 */
	public void stop() {
		if (server != null) {
			// stop with 2s delay
			server.stop(2);
		}
		if (secureServer != null) {
			// stop with 2s delay
			secureServer.stop(2);
		}
		try {
			Thread.sleep(2000);
		} catch (InterruptedException e) {
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

			boolean ready = isReady();
			if (stateReady.set(ready, DELAY_IN_SECONDS, TimeUnit.SECONDS)) {
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
				boolean ready = isReady();
				for (CoapServer server : coapServers) {
					server.stop();
				}
				if (ready) {
					stateReady.set(ready, 0, TimeUnit.SECONDS);
				}
				PersistentComponentUtil util = new PersistentComponentUtil();
				for (CoapServer server : coapServers) {
					util.addProvider(server);
				}
				int count = util.saveComponents(out, staleThresholdInSeconds);
				LOGGER.info("response: {} connections", count);
			} catch (IOException e) {
				LOGGER.warn("write response to {} failed!", exchange.getRemoteAddress(), e);
			} finally {
				long delay = stateReady.left(TimeUnit.NANOSECONDS);
				if (delay < 0) {
					stateAlive.set(false, DELAY_IN_SECONDS, TimeUnit.SECONDS);
				} else {
					stateAlive.set(false, delay, TimeUnit.NANOSECONDS);
				}
			}
		}
	}

	class AliveHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			LOGGER.info("request: {} {}", exchange.getRequestMethod(), exchange.getRequestURI());
			byte[] response;
			if (!stateAlive.get()) {
				response = "STOPPED\n".getBytes();
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
