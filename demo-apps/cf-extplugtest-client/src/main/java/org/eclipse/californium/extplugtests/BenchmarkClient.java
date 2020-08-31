/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add transmission error statistic
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util and introduce
 *                                                    a shared executor for clients.
 ******************************************************************************/

package org.eclipse.californium.extplugtests;

import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;

import java.io.File;
import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Formatter;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.californium.cli.ClientConfig;
import org.eclipse.californium.cli.ClientInitializer;
import org.eclipse.californium.cli.ConnectorConfig;
import org.eclipse.californium.cli.ConnectorConfig.AuthenticationMode;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EndpointContextTracer;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Message.OffloadMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.ResourceObserverAdapter;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.extplugtests.resources.Feed;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalKeyPairGenerator;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Simple benchmark client.
 * 
 * Starts multiple parallel clients to send CON-POST requests. Print statistic
 * with retransmissions.
 */
public class BenchmarkClient {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(BenchmarkClient.class);

	private static final Logger STATISTIC_LOGGER = LoggerFactory.getLogger("org.eclipse.californium.extplugtests.statistics");

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumBenchmark.properties");
	/**
	 * File name for reverse server network configuration. Used for reverse
	 * request including observes.
	 */
	private static final File REVERSE_SERVER_CONFIG_FILE = new File("CaliforniumReverseServer.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Benchmark Client";
	/**
	 * Header for reverse server network configuration. Used for reverse request
	 * including observes.
	 */
	private static final String REVERSE_SERVER_CONFIG_HEADER = "Californium CoAP Properties file for Reverse-Server in Client";
	/**
	 * Default maximum resource size.
	 */
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	/**
	 * Default block size.
	 */
	private static final int DEFAULT_BLOCK_SIZE = 1024;
	/**
	 * Default block size for reverse server. Used for reverse request including
	 * observes.
	 */
	private static final int DEFAULT_REVERSE_SERVER_BLOCK_SIZE = 64;
	/**
	 * Default number of clients.
	 */
	private static final String DEFAULT_CLIENTS = "5";
	/**
	 * Default number of requests.
	 */
	private static final String DEFAULT_REQUESTS = "100";

	/**
	 * NetworkConfig key for number of threads used per client. {@code 0} to use
	 * a shared thread pool.
	 * <p>
	 * Default: {@code 0}, use shared thread pool
	 * <p>
	 * Note: unfortunately the currently used synchronous socket requires at
	 * least it's own receiver thread. So the number of threads is considered to
	 * be used for the other components used by a client.
	 */
	private static final String KEY_BENCHMARK_CLIENT_THREADS = "BENCHMARK_CLIENT_THREADS";

	private static final ThreadGroup CLIENT_THREAD_GROUP = new ThreadGroup("Client"); //$NON-NLS-1$

	private static final NamedThreadFactory threadFactory = new DaemonThreadFactory("Client#", CLIENT_THREAD_GROUP);
	/**
	 * Special network configuration defaults handler.
	 */
	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.MAX_ACTIVE_PEERS, 10);
			config.setInt(Keys.PEERS_MARK_AND_SWEEP_MESSAGES, 16);
			config.setString(Keys.DEDUPLICATOR, Keys.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.setInt(Keys.DTLS_AUTO_RESUME_TIMEOUT, 0);
			config.setInt(Keys.DTLS_CONNECTION_ID_LENGTH, 0); // support it, but don't use it
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60 * 60 * 24); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 60 * 60 * 12); // 12h
			config.setInt(Keys.TCP_CONNECT_TIMEOUT, 30 * 1000); // 20s
			config.setInt(Keys.TLS_HANDSHAKE_TIMEOUT, 30 * 1000); // 20s
			config.setInt(Keys.TCP_WORKER_THREADS, 2);
			config.setInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, 1);
			config.setInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, 1);
			config.setInt(Keys.PROTOCOL_STAGE_THREAD_COUNT, 1);
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 8192);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 8192);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 0);
			config.setInt(KEY_BENCHMARK_CLIENT_THREADS, 0);
			config.setInt(ClientInitializer.KEY_DTLS_RETRANSMISSION_TIMEOUT, 2000);
		}

	};

	/**
	 * Special reverse server network configuration defaults handler. Used for
	 * reverse request including observes.
	 */
	private static NetworkConfigDefaultHandler REVERSE_DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			DEFAULTS.applyDefaults(config);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_REVERSE_SERVER_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_REVERSE_SERVER_BLOCK_SIZE);
		}
	};

	@Command(name = "BenchmarkClient", version = "(c) 2018-2020, Bosch.IO GmbH and others.",
			footer = {
					"",
					"Examples:",
					"  BenchmarkClient coap://localhost:5783/benchmark?rlen=200 \\",
					"     --clients 500 --requests 2000",
					"  (Benchmark 500 clients each sending about 2000 request",
					"   and the response should have 200 bytes payload.)",
					"",
					"  BenchmarkClient coap://localhost:5783/reverse-observe?\\",
					"     obs=25&res=feed-CON&timeout=10&rlen=400 \\",
					"     --clients 50 --requests 2 --reverse 500 --min 2000",
					"  (Reverse-observe benchmark using 50 clients each sending 2 requests",
					"   and waiting for about 500 notifies each client. The notifies are",
					"   sent as CON every 2000ms and have 400 bytes payload.",
					"   A blocksize of 64 bytes is used, as defined in",
					"   \"CaliforniumReverseServer.properties\".)",
					"",
					"Note: californium.eclipse.org doesn't support a benchmark",
					"      and will response with 5.01, NOT_IMPLEMENTED!"
			})
	private static class Config extends ClientConfig {
		@Option(names = "--clients", defaultValue = DEFAULT_CLIENTS, description = "number of clients. Default ${DEFAULT-VALUE}.")
		public int clients;

		@Option(names = "--requests", defaultValue = DEFAULT_REQUESTS, description = "number of requests. Default ${DEFAULT-VALUE}.")
		public int requests;

		@Option(names = "--no-stop", negatable = true, description = "stop on errors. Default ${DEFAULT-VALUE}.")
		public boolean stop = true;

		@Option(names = "--hono", description = "send hono-requests.")
		public Boolean hono;

		@Option(names = "--interval", description = "interval in milliseconds for request per client.")
		public Integer interval;

		@Option(names = "--handshakes-full", description = "number of requests to force a full-handshake.")
		public Integer handshakes;

		@Option(names = "--handshakes-close", description = "number of requests to close a connection.")
		public Integer closes;

		@Option(names = "--handshakes-burst", description = "number of closes or full-handshakes in sequence.")
		public Integer bursts;

		@ArgGroup(exclusive = false)
		Reverse reverse;

		static class Reverse {

			@Option(names = "--reverse", required = true, description = "number of reverse responses.")
			public Integer responses;

			@Option(names = { "--min", "--mininterval" }, required = false, description = "minimal interval of reverse responses.")
			public Integer min;

			@Option(names = { "--max", "--maxinterval" }, required = false, description = "maximal interval of reverse responses.")
			public Integer max;

			void defaults() {
				if (max == null && min == null) {
					min = Feed.DEFAULT_FEED_INTERVAL_IN_MILLIS;
					max = min;
				} else if (max == null) {
					max = min;
				} else if (min == null) {
					min = max;
				} else {
					if (max < min) {
						Integer temp = max;
						max = min;
						min = temp;
					}
				}
			}
		}

		public void defaults() {
			super.defaults();
			if (reverse != null) {
				reverse.defaults();
			}
			if (hono == null) {
				String honoMode = StringUtil.getConfiguration("COAP_HONO");
				hono = (honoMode != null && Boolean.parseBoolean(honoMode));
			}
			if (interval == null) {
				Long value = StringUtil.getConfigurationLong("COAP_REQUEST_INTERVAL");
				interval = value != null ? value.intValue() : 0;
			}
			if (handshakes == null) {
				Long value = StringUtil.getConfigurationLong("COAPS_HANDSHAKES_FULL");
				handshakes = value != null ? value.intValue() : 0;
			}
			if (closes == null) {
				Long value = StringUtil.getConfigurationLong("COAPS_HANDSHAKES_CLOSE");
				closes = value != null ? value.intValue() : 0;
			}
			if (bursts == null) {
				Long value = StringUtil.getConfigurationLong("COAPS_HANDSHAKES_BURST");
				bursts = value != null ? value.intValue() : 0;
			}
		}
	}

	private static final Config config = new Config();

	/**
	 * Benchmark timeout. If no messages are exchanged within this timeout, the
	 * benchmark is stopped.
	 */
	private static final long DEFAULT_TIMEOUT_SECONDS = TimeUnit.MILLISECONDS.toSeconds(10000);
	private static final long DEFAULT_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(DEFAULT_TIMEOUT_SECONDS);
	/**
	 * Atomic down-counter for overall requests.
	 */
	private static final AtomicLong overallRequestsDownCounter = new AtomicLong();
	/**
	 * Atomic down-counter for overall responses.
	 */
	private static final AtomicLong overallResponsesDownCounter = new AtomicLong();
	/**
	 * Done indicator for overall requests.
	 */
	private static final CountDownLatch overallRequestsDone = new CountDownLatch(1);
	/**
	 * Overall reverse responses down-counter.
	 */
	private static CountDownLatch overallReverseResponsesDownCounter;
	/**
	 * Client counter.
	 */
	private static final AtomicInteger clientCounter = new AtomicInteger();
	/**
	 * Client counter.
	 */
	private static final AtomicInteger connectDownCounter = new AtomicInteger();
	/**
	 * Overall retransmission counter.
	 */
	private static final AtomicLong retransmissionCounter = new AtomicLong();
	/**
	 * Message observer to detect retransmissions.
	 */
	private static final MessageObserver retransmissionDetector = new MessageObserverAdapter() {

		@Override
		public void onRetransmission() {
			retransmissionCounter.incrementAndGet();
		}
	};

	/**
	 * Overall transmission error counter.
	 */
	private static final AtomicLong transmissionErrorCounter = new AtomicLong();

	/**
	 * Overall notifications timeout counter.
	 */
	private static final AtomicLong notifiesCompleteTimeouts = new AtomicLong();

	/**
	 * 
	 */
	private static abstract class MyResourceObserverAdapter extends ResourceObserverAdapter {

		@Override
		public void addedObserveRelation(ObserveRelation relation) {
			overallObservationRegistrationCounter.incrementAndGet();
			synchronized (overallObserverCounter) {
				overallObserverCounter.incrementAndGet();
				overallObserverCounter.notify();
			}
		}

		@Override
		public void removedObserveRelation(ObserveRelation relation) {
			synchronized (overallObserverCounter) {
				overallObserverCounter.decrementAndGet();
				overallObserverCounter.notify();
			}
		}

	};

	private class FeedObserver extends MyResourceObserverAdapter {

		@Override
		public void addedObserveRelation(ObserveRelation relation) {
			super.addedObserveRelation(relation);
			observerCounter.incrementAndGet();
		}

		@Override
		public void removedObserveRelation(ObserveRelation relation) {
			super.removedObserveRelation(relation);
			int counter = observerCounter.decrementAndGet();
			if (counter == 0 && overallResponsesDownCounter.get() == 0
					&& overallReverseResponsesDownCounter.getCount() == 0) {
				stop();
			}
		}
	}

	/**
	 * Current overall observations counter. Incremented by every observation
	 * registration and decremented when relation is canceled.
	 */
	private static final AtomicInteger overallObserverCounter = new AtomicInteger();
	/**
	 * Overall observation registration counter. Only incremented by observation
	 * registrations.
	 */
	private static final AtomicInteger overallObservationRegistrationCounter = new AtomicInteger();
	/**
	 * Overall service unavailable responses.
	 */
	private static final AtomicInteger overallServiceUnavailable = new AtomicInteger();
	/**
	 * Overall hono &c&c cmds.
	 */
	private static final AtomicInteger overallHonoCmds = new AtomicInteger();
	/**
	 * Full handshake bursts counter.
	 */
	private static final AtomicLong handshakeFullBursts = new AtomicLong();
	/**
	 * Close handshake bursts counter.
	 */
	private static final AtomicLong handshakeCloseBursts = new AtomicLong();
	/**
	 * Offload messages.
	 */
	private static boolean offload;

	private final URI uri;
	/**
	 * Shutdown executor.
	 */
	private final boolean shutdown;
	/**
	 * Executor service for this client.
	 */
	private final ScheduledExecutorService executorService;
	/**
	 * Client to be used for benchmark.
	 */
	private final CoapClient client;
	/**
	 * Server for notifies.
	 */
	private final CoapServer server;
	/**
	 * Endpoint to exchange messages.
	 */
	private final Endpoint endpoint;
	/**
	 * Per client request counter.
	 */
	private final AtomicInteger requestsCounter = new AtomicInteger();
	/**
	 * Per client observer counter.
	 */
	private final AtomicInteger observerCounter = new AtomicInteger();
	/**
	 * Indicate that client has stopped.
	 * 
	 * @see #stop()
	 */
	private final AtomicBoolean stop = new AtomicBoolean();

	private final FeedObserver feedObserver = new FeedObserver();

	private final String id;

	private final boolean secure;

	private final DTLSConnector dtlsConnector;

	private final long ackTimeout;

	private Request prepareRequest(CoapClient client, long c) {
		if (overallRequestsDownCounter.decrementAndGet() < 0) {
			return null;
		}
		Request request;
		int accept = TEXT_PLAIN;
		byte[] payload = config.payloadBytes;
		if (config.hono) {
			request = secure ? Request.newPost() : Request.newPut();
			if (payload == null) {
				accept = APPLICATION_JSON;
				payload = "{\"temp\": %1$d }".getBytes();
			}
		} else {
			request = Request.newPost();
		}
		if (config.contentType != null) {
			accept = config.contentType.contentType;
		}
		request.getOptions().setAccept(accept);
		request.getOptions().setContentFormat(accept);
		if (config.con != null) {
			request.setConfirmable(config.con);
		}
		if (payload != null) {
			if (config.payloadFormat) {
				String text = new String(payload, CoAP.UTF8_CHARSET);
				text = String.format(text, c, System.currentTimeMillis() / 1000);
				request.setPayload(text);
			} else {
				request.setPayload(payload);
			}
		}
		if (config.proxy != null) {
			request.setDestinationContext(new AddressEndpointContext(config.proxy.destination));
			if (config.proxy.scheme != null) {
				request.getOptions().setProxyScheme(config.proxy.scheme);
			}
		}
		request.setURI(client.getURI());
		return request;
	}

	private class TestHandler implements CoapHandler {

		private final Request post;

		private TestHandler(final Request post) {
			this.post = post;
		}

		@Override
		public void onLoad(CoapResponse response) {
			if (response.isSuccess()) {
				if (!stop.get()) {
					String cmd = null;
					List<String> queries = response.getOptions().getLocationQuery();
					for (String query : queries) {
						if (query.startsWith("hono-command=")) {
							cmd = query.substring("hono-command=".length());
							break;
						}
					}
					if (cmd != null) {
						overallHonoCmds.incrementAndGet();
						List<String> location = response.getOptions().getLocationPath();
						if (location.size() == 2 || location.size() == 4) {
							LOGGER.debug("{}: cmd {}: {}", id, cmd, location);
							final Request cmdResponse = post.getCode() == Code.PUT ? Request.newPut()
									: Request.newPost();
							try {
								URI responseUri = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null,
										"hono-cmd-status=200", null);
								cmdResponse.setURI(responseUri);
								cmdResponse.getOptions().getUriPath().addAll(location);
								cmdResponse.setPayload("OK");
								client.advanced(new CoapHandler() {

									@Override
									public void onLoad(CoapResponse response) {
									}

									@Override
									public void onError() {
									}
								}, cmdResponse);
							} catch (URISyntaxException e) {
								LOGGER.warn("{}: C&C {} response failed!", id, cmd, e);
							}
						} else {
							LOGGER.debug("{}: cmd {}", id, cmd);
						}
					}
					next(config.interval, response.advanced().isConfirmable() ? -ackTimeout * 2 : 0, true, true);
				}
				long c = overallResponsesDownCounter.get();
				LOGGER.trace("{}: Received response: {} {}", id, response.advanced(), c);
			} else if (response.getCode() == ResponseCode.SERVICE_UNAVAILABLE) {
				long delay = TimeUnit.SECONDS.toMillis(response.getOptions().getMaxAge());
				int unavailable = overallServiceUnavailable.incrementAndGet();
				long c = overallResponsesDownCounter.get();
				LOGGER.debug("{}: {}, Received error response: {} {}", id, unavailable, response.advanced(), c);
				if (!stop.get()) {
					next(delay < 1000L ? 1000L : delay, -ackTimeout * 2, true, true);
				}
			} else if (!config.stop) {
				long c = requestsCounter.get();
				transmissionErrorCounter.incrementAndGet();
				LOGGER.warn("{}: Error after {} requests. {} - {}", id, c, response.advanced().getCode(),
						response.advanced().getPayloadString());
				if (!stop.get()) {
					next(1000, -ackTimeout * 2, true, true);
				}
			} else {
				long c = requestsCounter.get();
				LOGGER.warn("{}: Received error response: {} {} ({} successful)", id, endpoint.getUri(), response.advanced(), c);
				checkReady(true, true);
				stop();
			}
			if (offload) {
				post.offload(OffloadMode.FULL);
				response.advanced().offload(OffloadMode.PAYLOAD);
			}
		}

		@Override
		public void onError() {
			if (!stop.get()) {
				long c = requestsCounter.get();
				String msg = "";
				if (post.getSendError() != null) {
					msg = post.getSendError().getMessage();
				} else if (post.isTimedOut()) {
					msg = "timeout";
				} else if (post.isRejected()) {
					msg = "rejected";
				}
				if (!config.stop) {
					transmissionErrorCounter.incrementAndGet();
					LOGGER.info("{}: Error after {} requests. {}", id, c, msg);
					next(1000, secure ? 1000 : 0, requestsCounter.get() > 0, false);
				} else {
					LOGGER.error("{}: failed after {} requests! {}", id, c, msg);
					checkReady(true, false);
					stop();
				}
			}
		}

		public void next(long delayMillis, long forceHandshake, boolean connected, boolean response) {
			final long c = checkOverallRequests(connected, response);
			if (c > 0) {
				boolean close = false;
				boolean full = false;
				boolean force = forceHandshake > 0;
				if (!force) {
					close = (config.closes != 0 && (c % config.closes == 0));
					full = (config.handshakes != 0 && (c % config.handshakes == 0));
					if (config.bursts > 0) {
						if (close) {
							handshakeCloseBursts.compareAndSet(0, config.bursts);
						} else {
							close = countDown(handshakeCloseBursts) > 0;
						}
						if (full) {
							handshakeFullBursts.compareAndSet(0, config.bursts);
						} else {
							full = countDown(handshakeFullBursts) > 0;
						}
					}
				}
				final boolean reconnect = dtlsConnector != null && (close || full || force);
				final Request request = prepareRequest(client, c);
				if (request == null) {
					return;
				}
				request.addMessageObserver(retransmissionDetector);
				if (reconnect) {
					EndpointContext destinationContext = request.getDestinationContext();
					client.setDestinationContext(null);
					if (forceHandshake < 0) {
						forceHandshake = -forceHandshake;
					}
					if (delayMillis < forceHandshake) {
						delayMillis = forceHandshake;
					}
					if (close) {
						final InetSocketAddress destination = destinationContext.getPeerAddress();
						final long delay = delayMillis;
						executorService.schedule(new Runnable() {

							@Override
							public void run() {
								dtlsConnector.close(destination);
								LOGGER.trace("{}: close {} {}", id, c, delay);
							}
						}, delayMillis, TimeUnit.MILLISECONDS);
						if (delayMillis < 500) {
							delayMillis = 1000;
						} else {
							delayMillis *= 2;
						}
					} else {
						destinationContext = MapBasedEndpointContext.addEntries(destinationContext,
								DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE_FULL);
						request.setDestinationContext(destinationContext);
					}
				}
				final long delay = delayMillis;
				if (delayMillis > 0) {
					executorService.schedule(new Runnable() {
						@Override
						public void run() {
							client.advanced(new TestHandler(request), request);
							LOGGER.trace("{}: sent request {} {} {}", id, c, delay, reconnect);
						}
					}, delayMillis, TimeUnit.MILLISECONDS);
				} else {
					client.advanced(new TestHandler(request), request);
					LOGGER.trace("{}: sent request {} {} {}", id, c, delay, reconnect);
				}
			}
		}
	}

	/**
	 * Create client.
	 * 
	 * @param index index of client. used for thread names.
	 * @param intervalMin minimum notifies interval in milliseconds
	 * @param intervalMax maximum notifies interval in milliseconds
	 * @param uri destination URI
	 * @param endpoint local endpoint to exchange messages
	 * @param executor
	 * @param secondaryExecutor intended to be used for rare executing timers (e.g. cleanup tasks). 
	 */
	public BenchmarkClient(int index, Config.Reverse reverse, URI uri, Endpoint endpoint,
			ScheduledExecutorService executor, ScheduledThreadPoolExecutor secondaryExecutor) {
		this.secure = CoAP.isSecureScheme(uri.getScheme());
		Connector connector = ((CoapEndpoint)endpoint).getConnector();
		this.dtlsConnector = secure && connector instanceof DTLSConnector ? (DTLSConnector) connector : null;
		this.id = "client-" + index;
		this.uri = uri;
		int maxResourceSize = endpoint.getConfig().getInt(Keys.MAX_RESOURCE_BODY_SIZE);
		if (executor == null) {
			int threads = endpoint.getConfig().getInt(KEY_BENCHMARK_CLIENT_THREADS);
			this.executorService = ExecutorsUtil.newScheduledThreadPool(threads, threadFactory);
			this.shutdown = true;
		} else {
			this.executorService = executor;
			this.shutdown = false;
		}
		NetworkConfig config = endpoint.getConfig();
		this.ackTimeout =  config.getLong(Keys.ACK_TIMEOUT);
		endpoint.addInterceptor(new MessageTracer());
		endpoint.setExecutors(this.executorService, secondaryExecutor);
		this.client = new CoapClient(uri);
		this.server = new CoapServer(config);
		if (reverse != null) {
			Feed feed = new Feed(CoAP.Type.NON, index, maxResourceSize, reverse.min, reverse.max, this.executorService,
					overallReverseResponsesDownCounter, notifiesCompleteTimeouts);
			feed.addObserver(feedObserver);
			this.server.add(feed);
			feed = new Feed(CoAP.Type.CON, index, maxResourceSize, reverse.min, reverse.max, this.executorService,
					overallReverseResponsesDownCounter, notifiesCompleteTimeouts);
			feed.addObserver(feedObserver);
			this.server.add(feed);
		}
		this.server.setExecutors(this.executorService, secondaryExecutor, true);
		this.client.setExecutors(this.executorService, secondaryExecutor, true);
		this.endpoint = endpoint;
	}

	/**
	 * Start client. Start endpoint. Must be called before
	 * {@link #startBenchmark()}.
	 */
	public void start() {
		client.setEndpoint(endpoint);
		server.addEndpoint(endpoint);
		server.start();
	}

	/**
	 * Test request.
	 * 
	 * @return {@code true} on success, {@code false} on failure.
	 */
	public boolean test() {
		final Request request = prepareRequest(client, 12);
		try {
			request.addMessageObserver(new EndpointContextTracer() {
				private final AtomicInteger counter = new AtomicInteger();

				@Override
				public void onReadyToSend() {
					int count = counter.getAndIncrement();
					if (count == 0) {
						LOGGER.info("Request:{}{}", StringUtil.lineSeparator(), Utils.prettyPrint(request));
					} else {
						LOGGER.info("Request: {} retransmissions{}{}", count, StringUtil.lineSeparator(), Utils.prettyPrint(request));
					}
				}

				@Override
				public void onConnecting() {
					LOGGER.info(">>> CONNECTING <<<");
				}

				@Override
				public void onDtlsRetransmission(int flight) {
					LOGGER.info(">>> DTLS retransmission, flight  {}", flight);
				}

				@Override
				protected void onContextChanged(EndpointContext endpointContext) {
					LOGGER.info("{}", Utils.prettyPrint(endpointContext));
				}

				@Override
				public void onAcknowledgement() {
					LOGGER.info(">>> ACK <<<");
				}

				@Override
				public void onTimeout() {
					LOGGER.info(">>> TIMEOUT <<<");
				}
			});

			CoapResponse response = client.advanced(request);
			if (response != null) {
				if (response.isSuccess()) {
					if (LOGGER.isInfoEnabled()) {
						LOGGER.info("Received response:{}{}", StringUtil.lineSeparator(), Utils.prettyPrint(response));
					}
					clientCounter.incrementAndGet();
					checkReady(true, true);
					return true;
				} else {
					LOGGER.warn("Received error response: {} - {}", response.getCode(), response.getResponseText());
				}
			} else {
				LOGGER.warn("Received no response!");
			}
		} catch (Exception ex) {
			LOGGER.warn("Test failed!", ex);
		}
		return false;
	}

	/**
	 * Start benchmark.
	 * 
	 * Prepare first request and follow-up request on response handler calls.
	 * Must be called after {@link #start()}
	 */
	public void startBenchmark() {
		long c = checkOverallRequests(false, false);
		if (c > 0) {
			if (requestsCounter.get() == 0) {
				clientCounter.incrementAndGet();
			}
			Request request = prepareRequest(client, c);
			if (request != null) {
				request.addMessageObserver(retransmissionDetector);
				client.advanced(new TestHandler(request), request);
			}
		}
	}

	public boolean checkReady(boolean connected, boolean response) {
		return checkOverallRequests(connected, response) == 0;
	}

	public long checkOverallRequests(boolean connected, boolean response) {
		boolean allConnected = connectDownCounter.get() <= 0;
		if (connected) {
			if (requestsCounter.get() == 0) {
				allConnected = connectDownCounter.decrementAndGet() <= 0;
			}
			if (response) {
				requestsCounter.getAndIncrement();
			}
		}
		long c = response ? countDown(overallResponsesDownCounter) : overallResponsesDownCounter.get();
		if (c == 0 && allConnected) {
			overallRequestsDone.countDown();
			if (overallReverseResponsesDownCounter.getCount() == 0) {
				stop();
			}
		}
		return c;
	}

	/**
	 * Stop benchmark.
	 */
	public void stop() {
		if (stop.compareAndSet(false, true)) {
			clientCounter.decrementAndGet();
		}
	}

	/**
	 * Destroy client.
	 * 
	 * @return number of requests processed by this client.
	 */
	public int destroy() {
		stop();
		endpoint.stop();
		server.stop();
		if (shutdown) {
			executorService.shutdownNow();
		}
		client.shutdown();
		server.destroy();
		endpoint.destroy();
		return requestsCounter.get();
	}

	public static long countDown(AtomicLong downCounter) {
		long c = downCounter.get();
		while (c > 0) {
			if (downCounter.compareAndSet(c, c - 1)) {
				--c;
				break;
			}
			c = downCounter.get();
		}
		return c;
	}

	public static void main(String[] args) throws InterruptedException, IOException {

		startManagamentStatistic();
		config.networkConfigHeader = CONFIG_HEADER;
		config.networkConfigDefaultHandler = DEFAULTS;
		config.networkConfigFile = CONFIG_FILE;
		ClientInitializer.init(args, config, false);

		if (config.helpRequested) {
			System.exit(0);
		}

		// random part of PSK identity
		final SecureRandom random = new SecureRandom();
		final byte[] id = new byte[8];

		final int clients = config.clients;
		int requests = config.requests;
		int reverseResponses = 0;

		if (config.reverse != null) {
			config.networkConfig = NetworkConfig.createWithFile(REVERSE_SERVER_CONFIG_FILE,
					REVERSE_SERVER_CONFIG_HEADER, REVERSE_DEFAULTS);
			reverseResponses = config.reverse.responses;
		}

		offload = config.networkConfig.getBoolean(Keys.USE_MESSAGE_OFFLOADING);

		URI tempUri;
		try {
			tempUri = new URI(config.uri);
		} catch (URISyntaxException e) {
			tempUri = null;
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
		final URI uri = tempUri;

		int overallRequests = (requests * clients);
		int overallReverseResponses = (reverseResponses * clients);
		if (overallRequests < 0) {
			// overflow
			overallRequests = Integer.MAX_VALUE;
		}
		if (overallReverseResponses < 0) {
			// overflow
			overallReverseResponses = Integer.MAX_VALUE;
		}
		overallRequestsDownCounter.set(overallRequests);
		overallResponsesDownCounter.set(overallRequests);
		overallReverseResponsesDownCounter = new CountDownLatch(overallReverseResponses);

		final List<BenchmarkClient> clientList = Collections.synchronizedList(new ArrayList<BenchmarkClient>(clients));
		ScheduledExecutorService executor = ExecutorsUtil
				.newScheduledThreadPool(Runtime.getRuntime().availableProcessors(), new DaemonThreadFactory("Aux#"));

		final ScheduledExecutorService connectorExecutor = config.networkConfig.getInt(KEY_BENCHMARK_CLIENT_THREADS) == 0 ? executor : null;
		final boolean secure = CoAP.isSecureScheme(uri.getScheme());

		final ScheduledThreadPoolExecutor secondaryExecutor = new ScheduledThreadPoolExecutor(2,
				new DaemonThreadFactory("Aux(secondary)#"));

		String proxyMessage = "";
		if (config.proxy != null) {
			proxyMessage = "via proxy " + config.proxy + " ";
		}
		System.out.format("Create %d %s%sbenchmark clients, expect to send %d requests overall %sto %s%n", clients,
				!config.stop ? "none-stop " : "", secure ? "secure " : "", overallRequests, proxyMessage, uri);

		if (config.reverse != null && overallReverseResponses > 0) {
			if (config.reverse.min == config.reverse.max) {
				System.out.format("Expect %d notifies, interval %d [ms]%n", overallReverseResponses,
						config.reverse.min);
			} else {
				System.out.format("Expect %d notifies, interval %d ... %d [ms]%n", overallReverseResponses,
						config.reverse.min, config.reverse.max);
			}
		}
		connectDownCounter.set(clients);
		final boolean psk = config.authenticationModes.contains(AuthenticationMode.PSK)
				|| config.authenticationModes.contains(AuthenticationMode.ECDHE_PSK);
		final boolean rpk = config.authenticationModes.contains(AuthenticationMode.RPK);
		long startupNanos = System.nanoTime();
		final AuthenticationMode authentication = config.authenticationModes.isEmpty() ? null : config.authenticationModes.get(0);
		final CountDownLatch start = new CountDownLatch(clients);
		if (secure && authentication != null) {
			switch(authentication) {
			case NONE:
				System.out.println("No authentication.");
				break;
			case PSK:
				System.out.println("Use PSK.");
				break;
			case RPK:
				System.out.println("Use RPK.");
				break;
			case X509:
				System.out.println("Use X509.");
				break;
			case ECDHE_PSK:
				System.out.println("Use PSK/ECDHE.");
				break;
			}
		}
		final ThreadLocalKeyPairGenerator keyPairGenerator = rpk ? createKeyPairGenerator() : null;
		// Create & start clients
		final AtomicBoolean errors = new AtomicBoolean();
		final HealthStatisticLogger health = new HealthStatisticLogger(uri.getScheme(), !CoAP.isTcpScheme(uri.getScheme()));
		final NetStatLogger netstat = new NetStatLogger("udp");
		final int pskOffset = config.pskIndex != null ? config.pskIndex : 0;
		for (int index = 0; index < clients; ++index) {
			final int currentIndex = index;
			final String identity;
			final byte[] secret;
			if (secure && psk) {
				if (config.pskStore != null) {
					int pskIndex = (pskOffset + index) % config.pskStore.size();
					identity = config.pskStore.getIdentity(pskIndex);
					secret = config.pskStore.getSecrets(pskIndex);
				} else if (index == 0){
					identity = config.identity;
					secret = config.secretKey;
				} else {
					random.nextBytes(id);
					identity= ConnectorConfig.PSK_IDENTITY_PREFIX + StringUtil.byteArray2Hex(id);
					secret = config.secretKey;
				}
			} else {
				identity = null;
				secret = null;
			}
			Runnable run = new Runnable() {

				@Override
				public void run() {
					if (errors.get()) {
						return;
					}
					CoapEndpoint.Builder endpointBuilder = new CoapEndpoint.Builder();
					endpointBuilder.setNetworkConfig(config.networkConfig);
					ClientConfig connectionConfig = config;
					if (secure) {
						if (rpk) {
							if (keyPairGenerator != null) {
								try {
									KeyPairGenerator generator = keyPairGenerator.current();
									generator.initialize(new ECGenParameterSpec("secp256r1"), RandomManager.currentSecureRandom());
									KeyPair keyPair = generator.generateKeyPair();
									connectionConfig = connectionConfig.create(keyPair.getPrivate(), keyPair.getPublic());
								} catch (GeneralSecurityException ex) {
									if (!errors.getAndSet(true)) {
										ex.printStackTrace();
										System.out.format("Failed after %d clients, exit Benchmark.%n",
												(clients - start.getCount()));
										System.exit(-1);
									}
								}
							}
						}
						if (psk) {
							connectionConfig = connectionConfig.create(identity, secret);
						}
					}
					CoapEndpoint coapEndpoint = ClientInitializer.createEndpoint(connectionConfig, connectorExecutor);
					if (health.isEnabled()) {
						coapEndpoint.addPostProcessInterceptor(health);
					}
					BenchmarkClient client = new BenchmarkClient(currentIndex, config.reverse, uri,
							coapEndpoint, connectorExecutor, secondaryExecutor);
					clientList.add(client);
					try {
						client.start();
						start.countDown();
						if (currentIndex == 0) {
							// first client, so test request
							if (client.test()) {
								System.out.println("Benchmark clients, first request successful.");
							} else {
								System.out.format("Request %s POST failed, exit Benchmark.%n", uri);
								System.exit(-1);
							}
							// ensure to use ephemeral port for other clients
							config.localPort = null;
						} 
					} catch (RuntimeException e) {
						if (!errors.getAndSet(true)) {
							e.printStackTrace();
							System.out.format("Failed after %d clients, exit Benchmark.%n",
									(clients - start.getCount()));
							System.exit(-1);
						}
					}
				}
			};
			if (index == 0) {
				// first client, so test request
				if (identity != null) {
					// first client, so test request
					if (secret == null) {
						System.out.println("ID: " + identity);
					} else {
						System.out.println("ID: " + identity + ", " + new String(secret));
					}
				}
				run.run();
			} else if (!errors.get()) {
				startupNanos = System.nanoTime();
				executor.execute(run);
			}
		}
		start.await();
		startupNanos = System.nanoTime() - startupNanos;
		if (clients == 1) {
			System.out.format("Benchmark client created. %s%n", formatTime(startupNanos));
		} else {
			System.out.format("Benchmark clients created. %s%s%n", formatTime(startupNanos),
					formatPerSecond("clients", clients - 1, startupNanos));
		}

		// Start Test
		boolean stale = false;
		long requestNanos = System.nanoTime();
		long reverseResponseNanos = requestNanos;
		long lastRequestsCountDown = overallResponsesDownCounter.get();
		long lastRetransmissions = retransmissionCounter.get();
		long lastTransmissionErrrors = transmissionErrorCounter.get();
		int lastUnavailable = overallServiceUnavailable.get();
		int lastHonoCmds = overallHonoCmds.get();

		for (int index = clients - 1; index >= 0; --index) {
			BenchmarkClient client = clientList.get(index);
			client.startBenchmark();
		}
		System.out.println("Benchmark started.");

		// Wait with timeout or all requests send.
		while (!overallRequestsDone.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
			long currentRequestsCountDown = overallResponsesDownCounter.get();
			int numberOfClients = clientCounter.get();
			int connectsPending = connectDownCounter.get();
			long requestDifference = (lastRequestsCountDown - currentRequestsCountDown);
			long currentOverallSentRequests = overallRequests - currentRequestsCountDown;
			if ((requestDifference == 0 && currentRequestsCountDown < overallRequests)
					|| (numberOfClients == 0)) {
				// no new requests, clients are stale, or no clients left
				// adjust start time with timeout
				requestNanos += DEFAULT_TIMEOUT_NANOS;
				reverseResponseNanos = requestNanos;
				stale = true;
				System.out.format("%d requests, stale (%d clients, %d pending)%n", currentOverallSentRequests, numberOfClients, connectsPending);
				break;
			}
			long retransmissions = retransmissionCounter.get();
			long retransmissionsDifference = retransmissions - lastRetransmissions;
			long transmissionErrors = transmissionErrorCounter.get();
			long transmissionErrorsDifference = transmissionErrors - lastTransmissionErrrors;
			int unavailable = overallServiceUnavailable.get();
			int unavailableDifference = unavailable - lastUnavailable;

			int honoCmds = overallHonoCmds.get();
			int honoCmdsDifference = honoCmds - lastHonoCmds;

			lastRequestsCountDown = currentRequestsCountDown;
			lastRetransmissions = retransmissions;
			lastTransmissionErrrors = transmissionErrors;
			lastUnavailable = unavailable;
			lastHonoCmds = honoCmds;

			StringBuilder line = new StringBuilder();
			line.append(String.format("%d requests (%d reqs/s", currentOverallSentRequests,
					roundDiv(requestDifference, DEFAULT_TIMEOUT_SECONDS)));
			line.append(", ").append(formatRetransmissions(retransmissionsDifference, requestDifference));
			line.append(", ").append(formatTransmissionErrors(transmissionErrorsDifference, requestDifference));
			if (unavailable > 0) {
				line.append(", ").append(formatUnavailable(unavailableDifference, requestDifference));
			}
			if (honoCmds > 0) {
				line.append(", ").append(formatHonoCmds(honoCmdsDifference, requestDifference));
			}
			line.append(String.format(", %d clients", numberOfClients));
			if (connectsPending > 0) {
				line.append(String.format(", %d pending", connectsPending));
			}
			line.append(")");
			System.out.println(line);
		}
		long overallSentRequests = overallRequests - overallResponsesDownCounter.get();
		requestNanos = System.nanoTime() - requestNanos;

		boolean observe = false;
		long lastReverseResponsesCountDown = overallReverseResponsesDownCounter.getCount();
		if (config.reverse != null && lastReverseResponsesCountDown > 0) {
			System.out.println("Requests send.");
			long lastChangeNanoRealtime = ClockUtil.nanoRealtime();
			while (!overallReverseResponsesDownCounter.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
				long currentReverseResponsesCountDown = overallReverseResponsesDownCounter.getCount();
				int numberOfClients = clientCounter.get();
				int observers = overallObserverCounter.get();
				long reverseResponsesDifference = (lastReverseResponsesCountDown - currentReverseResponsesCountDown);
				long currentOverallReverseResponses = overallReverseResponses - currentReverseResponsesCountDown;
				if (overallObservationRegistrationCounter.get() > 0) {
					observe = true;
				}
				long time = 0;
				if (currentReverseResponsesCountDown < overallReverseResponses) {
					if (reverseResponsesDifference == 0) {
						time = ClockUtil.nanoRealtime() - lastChangeNanoRealtime;
					} else {
						lastChangeNanoRealtime = ClockUtil.nanoRealtime();
					}
				} else {
					// wait extra DEFAULT_TIMEOUT_NANOS for start of reverse responses.
					time = ClockUtil.nanoRealtime() - lastChangeNanoRealtime - DEFAULT_TIMEOUT_NANOS;
				}
				if ((config.reverse.max < TimeUnit.NANOSECONDS.toMillis(time - DEFAULT_TIMEOUT_NANOS)) || (numberOfClients == 0)) {
					// no new notifies for interval max, clients are stale, or no clients left
					// adjust start time with timeout
					reverseResponseNanos += time;
					stale = true;
					if (observe) {
						System.out.format("%d notifies, stale (%d clients, %d observes)%n",
								currentOverallReverseResponses, numberOfClients, observers);
					} else {
						System.out.format("%d reverse-responses, stale (%d clients)%n", currentOverallReverseResponses,
								numberOfClients);
					}
					break;
				}
				lastReverseResponsesCountDown = currentReverseResponsesCountDown;
				if (observe) {
					System.out.format("%d notifies (%d notifies/s, %d clients, %d observes)%n",
							currentOverallReverseResponses,
							roundDiv(reverseResponsesDifference, DEFAULT_TIMEOUT_SECONDS),
							numberOfClients, observers);
				} else {
					System.out.format("%d reverse-responses (%d reverse-responses/s, %d clients)%n",
							currentOverallReverseResponses,
							roundDiv(reverseResponsesDifference, DEFAULT_TIMEOUT_SECONDS),
							numberOfClients);
				}
			}
		}
		long overallSentReverseResponses = overallReverseResponses - overallReverseResponsesDownCounter.getCount();
		reverseResponseNanos = System.nanoTime() - reverseResponseNanos;

		System.out.format("%d benchmark clients %s.%n", clients, stale ? "stopped" : "finished");
		Logger statisticsLogger = printManagamentStatistic(args, reverseResponseNanos);

		// stop and collect per client requests
		final int statistic[] = new int[clients];
		final CountDownLatch stop = new CountDownLatch(clients);
		for (int index = 0; index < clients; ++index) {
			final int currentIndex = index;
			Runnable run = new Runnable() {

				@Override
				public void run() {
					BenchmarkClient client = clientList.get(currentIndex);
					int requests = client.destroy();
					synchronized (statistic) {
						statistic[currentIndex] = requests;
					}
					stop.countDown();
				}
			};
			executor.execute(run);
		}
		stop.await();
		Thread.sleep(1000);
		executor.shutdown();
		statisticsLogger.info("{} requests sent, {} expected", overallSentRequests, overallRequests);
		statisticsLogger.info("{} requests in {} ms{}", overallSentRequests, TimeUnit.NANOSECONDS.toMillis(requestNanos),
				formatPerSecond("reqs", overallSentRequests, requestNanos));
		if (overallReverseResponses > 0) {
			if (observe) {
				statisticsLogger.info("{} notifies sent, {} expected, {} observe request", overallSentReverseResponses,
						overallReverseResponses, overallObservationRegistrationCounter.get());
				statisticsLogger.info("{} notifies in {} ms{}", overallSentReverseResponses,
						TimeUnit.NANOSECONDS.toMillis(reverseResponseNanos),
						formatPerSecond("notifies", overallSentReverseResponses, reverseResponseNanos));
				statisticsLogger.info("{} notifies could not be completed", notifiesCompleteTimeouts.get());
			} else {
				statisticsLogger.info("{} reverse-responses sent, {} expected", overallSentReverseResponses,
						overallReverseResponses);
				statisticsLogger.info("{} reverse-responses in {} ms{}", overallSentReverseResponses,
						TimeUnit.NANOSECONDS.toMillis(reverseResponseNanos),
						formatPerSecond("reverse-responses", overallSentReverseResponses, reverseResponseNanos));
			}
		}
		long retransmissions = retransmissionCounter.get();
		if (retransmissions > 0) {
			statisticsLogger.info("{}", formatRetransmissions(retransmissions, overallSentRequests));
		}
		long transmissionErrors = transmissionErrorCounter.get();
		if (transmissionErrors > 0) {
			statisticsLogger.info("{}", formatTransmissionErrors(transmissionErrors, overallSentRequests));
		}
		if (overallSentRequests < overallRequests) {
			statisticsLogger.info("Stale at {} messages ({}%)", overallSentRequests,
					(overallSentRequests * 100L) / overallRequests);
		}
		int unavailables = overallServiceUnavailable.get();
		if (unavailables > 0) {
			System.out.println(formatUnavailable(unavailables, overallSentRequests));
			long successfullRequest = overallSentRequests - unavailables;
			System.out.format("%d successful requests in %dms%s%n", successfullRequest,
					TimeUnit.NANOSECONDS.toMillis(requestNanos),
					formatPerSecond("reqs", successfullRequest, requestNanos));
		}

		health.dump();
		netstat.dump();
		if (1 < clients) {
			synchronized (statistic) {
				Arrays.sort(statistic);
			}
			int grouped = 10;
			int last = 0;
			if (overallRequests > 500000) {
				grouped = overallRequests / 50000;
			}
			for (int index = 1; index < clients; ++index) {
				if ((statistic[index] / grouped) > (statistic[last] / grouped)) {
					System.out.println(formatClientRequests(statistic, index, last));
					last = index;
				}
			}
			System.out.println(formatClientRequests(statistic, clients, last));
		}
	}

	private static ThreadLocalKeyPairGenerator createKeyPairGenerator() {
		try {
			ThreadLocalKeyPairGenerator keyPairGenerator = new ThreadLocalKeyPairGenerator("EC");
			KeyPairGenerator generator = keyPairGenerator.current();
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			System.out.println("Use RPK.");
			return keyPairGenerator;
		} catch (GeneralSecurityException ex) {
			LOGGER.error("EC failed!", ex);
			return null;
		}
	}

	private static void startManagamentStatistic() {
		ThreadMXBean mxBean = ManagementFactory.getThreadMXBean();
		if (mxBean.isThreadCpuTimeSupported() && !mxBean.isThreadCpuTimeEnabled()) {
			mxBean.setThreadCpuTimeEnabled(true);
		}
	}

	private static Logger printManagamentStatistic(String[] args, long uptimeNanos) {
		OperatingSystemMXBean osMxBean = ManagementFactory.getOperatingSystemMXBean();
		int processors = osMxBean.getAvailableProcessors();
		String tag = StringUtil.getConfiguration("CALIFORNIUM_STATISTIC");
		Logger logger = STATISTIC_LOGGER;
		if (tag != null && !tag.isEmpty()) {
			// with tag, use file
			logger = LoggerFactory.getLogger(logger.getName() + ".file");
			logger.info("------- {} ------------------------------------------------", tag);
			logger.info("{}, {}, {}", osMxBean.getName(), osMxBean.getVersion(), osMxBean.getArch());
			StringBuilder line = new StringBuilder();
			List<String> vmArgs = ManagementFactory.getRuntimeMXBean().getInputArguments();
			for (String arg : vmArgs) {
				line.append(arg).append(" ");
			}
			logger.info("{}", line);
			line.setLength(0);
			for (String arg : args) {
				line.append(arg).append(" ");
			}
			logger.info("{}", line);
		}
		logger.info("uptime: {} ms, {} processors", TimeUnit.NANOSECONDS.toMillis(uptimeNanos), processors);
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
			logger.info("cpu-time: {} ms (per-processor: {} ms, load: {}%)", TimeUnit.NANOSECONDS.toMillis(alltime),
					TimeUnit.NANOSECONDS.toMillis(pTime), (pTime * 100) / uptimeNanos);
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
		return logger;
	}

	private static String formatRetransmissions(long retransmissions, long requests) {
		try (Formatter formatter = new Formatter()) {
			if (requests > 0) {
				return formatter
						.format("%d retransmissions (%4.2f%%)", retransmissions, ((retransmissions * 100D) / requests))
						.toString();
			} else {
				return formatter.format("%d retransmissions (no response-messages received!)", retransmissions)
						.toString();
			}
		}
	}

	private static String formatTransmissionErrors(long transmissionErrors, long requests) {
		try (Formatter formatter = new Formatter()) {
			if (requests > 0) {
				return formatter.format("%d transmission errors (%4.2f%%)", transmissionErrors,
						((transmissionErrors * 100D) / requests)).toString();
			} else {
				return formatter.format("%d transmission errors (no response-messages received!)", transmissionErrors)
						.toString();
			}
		}
	}

	private static String formatTime(long nanos) {
		long millis = TimeUnit.NANOSECONDS.toMillis(nanos);
		if (millis > 10000) {
			long secs = TimeUnit.NANOSECONDS.toSeconds(nanos);
			return secs + " s";
		} else {
			return millis + " ms";
		}
	}

	private static String formatUnavailable(int unavailable, long requests) {
		try (Formatter formatter = new Formatter()) {
			if (requests > 0) {
				return formatter.format("%d unavailables (%4.2f%%)", unavailable, ((unavailable * 100D) / requests))
						.toString();
			} else {
				return formatter.format("%d unavailables (no response-messages received!)", unavailable).toString();
			}
		}
	}

	private static String formatHonoCmds(int honoCmds, long requests) {
		try (Formatter formatter = new Formatter()) {
			if (requests > 0) {
				return formatter.format("%d hono-cmds (%4.2f%%)", honoCmds, ((honoCmds * 100D) / requests))
						.toString();
			} else {
				return formatter.format("%d hono-cmds (no response-messages received!)", honoCmds).toString();
			}
		}
	}

	private static String formatPerSecond(String units, long counts, long nanos) {
		long millis = TimeUnit.NANOSECONDS.toMillis(nanos);
		if (millis > 0) {
			try (Formatter formatter = new Formatter()) {
				return formatter.format(", %d %s/s", roundDiv(counts * 1000, millis), units).toString();
			}
		}
		return "";
	}

	private static String formatClientRequests(int statistic[], int index, int last) {
		try (Formatter formatter = new Formatter()) {
			formatter.format("%4d clients with %d", (index - last), statistic[last]);
			if (statistic[index - 1] != statistic[last]) {
				formatter.format(" to %d", statistic[index - 1]);
			}
			return formatter.format(" requests.").toString();
		}
	}

	private static long roundDiv(long count, long div) {
		return (count + (div / 2)) / div;
	}
}
