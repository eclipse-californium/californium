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

import javax.crypto.SecretKey;

import org.eclipse.californium.cli.ClientConfig;
import org.eclipse.californium.cli.ClientInitializer;
import org.eclipse.californium.cli.ConnectorConfig;
import org.eclipse.californium.cli.ConnectorConfig.AuthenticationMode;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EndpointContextTracer;
import org.eclipse.californium.core.coap.Message.OffloadMode;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.ResponseTimeout;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.ResourceObserverAdapter;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.FilteredLogger;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.TimeStatistic;
import org.eclipse.californium.extplugtests.resources.Feed;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalKeyPairGenerator;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

/**
 * Simple benchmark client.
 * 
 * Starts multiple parallel clients to send CON-POST requests. Print statistic
 * with retransmissions.
 */
public class BenchmarkClient {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(BenchmarkClient.class);

	private static final Logger STATISTIC_LOGGER = LoggerFactory
			.getLogger("org.eclipse.californium.extplugtests.statistics");

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumBenchmark3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Benchmark Client";
	/**
	 * Default maximum resource size.
	 */
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	/**
	 * Default block size.
	 */
	private static final int DEFAULT_BLOCK_SIZE = 1024;
	/**
	 * Default number of clients.
	 */
	private static final String DEFAULT_CLIENTS = "5";
	/**
	 * Default number of requests.
	 */
	private static final String DEFAULT_REQUESTS = "100";

	/**
	 * Definition for number of threads used per client. {@code 0} to use a
	 * shared thread pool.
	 * <p>
	 * Default: {@code 0}, use shared thread pool
	 * <p>
	 * Note: unfortunately the currently used synchronous socket requires at
	 * least it's own receiver thread. So the number of threads is considered to
	 * be used for the other components used by a client.
	 */
	private static final IntegerDefinition BENCHMARK_CLIENT_THREADS = new IntegerDefinition("BENCHMARK_CLIENT_THREADS",
			"Number of threads used per client. 0 to use a shared thread pool.");
	/**
	 * Response timeout for requests.
	 * 
	 * NON request may be limited by a smaller {@link CoapConfig#NON_LIFETIME}.
	 * 
	 * @since 3.1
	 */
	private static final TimeDefinition BENCHMARK_RESPONSE_TIMEOUT = new TimeDefinition("BENCHMARK_RESPONSE_TIMEOUT",
			"Response timeout.", 30, TimeUnit.SECONDS);

	private static final ThreadGroup CLIENT_THREAD_GROUP = new ThreadGroup("Client"); //$NON-NLS-1$

	private static final NamedThreadFactory threadFactory = new DaemonThreadFactory("Client#", CLIENT_THREAD_GROUP);
	/**
	 * Special configuration defaults handler.
	 */
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(BENCHMARK_CLIENT_THREADS, 0);
			config.set(BENCHMARK_RESPONSE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 10);
			config.set(CoapConfig.PEERS_MARK_AND_SWEEP_MESSAGES, 16);
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 24, TimeUnit.HOURS);
			config.set(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT, 1);
			// enabled by cli option, see "--bertblocks".
			config.set(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS, 1);
			config.set(TcpConfig.TCP_CONNECTION_IDLE_TIMEOUT, 12, TimeUnit.HOURS);
			config.set(TcpConfig.TCP_CONNECT_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(TcpConfig.TLS_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(TcpConfig.TLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false);
			config.set(TcpConfig.TCP_WORKER_THREADS, 1);
			config.set(UdpConfig.UDP_RECEIVER_THREAD_COUNT, 1);
			config.set(UdpConfig.UDP_SENDER_THREAD_COUNT, 1);
			config.set(UdpConfig.UDP_RECEIVE_BUFFER_SIZE, 8192);
			config.set(UdpConfig.UDP_SEND_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1);
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 10);
			config.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, 2);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			// support CID, but don't use for received records
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0);
			config.set(DtlsConfig.DTLS_RECEIVE_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_SEND_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false);
			config.set(DtlsConfig.DTLS_REMOVE_STALE_DOUBLE_PRINCIPALS, false);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 0, TimeUnit.SECONDS); // disabled
		}

	};

	@Command(name = "BenchmarkClient", version = "(c) 2018-2020, Bosch.IO GmbH and others.", footer = { "", "Examples:",
			"  BenchmarkClient coap://localhost:5783/benchmark?rlen=200 \\", "     --clients 500 --requests 2000",
			"  (Benchmark 500 clients each sending about 2000 request",
			"   and the response should have 200 bytes payload.)", "",
			"  BenchmarkClient coap://localhost:5783/reverse-observe?\\",
			"     obs=25&res=feed-CON&timeout=10&rlen=400 \\",
			"     --clients 50 --requests 2 --reverse 500 --min 2000",
			"  (Reverse-observe benchmark using 50 clients each sending 2 requests",
			"   and waiting for about 500 notifies each client. The notifies are",
			"   sent as CON every 2000ms and have 400 bytes payload.",
			"   A blocksize of 64 bytes is used, as defined in", "   \"CaliforniumReverseServer.properties\".)", "",
			"Note: californium.eclipseprojects.io doesn't support a benchmark",
			"      and will response with 5.01, NOT_IMPLEMENTED!" })
	private static class Config extends ClientConfig {

		@Option(names = "--clients", defaultValue = DEFAULT_CLIENTS, description = "number of clients. Default ${DEFAULT-VALUE}.")
		public int clients;

		@Option(names = "--requests", defaultValue = DEFAULT_REQUESTS, description = "number of requests. Default ${DEFAULT-VALUE}.")
		public int requests;

		/**
		 * Command spec for {@link ParameterException}.
		 * 
		 * @since 3.0
		 */
		@Spec
		CommandSpec spec; // injected by picocli

		/**
		 * Blockwise options.
		 * 
		 * @since 3.0
		 */
		@ArgGroup(exclusive = true)
		BlockwiseOptions blockwiseOptions;

		static class BlockwiseOptions {

			@Option(names = "--blocksize", description = "use blocksize [16, 32, ..., 1024]. Default according CaliforniumBenchmark.properties.")
			public Integer blocksize;

			@Option(names = "--bertblocks", description = "number of block used for bert-blockwise (TCP only). Default according CaliforniumBenchmark.properties.")
			public Integer bertBlocks;
		}

		@Option(names = "--timeout", description = "timeout of requests in milliseconds.")
		public Integer timeout;

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

		@Option(names = "--nstart", description = "number of concurrent requests.")
		public Integer nstart;

		static class Reverse {

			@Option(names = "--reverse", required = true, description = "number of reverse responses.")
			public Integer responses;

			@Option(names = { "--min",
					"--mininterval" }, required = false, description = "minimal interval of reverse responses.")
			public Integer min;

			@Option(names = { "--max",
					"--maxinterval" }, required = false, description = "maximal interval of reverse responses.")
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

		static class Observe {

			@Option(names = "--notifies", required = true, description = "number of notify responses.")
			public int notifies;

			@Option(names = "--reregister", required = false, description = "number of notify responses to reregister observe.")
			public int reregister = 0;

			@Option(names = "--register", required = false, description = "number of notify responses to register observe.")
			public int register = 0;

			@Option(names = "--cancel-proactive", required = false, description = "cancel observe relation proactive. Default is reactive.")
			public boolean proactive = false;
		}

		@ArgGroup(exclusive = true)
		Mode mode;

		static class Mode {
			@ArgGroup(exclusive = false)
			Observe observe_;

			@ArgGroup(exclusive = false)
			Reverse reverse_;

		}

		Observe observe;

		Reverse reverse;

		boolean multipleObserveRequests;

		public void defaults() {
			super.defaults();
			if (blockwiseOptions != null && blockwiseOptions.blocksize != null) {
				if (blockwiseOptions.blocksize > 1024
						|| blockwiseOptions.blocksize != Integer.highestOneBit(blockwiseOptions.blocksize)) {
					throw new ParameterException(spec.commandLine(),
							String.format(
									"Invalid value '%s' for option '--blocksize': value is not [16, 32, ..., 1024].",
									blockwiseOptions.blocksize));
				}
			}

			if (mode != null) {
				if (mode.reverse_ != null) {
					reverse = mode.reverse_;
					reverse.defaults();
				} else if (mode.observe_ != null) {
					observe = mode.observe_;
					requests = 1;
					multipleObserveRequests = mode.observe_.register > 0;
				}
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
			if (requests < 1) {
				requests = 1;
			}
		}
	}

	private static final Config config = new Config();

	/**
	 * Benchmark timeout. If no messages are exchanged within this timeout, the
	 * benchmark is stopped.
	 */
	private static final long DEFAULT_TIMEOUT_SECONDS = 10;
	private static final long DEFAULT_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(DEFAULT_TIMEOUT_SECONDS);
	private static final long DTLS_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(120);

	private static final FilteredLogger errorResponseFilter = new FilteredLogger(LOGGER.getName(), 5, DEFAULT_TIMEOUT_NANOS);
	private static final FilteredLogger errorFilter = new FilteredLogger(LOGGER.getName(), 3, DEFAULT_TIMEOUT_NANOS);

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
	 * Done indicator for overall reverse responses.
	 */
	private static final CountDownLatch overallReveresResponsesDone = new CountDownLatch(1);
	/**
	 * Atomic down-counter for overall reverse responses.
	 */
	private static final AtomicLong overallReverseResponsesDownCounter = new AtomicLong();
	/**
	 * Done indicator for overall notifies.
	 */
	private static final CountDownLatch overallNotifiesDone = new CountDownLatch(1);
	/**
	 * Atomic down-counter for overall notifies.
	 */
	private static final AtomicLong overallNotifiesDownCounter = new AtomicLong();
	/**
	 * Client counter.
	 */
	private static final AtomicInteger clientCounter = new AtomicInteger();
	/**
	 * Initial connect counter. On success, matches client counter.
	 */
	private static final AtomicInteger initialConnectDownCounter = new AtomicInteger();
	/**
	 * Overall transmission counter.
	 * 
	 * Counts per block request.
	 */
	private static final AtomicLong transmissionCounter = new AtomicLong();
	/**
	 * Overall retransmission counter.
	 */
	private static final AtomicLong retransmissionCounter = new AtomicLong();
	/**
	 * Message observer to detect retransmissions.
	 */
	private static final MessageObserver retransmissionDetector = new MessageObserverAdapter() {

		@Override
		public void onSent(boolean retransmission) {
			if (!retransmission) {
				transmissionCounter.incrementAndGet();
			}
		}

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
			if (counter == 0) {
				checkStop();
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

	private static final TimeStatistic connectRttStatistic = new TimeStatistic(10000, 5, TimeUnit.MILLISECONDS);

	private static final TimeStatistic rttStatistic = new TimeStatistic(10000, 5, TimeUnit.MILLISECONDS);

	private static final TimeStatistic errorRttStatistic = new TimeStatistic(10000, 5, TimeUnit.MILLISECONDS);

	private static final TimeStatistic transmissionRttStatistic = new TimeStatistic(10000, 5, TimeUnit.MILLISECONDS);

	private static volatile String[] args;
	private static volatile int clients;
	private static volatile int overallRequests;
	private static volatile int overallReverseResponses;
	private static volatile int overallNotifies;
	private static volatile long startRequestNanos;
	private static volatile long timeRequestNanos;
	private static volatile long startReverseResponseNanos;
	private static volatile long timeReverseResponseNanos;
	private static volatile long startNotifiesNanos;
	private static volatile long timeNotifiesNanos;
	private static volatile HealthStatisticLogger health;
	private static volatile NetStatLogger netstat4;
	private static volatile NetStatLogger netstat6;
	private static volatile boolean done;

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
	 * Per client request down counter. Used,if only a few requests per client
	 * is expected.
	 */
	private final AtomicInteger requestsDownCounter = new AtomicInteger();
	/**
	 * Per client notifies counter.
	 */
	private final AtomicInteger notifiesCounter = new AtomicInteger();
	/**
	 * Indicate that the next notification counts as response.
	 */
	private final AtomicBoolean notifyResponse = new AtomicBoolean();
	/**
	 * Indicate that client is pending to connect.
	 */
	private final AtomicBoolean connect = new AtomicBoolean(true);
	/**
	 * Indicate that client has stopped.
	 * 
	 * @see #stop()
	 */
	private final AtomicBoolean stop = new AtomicBoolean();

	private final FeedObserver feedObserver = new FeedObserver();

	private final String id;

	private final boolean secure;
	private final boolean tcp;

	private final DTLSConnector dtlsConnector;

	private final long ackTimeout;
	private final long responseTimeout;
	private final BlockOption block2;

	private volatile CoapObserveRelation clientObserveRelation;

	private Request prepareRequest(CoapClient client, long c) {
		if (!config.multipleObserveRequests && overallRequestsDownCounter.get() <= 0) {
			return null;
		}
		countDown(overallRequestsDownCounter);
		Request request;
		int accept = TEXT_PLAIN;
		byte[] payload = config.payload == null ? null : config.payload.payloadBytes;
		if (config.hono) {
			request = secure ? Request.newPost() : Request.newPut();
			if (payload == null) {
				accept = APPLICATION_JSON;
				payload = "{\"temp\": %1$d }".getBytes();
			}
		} else if (config.observe != null) {
			request = Request.newGet();
			request.setObserve();
		} else {
			request = Request.newPost();
		}
		if (config.contentType != null) {
			accept = config.contentType.contentType;
		}
		request.getOptions().setAccept(accept);
		if (config.messageType != null) {
			request.setConfirmable(config.messageType.con);
		}
		request.getOptions().setBlock2(block2);
		if (request.isIntendedPayload()) {
			request.getOptions().setContentFormat(accept);
			if (payload != null) {
				if (config.payloadFormat) {
					String text = new String(payload, CoAP.UTF8_CHARSET);
					text = String.format(text, c, System.currentTimeMillis() / 1000);
					request.setPayload(text);
				} else {
					request.setPayload(payload);
				}
			}
		}
		if (config.proxy != null) {
			request.setDestinationContext(new AddressEndpointContext(config.proxy.destination));
			if (config.proxy.scheme != null) {
				request.getOptions().setProxyScheme(config.proxy.scheme);
			}
		}
		EndpointContext destinationContext = client.getDestinationContext();
		if (destinationContext != null) {
			request.setDestinationContext(destinationContext);
		}
		request.setURI(uri);
		ResponseTimeout timeout = new ResponseTimeout(request, responseTimeout, executorService);
		request.addMessageObserver(timeout);
		request.addMessageObserver(retransmissionDetector);
		return request;
	}

	private class TestHandler implements CoapHandler {

		private final Request post;
		private final long start = ClockUtil.nanoRealtime();

		private TestHandler(final Request post) {
			this.post = post;
		}

		@Override
		public void onLoad(CoapResponse response) {
			addToStatistic(response);
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
					next(config.interval, response.advanced().isConfirmable() ? -ackTimeout * 2 : 0, true, true, response.advanced().isNotification());
				}
				long c = overallResponsesDownCounter.get();
				LOGGER.trace("{}: Received response: {} {}", id, response.advanced(), c);
			} else if (response.getCode() == ResponseCode.SERVICE_UNAVAILABLE) {
				long delay = TimeUnit.SECONDS.toMillis(response.getOptions().getMaxAge());
				int unavailable = overallServiceUnavailable.incrementAndGet();
				long c = overallResponsesDownCounter.get();
				LOGGER.debug("{}: Received {} unavailabe response: {} {}", id, unavailable, response.advanced(), c);
				if (!stop.get()) {
					next(delay < 1000L ? 1000L : delay, -ackTimeout * 2, true, true, false);
				}
			} else if (!config.stop) {
				String type = post.isConfirmable() ? "CON" : "NON";
				long c = requestsCounter.get();
				transmissionErrorCounter.incrementAndGet();
				errorResponseFilter.warn("{}: Error response after {} {}-requests. {} - {}", id, c, type,
						response.advanced().getCode(), response.advanced().getPayloadString());
				if (!stop.get()) {
					next(1000, -ackTimeout * 2, true, true, false);
				}
			} else {
				String type = post.isConfirmable() ? "CON" : "NON";
				long c = requestsCounter.get();
				LOGGER.warn("{}: Received error response: {} {} ({} {} successful)", id, endpoint.getUri(),
						response.advanced(), c, type);
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
				boolean non = !post.isConfirmable();
				String type = non ? "NON" : "CON";
				long c = requestsCounter.get();
				long time = ClockUtil.nanoRealtime() - start;
				String msg = "";
				if (post.getSendError() != null) {
					msg = post.getSendError().getMessage();
				} else if (post.isTimedOut()) {
					msg = "timeout (" + TimeUnit.NANOSECONDS.toSeconds(time) + "s)";
				} else if (post.isRejected()) {
					msg = "rejected";
				}
				if (!config.stop || non) {
					if (requestsDownCounter.get() > 0) {
						requestsDownCounter.incrementAndGet();
					}
					overallRequestsDownCounter.incrementAndGet();
					transmissionErrorCounter.incrementAndGet();
					if (next(1000, secure && !non ? 1000 : 0, c > 0, false, false)) {
						errorFilter.info("{}: Error after {} {}-requests. {}", id, c, type, msg);
					} else {
						LOGGER.warn("{}: stopped by error after {} {}-requests. {}", id, c, type, msg);
						stop();
					}
				} else {
					LOGGER.error("{}: failed after {} {}-requests! {}", id, c, type, msg);
					checkReady(true, false);
					stop();
				}
			}
		}

		public boolean next(long delayMillis, long forceHandshake, boolean connected, boolean response, boolean notify) {
			long responses;
			if (notify && post.isObserve() && config.observe != null) {
				int notifies = notifiesCounter.incrementAndGet();
				if (notifyResponse.compareAndSet(true, false)) {
					responses = checkOverallRequests(connected, response);
				} else {
					responses = overallResponsesDownCounter.get();
				}
				if (overallNotifiesDownCounter.decrementAndGet() <= 0) {
					overallNotifiesDone.countDown();
					if (checkStop()) {
						return false;
					}
				}
				LOGGER.trace("{}: receive notify {}/{}", id, notifies, overallNotifiesDownCounter.get());
				CoapObserveRelation relation = clientObserveRelation;
				if (relation != null && !relation.isCanceled()) {
					if (config.observe.register > 0 && (notifies % config.observe.register) == 0) {
						clientObserveRelation = null;
						if (config.observe.proactive || tcp) {
							relation.proactiveCancel();
							LOGGER.trace("{}: cancel proactive, register again {}/{}", id, notifies, overallNotifiesDownCounter.get());
							return true;
						} else {
							relation.reactiveCancel();
							LOGGER.trace("{}: register again {}/{}", id, notifies, overallNotifiesDownCounter.get());
							// send next request for new registration
						}
					} else if (config.observe.reregister > 0 && (notifies % config.observe.reregister) == 0) {
						notifyResponse.set(true);
						try {
							relation.reregister();
							overallRequestsDownCounter.decrementAndGet();
							LOGGER.trace("{}: reregister {}/{}", id, notifies, overallNotifiesDownCounter.get());
						} catch (IllegalStateException ex) {
						}
						return true;
					} else {
						// notify without new request
						return true;
					}
				} else {
					// notify too fast
					return true;
				}
			} else {
				responses = checkOverallRequests(connected, response);
			}
			if (!config.multipleObserveRequests) {
				if (responses <= 0) {
					return false;
				}
				if (requestsDownCounter.get() > 0) {
					if (requestsDownCounter.decrementAndGet() == 0) {
						return false;
					}
				}
			}

			boolean close = false;
			boolean dtlsReconnect = false;
			if (dtlsConnector != null) {
				boolean full = false;
				boolean force = forceHandshake > 0;
				if (!force) {
					close = (config.closes != 0 && (responses % config.closes == 0));
					full = (config.handshakes != 0 && (responses % config.handshakes == 0));
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
				dtlsReconnect = close || full || force;
			}
			if (dtlsReconnect) {
				// reset destination context
				client.setDestinationContext(null);
			}
			final boolean reconnect = dtlsReconnect;
			final Request request = prepareRequest(client, responses);
			final long responseCounter = responses;
			if (request == null) {
				return false;
			}
			if (reconnect) {
				connect.set(true);
				EndpointContext destinationContext = request.getDestinationContext();
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
							LOGGER.trace("{}: close {} {}", id, responseCounter, delay);
						}
					}, delayMillis, TimeUnit.MILLISECONDS);
					if (delayMillis < 500) {
						delayMillis = 1000;
					} else {
						delayMillis *= 2;
					}
				} else {
					destinationContext = MapBasedEndpointContext.setEntries(destinationContext,
							DtlsEndpointContext.ATTRIBUE_HANDSHAKE_MODE_FORCE_FULL);
					request.setDestinationContext(destinationContext);
				}
			}
			if (delayMillis > 0) {
				int r = RandomManager.currentRandom().nextInt(500);
				final long delay = delayMillis + r;
				executorService.schedule(new Runnable() {

					@Override
					public void run() {
						send(request);
						LOGGER.trace("{}: sent request {} {} {}", id, responseCounter, delay, reconnect);
					}
				}, delay, TimeUnit.MILLISECONDS);
			} else {
				send(request);
				LOGGER.trace("{}: sent request {} {} {}", id, responseCounter, delayMillis, reconnect);
			}
			return true;
		}
	}

	/**
	 * Create client.
	 * 
	 * @param index index of client. used for thread names.
	 * @param reverse reverse configuration with minimum and maxium notifies
	 *            interval
	 * @param uri destination URI
	 * @param endpoint local endpoint to exchange messages
	 * @param executor executor for client
	 * @param secondaryExecutor intended to be used for rare executing timers
	 *            (e.g. cleanup tasks).
	 */
	public BenchmarkClient(int index, Config.Reverse reverse, URI uri, CoapEndpoint endpoint,
			ScheduledExecutorService executor, ScheduledThreadPoolExecutor secondaryExecutor) {
		this.secure = CoAP.isSecureScheme(uri.getScheme());
		this.tcp = CoAP.isTcpScheme(uri.getScheme());
		Connector connector = endpoint.getConnector();
		this.dtlsConnector = secure && connector instanceof DTLSConnector ? (DTLSConnector) connector : null;
		this.id = endpoint.getTag();
		this.uri = uri;
		Configuration configuration = endpoint.getConfig();
		int maxResourceSize = configuration.get(CoapConfig.MAX_RESOURCE_BODY_SIZE);
		if (executor == null) {
			int threads = configuration.get(BENCHMARK_CLIENT_THREADS);
			this.executorService = ExecutorsUtil.newScheduledThreadPool(threads, threadFactory);
			this.shutdown = true;
		} else {
			this.executorService = executor;
			this.shutdown = false;
		}
		this.ackTimeout = configuration.getTimeAsInt(CoapConfig.ACK_TIMEOUT, TimeUnit.MILLISECONDS);
		this.responseTimeout = configuration.getTimeAsInt(BENCHMARK_RESPONSE_TIMEOUT, TimeUnit.MILLISECONDS);

		if (config.blockwiseOptions != null && config.blockwiseOptions.blocksize != null) {
			block2 = new BlockOption(BlockOption.size2Szx(config.blockwiseOptions.blocksize), false, 0);
		} else {
			block2 = null;
		}

		endpoint.addInterceptor(new MessageTracer());
		endpoint.setExecutors(this.executorService, secondaryExecutor);
		this.client = new CoapClient(uri);
		this.server = new CoapServer(configuration);
		if (reverse != null) {
			Feed feed = new Feed(CoAP.Type.NON, index, maxResourceSize, reverse.min, reverse.max, this.executorService,
					overallReveresResponsesDone, overallReverseResponsesDownCounter, notifiesCompleteTimeouts, stop);
			feed.addObserver(feedObserver);
			this.server.add(feed);
			feed = new Feed(CoAP.Type.CON, index, maxResourceSize, reverse.min, reverse.max, this.executorService,
					overallReveresResponsesDone, overallReverseResponsesDownCounter, notifiesCompleteTimeouts, stop);
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

	private void addToStatistic(CoapResponse response) {
		Long rtt = response.advanced().getApplicationRttNanos();
		if (rtt != null) {
			TimeStatistic statistic = errorRttStatistic;
			if (connect.compareAndSet(true, false)) {
				statistic = connectRttStatistic;
			} else {
				statistic = rttStatistic;
				Long transmissionRttNanos = response.advanced().getTransmissionRttNanos();
				if (transmissionRttNanos != null && !transmissionRttNanos.equals(rtt)) {
					transmissionRttStatistic.add(transmissionRttNanos, TimeUnit.NANOSECONDS);
				}
			}
			statistic.add(rtt, TimeUnit.NANOSECONDS);
		}
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

				private final AtomicBoolean ready = new AtomicBoolean();
				private final AtomicInteger counter = new AtomicInteger();

				@Override
				public void onReadyToSend() {
					if (ready.compareAndSet(false, true)) {
						LOGGER.info("Request:{}{}", StringUtil.lineSeparator(), Utils.prettyPrint(request));
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
				public void onRetransmission() {
					int count = counter.incrementAndGet();
					LOGGER.info("Request: {} retransmissions{}{}", count, StringUtil.lineSeparator(),
							Utils.prettyPrint(request));
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
			CoapResponse response = null;
			;
			if (request.isObserve()) {
				clientObserveRelation = client.observeAndWait(new TestHandler(request));
				response = clientObserveRelation.getCurrent();
			} else {
				response = client.advanced(request);
			}
			if (response != null) {
				addToStatistic(response);
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
	public void startBenchmark(int requestPerClient) {
		requestsDownCounter.set(requestPerClient);
		if (clientObserveRelation != null) {
			LOGGER.trace("{}: observation already started!", id);
			return;
		}
		long c = checkOverallRequests(false, false);
		if (c > 0) {
			if (requestsCounter.get() == 0) {
				clientCounter.incrementAndGet();
			}
			Request request = prepareRequest(client, c);
			if (request != null) {
				LOGGER.trace("{}: sent initial request", id);
				send(request);
			}
			if (config.nstart != null) {
				for (int counter = 1; counter < config.nstart; ++counter) {
					request = prepareRequest(client, c);
					if (request != null) {
						request.addMessageObserver(retransmissionDetector);
						client.advanced(new TestHandler(request), request);
					}
				}
			}
		} else {
			LOGGER.trace("{}: {} requests and {} responses reached, not started", id, overallRequestsDownCounter.get(),
					overallResponsesDownCounter.get());
		}
	}

	public void send(Request request) {
		TestHandler handler = new TestHandler(request);
		if (request.isObserve()) {
			CoapObserveRelation relation = clientObserveRelation;
			if (relation != null) {
				relation.reactiveCancel();
			}
			notifyResponse.set(true);
			clientObserveRelation = client.observe(request, handler);
		} else {
			client.advanced(handler, request);
		}
	}

	public boolean checkReady(boolean connected, boolean response) {
		return checkOverallRequests(connected, response) <= 0;
	}

	public long checkOverallRequests(boolean connected, boolean response) {
		if (connected) {
			if (requestsCounter.get() == 0) {
				initialConnectDownCounter.decrementAndGet();
			}
			if (response) {
				requestsCounter.getAndIncrement();
			}
		}
		long c = response ? countDown(overallResponsesDownCounter) : overallResponsesDownCounter.get();
		if (c <= 0 && initialConnectDownCounter.get() <= 0) {
			overallRequestsDone.countDown();
			checkStop();
		}
		return c;
	}

	/**
	 * Check, if all counters have reached the expected value.
	 * 
	 * @return {@code true}, if client is stopped, {@code false}, otherwise
	 * @since 3.6
	 */
	public boolean checkStop() {
		if (initialConnectDownCounter.get() <= 0 && overallResponsesDownCounter.get() <= 0 && observerCounter.get() <= 0
				&& overallReverseResponsesDownCounter.get() <= 0 && overallNotifiesDownCounter.get() <= 0) {
			stop();
			return true;
		}
		return false;
	}

	/**
	 * Stop benchmark.
	 */
	public void stop() {
		if (stop.compareAndSet(false, true)) {
			if (clientObserveRelation != null) {
				clientObserveRelation.reactiveCancel();
			}
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
		if (config.multipleObserveRequests) {
			return downCounter.decrementAndGet();
		} else {
			long c = downCounter.get();
			while (c > 0) {
				if (downCounter.compareAndSet(c, c - 1)) {
					return c - 1;
				}
				c = downCounter.get();
			}
			return 0;
		}
	}

	public static void main(String[] args) throws InterruptedException, IOException {
		TcpConfig.register();
		BenchmarkClient.args = args;
		startManagamentStatistic();
		config.configurationHeader = CONFIG_HEADER;
		config.customConfigurationDefaultsProvider = DEFAULTS;
		config.configurationFile = CONFIG_FILE;
		ClientInitializer.init(args, config, false);

		if (config.helpRequested) {
			System.exit(0);
		}

		// random part of PSK identity
		final SecureRandom random = new SecureRandom();
		final byte[] id = new byte[8];

		final int clients = config.clients;
		BenchmarkClient.clients = clients;
		int reverseResponses = 0;
		int notifies = 0;

		if (config.blockwiseOptions != null) {
			if (config.blockwiseOptions.bertBlocks != null && config.blockwiseOptions.bertBlocks > 0) {
				config.configuration.set(CoapConfig.MAX_MESSAGE_SIZE, 1024);
				config.configuration.set(CoapConfig.PREFERRED_BLOCK_SIZE, 1024);
				config.configuration.set(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS, config.blockwiseOptions.bertBlocks);
			} else if (config.blockwiseOptions.blocksize != null) {
				config.configuration.set(CoapConfig.MAX_MESSAGE_SIZE, config.blockwiseOptions.blocksize);
				config.configuration.set(CoapConfig.PREFERRED_BLOCK_SIZE, config.blockwiseOptions.blocksize);
			}
		}

		if (config.reverse != null) {
			reverseResponses = config.reverse.responses;
		}
		if (config.observe != null) {
			notifies = config.observe.notifies;
		}

		if (config.timeout != null) {
			config.configuration.set(CoapConfig.NON_LIFETIME, config.timeout, TimeUnit.MILLISECONDS);
		}

		offload = config.configuration.get(CoapConfig.USE_MESSAGE_OFFLOADING);

		URI tempUri;
		try {
			tempUri = new URI(config.uri);
		} catch (URISyntaxException e) {
			tempUri = null;
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
		final URI uri = tempUri;

		overallRequests = (config.requests * clients);
		overallReverseResponses = (reverseResponses * clients);
		overallNotifies = (notifies * clients);
		if (overallRequests < 0) {
			// overflow
			overallRequests = Integer.MAX_VALUE;
		}
		if (overallReverseResponses < 0) {
			// overflow
			overallReverseResponses = Integer.MAX_VALUE;
		}
		if (overallNotifies < 0) {
			// overflow
			overallNotifies = Integer.MAX_VALUE;
		}
		overallRequestsDownCounter.set(overallRequests);
		overallResponsesDownCounter.set(overallRequests);
		overallReverseResponsesDownCounter.set(overallReverseResponses);
		overallNotifiesDownCounter.set(overallNotifies);

		final List<BenchmarkClient> clientList = Collections.synchronizedList(new ArrayList<BenchmarkClient>(clients));
		ScheduledExecutorService executor = ExecutorsUtil
				.newScheduledThreadPool(Runtime.getRuntime().availableProcessors(), new DaemonThreadFactory("Aux#"));

		final ScheduledExecutorService connectorExecutor = config.configuration.get(BENCHMARK_CLIENT_THREADS) == 0
				? executor
				: null;
		final boolean secure = CoAP.isSecureScheme(uri.getScheme());
		final boolean dtls = secure && !CoAP.isTcpScheme(uri.getScheme());

		final ScheduledThreadPoolExecutor secondaryExecutor = new ScheduledThreadPoolExecutor(2,
				new DaemonThreadFactory("Aux(secondary)#"));

		String proxyMessage = "";
		if (config.proxy != null) {
			proxyMessage = "via proxy " + config.proxy + " ";
		}
		System.out.format("Create %d %s%sbenchmark clients, expect to send %d requests overall %sto %s%n", clients,
				!config.stop ? "none-stop " : "", secure ? "secure " : "", overallRequests, proxyMessage, uri);

		if (overallReverseResponses > 0) {
			if (config.reverse.min.equals(config.reverse.max)) {
				System.out.format("Expect %d notifies sent, interval %d [ms]%n", overallReverseResponses,
						config.reverse.min);
			} else {
				System.out.format("Expect %d notifies sent, interval %d ... %d [ms]%n", overallReverseResponses,
						config.reverse.min, config.reverse.max);
			}
		}
		if (overallNotifies > 0) {
			System.out.format("Expect %d notifies received, reregister every %d and register every %d notify%n", overallNotifies,
						config.observe.reregister, config.observe.register);
		}
		initialConnectDownCounter.set(clients);
		final boolean psk = config.authenticationModes.contains(AuthenticationMode.PSK)
				|| config.authenticationModes.contains(AuthenticationMode.ECDHE_PSK);
		final boolean rpk = config.authenticationModes.contains(AuthenticationMode.RPK);
		long startupNanos = System.nanoTime();
		final AuthenticationMode authentication = config.authenticationModes.isEmpty() ? null
				: config.authenticationModes.get(0);
		final CountDownLatch start = new CountDownLatch(clients);
		if (secure && authentication != null) {
			switch (authentication) {
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
		health = new HealthStatisticLogger(uri.getScheme(), CoAP.isUdpScheme(uri.getScheme()));
		if (CoAP.isUdpScheme(uri.getScheme())) {
			netstat4 = new NetStatLogger("udp4", false);
			netstat6 = new NetStatLogger("udp6", true);
		}
		final String tag = config.tag == null ? "client-" : config.tag;
		final int pskOffset = config.pskIndex != null ? config.pskIndex : 0;
		for (int index = 0; index < clients; ++index) {
			final int currentIndex = index;
			final String identity;
			final SecretKey secret;
			if (secure && psk) {
				if (config.pskStore != null) {
					int pskIndex = (pskOffset + index) % config.pskStore.size();
					identity = config.pskStore.getIdentity(pskIndex);
					secret = config.pskStore.getSecret(pskIndex);
				} else if (index == 0) {
					identity = config.identity;
					secret = config.getPskSecretKey();
				} else {
					random.nextBytes(id);
					identity = ConnectorConfig.PSK_IDENTITY_PREFIX + StringUtil.byteArray2Hex(id);
					secret = config.getPskSecretKey();
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
					ClientConfig connectionConfig = config;
					if (secure) {
						if (rpk) {
							if (keyPairGenerator != null) {
								try {
									KeyPairGenerator generator = keyPairGenerator.current();
									generator.initialize(new ECGenParameterSpec("secp256r1"),
											RandomManager.currentSecureRandom());
									KeyPair keyPair = generator.generateKeyPair();
									connectionConfig = connectionConfig.create(keyPair.getPrivate(),
											keyPair.getPublic());
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
					if (connectionConfig == config) {
						connectionConfig = config.create();
					}
					connectionConfig.tag = tag + currentIndex;
					CoapEndpoint coapEndpoint = ClientInitializer.createEndpoint(connectionConfig, connectorExecutor);
					if (health.isEnabled()) {
						coapEndpoint.addPostProcessInterceptor(health);
					}
					BenchmarkClient client = new BenchmarkClient(currentIndex, config.reverse, uri, coapEndpoint,
							connectorExecutor, secondaryExecutor);
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
						System.out.println("ID: " + identity + ", " + new String(secret.getEncoded()));
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
		startRequestNanos = System.nanoTime();
		startReverseResponseNanos = startRequestNanos;
		startNotifiesNanos = startRequestNanos;
		long lastRequestsCountDown = overallRequestsDownCounter.get();
		long lastResponsesCountDown = overallResponsesDownCounter.get();
		long lastTransmissions = transmissionCounter.get();
		long lastRetransmissions = retransmissionCounter.get();
		long lastTransmissionErrrors = transmissionErrorCounter.get();
		int lastUnavailable = overallServiceUnavailable.get();
		int lastHonoCmds = overallHonoCmds.get();
		int requestsPerClient = config.requests <= 10 ? config.requests : -1;
		for (int index = clients - 1; index >= 0; --index) {
			BenchmarkClient client = clientList.get(index);
			if (index == 0) {
				--requestsPerClient;
			}
			client.startBenchmark(requestsPerClient);
		}
		registerShutdown();
		System.out.println("Benchmark started.");

		long staleTime = System.nanoTime();
		long interval = config.interval == null ? 0 : TimeUnit.MILLISECONDS.toNanos(config.interval);
		if (dtls) {
			interval = Math.max(interval, DTLS_TIMEOUT_NANOS);
		}
		long staleTimeout = DEFAULT_TIMEOUT_NANOS + interval;
		int count = 0;
		// Wait with timeout or all requests send.
		while (!overallRequestsDone.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
			long currentRequestsCountDown = overallRequestsDownCounter.get();
			long currentResponsesCountDown = overallResponsesDownCounter.get();
			int numberOfClients = clientCounter.get();
			int connectsPending = initialConnectDownCounter.get();
			long requestsDifference = (lastRequestsCountDown - currentRequestsCountDown);
			long responsesDifference = (lastResponsesCountDown - currentResponsesCountDown);
			long currentOverallSentRequests = overallRequests - currentRequestsCountDown;
			if ((responsesDifference == 0 && currentResponsesCountDown < overallRequests) || (numberOfClients == 0)) {
				// no new requests, clients are stale, or no clients left
				// adjust start time with timeout
				long timeout = System.nanoTime() - staleTime;
				if ((timeout - staleTimeout) > 0) {
					startRequestNanos += timeout;
					startReverseResponseNanos = startRequestNanos;
					startNotifiesNanos = startRequestNanos;
					stale = true;
					System.out.format("[%04d]: %d requests, stale (%d clients, %d pending)%n", ++count,
							currentOverallSentRequests, numberOfClients, connectsPending);
					break;
				}
			} else {
				staleTime = System.nanoTime();
			}
			long transmissions = transmissionCounter.get();
			long transmissionsDifference = transmissions - lastTransmissions;
			long retransmissions = retransmissionCounter.get();
			long retransmissionsDifference = retransmissions - lastRetransmissions;
			long transmissionErrors = transmissionErrorCounter.get();
			long transmissionErrorsDifference = transmissionErrors - lastTransmissionErrrors;
			int unavailable = overallServiceUnavailable.get();
			int unavailableDifference = unavailable - lastUnavailable;

			int honoCmds = overallHonoCmds.get();
			int honoCmdsDifference = honoCmds - lastHonoCmds;

			lastRequestsCountDown = currentRequestsCountDown;
			lastResponsesCountDown = currentResponsesCountDown;
			lastTransmissions = transmissions;
			lastRetransmissions = retransmissions;
			lastTransmissionErrrors = transmissionErrors;
			lastUnavailable = unavailable;
			lastHonoCmds = honoCmds;

			StringBuilder line = new StringBuilder();
			line.append(String.format("[%04d]: ", ++count));
			line.append(String.format("%d requests (%d reqs/s", currentOverallSentRequests,
					roundDiv(responsesDifference, DEFAULT_TIMEOUT_SECONDS)));
			line.append(", ").append(
					formatRetransmissions(retransmissionsDifference, transmissionsDifference, responsesDifference));
			line.append(", ").append(
					formatTransmissionErrors(transmissionErrorsDifference, requestsDifference, responsesDifference));
			if (unavailable > 0) {
				line.append(", ").append(formatUnavailable(unavailableDifference, responsesDifference));
			}
			if (honoCmds > 0) {
				line.append(", ").append(formatHonoCmds(honoCmdsDifference, responsesDifference));
			}
			line.append(String.format(", %d clients", numberOfClients));
			if (connectsPending > 0) {
				line.append(String.format(", %d pending", connectsPending));
			}
			line.append(")");
			System.out.println(line);
		}
		timeRequestNanos = System.nanoTime() - startRequestNanos;

		boolean observe = false;
		long lastReverseResponsesCountDown = overallReverseResponsesDownCounter.get();
		if (config.reverse != null && lastReverseResponsesCountDown > 0) {
			System.out.println("Requests sent.");
			long lastChangeNanoRealtime = ClockUtil.nanoRealtime();
			while (!overallReveresResponsesDone.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
				long currentReverseResponsesCountDown = overallReverseResponsesDownCounter.get();
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
					// wait extra DEFAULT_TIMEOUT_NANOS for start of reverse
					// responses.
					time = ClockUtil.nanoRealtime() - lastChangeNanoRealtime - DEFAULT_TIMEOUT_NANOS;
				}
				if (config.reverse.max < TimeUnit.NANOSECONDS.toMillis(time - DEFAULT_TIMEOUT_NANOS)
						|| (numberOfClients == 0)) {
					// no new notifies for interval max, clients are stale, or
					// no clients left
					// adjust start time with timeout
					startReverseResponseNanos += time;
					stale = true;
					if (observe) {
						System.out.format("[%04d]: %d notifies, stale (%d clients, %d observes)%n", ++count,
								currentOverallReverseResponses, numberOfClients, observers);
					} else {
						System.out.format("[%04d]: %d reverse-responses, stale (%d clients)%n", ++count,
								currentOverallReverseResponses, numberOfClients);
					}
					break;
				}
				lastReverseResponsesCountDown = currentReverseResponsesCountDown;
				if (observe) {
					System.out.format("[%04d]: %d notifies (%d notifies/s, %d clients, %d observes)%n", ++count,
							currentOverallReverseResponses,
							roundDiv(reverseResponsesDifference, DEFAULT_TIMEOUT_SECONDS), numberOfClients, observers);
				} else {
					System.out.format("[%04d]: %d reverse-responses (%d reverse-responses/s, %d clients)%n", ++count,
							currentOverallReverseResponses,
							roundDiv(reverseResponsesDifference, DEFAULT_TIMEOUT_SECONDS), numberOfClients);
				}
			}
		}

		timeReverseResponseNanos = System.nanoTime() - startReverseResponseNanos;

		long lastNotifiesCountDown = overallNotifiesDownCounter.get();
		if (config.observe != null && lastNotifiesCountDown > 0) {
			System.out.println("Observe-Requests sent.");
			long currentOverallSentRequests = overallRequests - overallRequestsDownCounter.get();
			long lastChangeNanoRealtime = ClockUtil.nanoRealtime();
			while (!overallNotifiesDone.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
				long currentRequestsCountDown = overallRequestsDownCounter.get();
				long requestsDifference = (lastRequestsCountDown - currentRequestsCountDown);
				currentOverallSentRequests += requestsDifference;

				long currentNotifiesCountDown = overallNotifiesDownCounter.get();
				int numberOfClients = clientCounter.get();
				long notifiesDifference = (lastNotifiesCountDown - currentNotifiesCountDown);
				long currentOverallNotifies = overallNotifies - currentNotifiesCountDown;
				long time = 0;
				if (currentNotifiesCountDown < overallNotifies) {
					if (notifiesDifference == 0) {
						time = ClockUtil.nanoRealtime() - lastChangeNanoRealtime;
					} else {
						lastChangeNanoRealtime = ClockUtil.nanoRealtime();
					}
				} else {
					// wait extra DEFAULT_TIMEOUT_NANOS for start of reverse
					// responses.
					time = ClockUtil.nanoRealtime() - lastChangeNanoRealtime - DEFAULT_TIMEOUT_NANOS;
				}
				if (0 < TimeUnit.NANOSECONDS.toMillis(time - DEFAULT_TIMEOUT_NANOS) || (numberOfClients == 0)) {
					// no new notifies for interval max, clients are stale, or
					// no clients left
					// adjust start time with timeout
					startNotifiesNanos += time;
					stale = true;
					System.out.format("[%04d]: %d notifies, %d request, stale (%d clients)%n", ++count,
							currentOverallNotifies, currentOverallSentRequests, numberOfClients);
					break;
				}
				lastRequestsCountDown = currentRequestsCountDown;
				lastNotifiesCountDown = currentNotifiesCountDown;
				System.out.format("[%04d]: %d notifies, %d request (%d notifies/s, %d clients)%n", ++count,
						currentOverallNotifies, currentOverallSentRequests,
						roundDiv(notifiesDifference, DEFAULT_TIMEOUT_SECONDS), numberOfClients);
			}
		}

		timeNotifiesNanos = System.nanoTime() - startNotifiesNanos;

		// long overallSentReverseResponses = overallReverseResponses -
		// overallReverseResponsesDownCounter.getCount();

		System.out.format("%d benchmark clients %s.%n", clients, stale ? "stopped" : "finished");

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
		done = true;
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

	private static void printResults() {
		long now = System.nanoTime();
		if (timeRequestNanos == 0) {
			timeRequestNanos = now - startRequestNanos;
		}
		if (timeReverseResponseNanos == 0) {
			timeReverseResponseNanos = now - startReverseResponseNanos;
		}
		if (timeNotifiesNanos == 0) {
			timeNotifiesNanos = now - startNotifiesNanos;
		}
		if (!done) {
			System.out.format("%n%d benchmark clients interrupted.%n", clients);
		}

		Logger statisticsLogger = printManagamentStatistic(args, timeReverseResponseNanos);
		long overallSentRequests = overallRequests - overallResponsesDownCounter.get();
		statisticsLogger.info("{} requests sent, {} expected", overallSentRequests, overallRequests);
		overallSentRequests = overallRequests - Math.max(0,  overallResponsesDownCounter.get());
		statisticsLogger.info("{} requests in {} ms{}", overallSentRequests,
				TimeUnit.NANOSECONDS.toMillis(timeRequestNanos),
				formatPerSecond("reqs", overallSentRequests, timeRequestNanos));
		if (overallReverseResponses > 0) {
			long overallSentReverseResponses = overallReverseResponses - overallReverseResponsesDownCounter.get();
			if (overallObservationRegistrationCounter.get() > 0) {
				statisticsLogger.info("{} notifies sent, {} expected, {} observe request", overallSentReverseResponses,
						overallReverseResponses, overallObservationRegistrationCounter.get());
				statisticsLogger.info("{} notifies sent in {} ms{}", overallSentReverseResponses,
						TimeUnit.NANOSECONDS.toMillis(timeReverseResponseNanos),
						formatPerSecond("notifies", overallSentReverseResponses, timeReverseResponseNanos));
				statisticsLogger.info("{} sent notifies could not be completed", notifiesCompleteTimeouts.get());
			} else {
				statisticsLogger.info("{} reverse-responses sent, {} expected", overallSentReverseResponses,
						overallReverseResponses);
				statisticsLogger.info("{} reverse-responses in {} ms{}", overallSentReverseResponses,
						TimeUnit.NANOSECONDS.toMillis(timeReverseResponseNanos),
						formatPerSecond("reverse-responses", overallSentReverseResponses, timeReverseResponseNanos));
			}
		}
		if (overallNotifies > 0) {
			long overallReceivedNotifies = overallNotifies - overallNotifiesDownCounter.get();
			statisticsLogger.info("{} notifies received, {} expected", overallReceivedNotifies, overallNotifies);
			statisticsLogger.info("{} notifies received in {} ms{}", overallReceivedNotifies,
					TimeUnit.NANOSECONDS.toMillis(timeNotifiesNanos),
					formatPerSecond("notifies", overallReceivedNotifies, timeNotifiesNanos));
		}
		long retransmissions = retransmissionCounter.get();
		if (retransmissions > 0) {
			statisticsLogger.info("{}",
					formatRetransmissions(retransmissions, overallSentRequests, overallSentRequests));
		}
		long transmissionErrors = transmissionErrorCounter.get();
		if (transmissionErrors > 0) {
			statisticsLogger.info("{}",
					formatTransmissionErrors(transmissionErrors, overallSentRequests, overallSentRequests));
		}
		if (overallSentRequests < overallRequests) {
			if (done) {
				statisticsLogger.info("Stale at {} messages ({}%)", overallSentRequests,
						(overallSentRequests * 100L) / overallRequests);
			} else {
				statisticsLogger.info("Interrupted at {} messages ({}%)", overallSentRequests,
						(overallSentRequests * 100L) / overallRequests);
			}
		}
		int unavailables = overallServiceUnavailable.get();
		if (unavailables > 0) {
			System.out.println(formatUnavailable(unavailables, overallSentRequests));
			long successfullRequest = overallSentRequests - unavailables;
			System.out.format("%d successful requests in %dms%s%n", successfullRequest,
					TimeUnit.NANOSECONDS.toMillis(timeRequestNanos),
					formatPerSecond("reqs", successfullRequest, timeRequestNanos));
		}

		statisticsLogger.info("connects          : {}", connectRttStatistic.getSummaryAsText());
		statisticsLogger.info("success-responses : {}", rttStatistic.getSummaryAsText());
		statisticsLogger.info("errors-responses  : {}", errorRttStatistic.getSummaryAsText());
		statisticsLogger.info("single-blocks     : {}", transmissionRttStatistic.getSummaryAsText());

		health.dump();
		if (netstat4 != null) {
			netstat4.dump();
		}
		if (netstat6 != null) {
			netstat6.dump();
		}
	}

	private static void registerShutdown() {
		LOGGER.info("register shutdown hook.");
		Runtime.getRuntime().addShutdownHook(new Thread("SHUTDOWN") {

			@Override
			public void run() {
				printResults();
			}
		});
	}

	private static String formatRetransmissions(long retransmissions, long requests, long responses) {
		try (Formatter formatter = new Formatter()) {
			if (requests > 0) {
				String amend = responses == 0 ? ", no responses received!" : "";
				return formatter.format("%d retransmissions (%4.2f%%%s)", retransmissions,
						((retransmissions * 100D) / requests), amend).toString();
			} else {
				return formatter.format("%d retransmissions", retransmissions).toString();
			}
		}
	}

	private static String formatTransmissionErrors(long transmissionErrors, long requests, long responses) {
		try (Formatter formatter = new Formatter()) {
			if (requests > 0) {
				String amend = responses == 0 ? ", no responses received!" : "";
				return formatter.format("%d transmission errors (%4.2f%%%s)", transmissionErrors,
						((transmissionErrors * 100D) / requests), amend).toString();
			} else {
				return formatter.format("%d transmission errors", transmissionErrors).toString();
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
				return formatter.format("%d hono-cmds (%4.2f%%)", honoCmds, ((honoCmds * 100D) / requests)).toString();
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
