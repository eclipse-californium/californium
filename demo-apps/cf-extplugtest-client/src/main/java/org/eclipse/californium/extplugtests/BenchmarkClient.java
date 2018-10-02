/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
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

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceObserver;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.extplugtests.resources.Feed;
import org.eclipse.californium.plugtests.ClientInitializer;
import org.eclipse.californium.plugtests.ClientInitializer.Arguments;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple benchmark client.
 * 
 * Starts multiple parallel clients to send CON-POST requests. Print statistic
 * with retransmissions.
 */
public class BenchmarkClient {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(BenchmarkClient.class.getCanonicalName());
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
	private static final int DEFAULT_CLIENTS = 5;
	/**
	 * Default number of requests.
	 */
	private static final int DEFAULT_REQUESTS = 100;
	/**
	 * Default number of reverse responses send by a reverse server. Used for
	 * reverse request including observes.
	 */
	private static final int DEFAULT_REVERSE_RESPONSES = 0;

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
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60 * 60 * 24); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 60 * 60 * 12); // 12h
			config.setInt(Keys.TCP_CONNECT_TIMEOUT, 5 * 1000); // 5s
			config.setInt(Keys.TCP_WORKER_THREADS, 2);
			config.setInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, 1);
			config.setInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, 1);
			config.setInt(Keys.PROTOCOL_STAGE_THREAD_COUNT, 1);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 0);
			config.setInt(KEY_BENCHMARK_CLIENT_THREADS, 0);
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
			// 24.7s instead of 247s
			config.setInt(Keys.EXCHANGE_LIFETIME, 24700);
		}
	};

	/**
	 * Benchmark timeout. If no messages are exchanged within this timeout, the
	 * benchmark is stopped.
	 */
	private static final long DEFAULT_TIMEOUT_NANOS = TimeUnit.MILLISECONDS.toNanos(10000);
	/**
	 * Atomic down-counter for overall request.
	 */
	private static final AtomicLong overallRequestsDownCounter = new AtomicLong();
	/**
	 * Done indicator for overall requests.
	 */
	private static CountDownLatch overallRequestsDone;
	/**
	 * Overall reverse responses down-counter.
	 */
	private static CountDownLatch overallReverseResponsesDownCounter;
	/**
	 * Client counter.
	 */
	private static final AtomicInteger clientCounter = new AtomicInteger();
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
	private static abstract class ResourceObserverAdapter implements ResourceObserver {

		@Override
		public void changedName(String old) {
		}

		@Override
		public void changedPath(String old) {
		}

		@Override
		public void addedChild(Resource child) {
		}

		@Override
		public void removedChild(Resource child) {
		}

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

	private class FeedObserver extends ResourceObserverAdapter {

		@Override
		public void addedObserveRelation(ObserveRelation relation) {
			super.addedObserveRelation(relation);
			observerCounter.incrementAndGet();
		}

		@Override
		public void removedObserveRelation(ObserveRelation relation) {
			super.removedObserveRelation(relation);
			int counter = observerCounter.decrementAndGet();
			if (counter == 0 && overallRequestsDownCounter.get() == 0
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
	 * Don't stop client on transmission errors.
	 */
	private static boolean noneStop;
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

	/**
	 * Create client.
	 * 
	 * @param index index of client. used for thread names.
	 * @param intervalMin minimum notifies interval in milliseconds
	 * @param intervalMax maximum notifies interval in milliseconds
	 * @param uri destination URI
	 * @param endpoint local endpoint to exchange messages
	 * @param executor
	 */
	public BenchmarkClient(int index, int intervalMin, int intervalMax, URI uri, Endpoint endpoint,
			ScheduledExecutorService executor) {
		int maxResourceSize = endpoint.getConfig().getInt(Keys.MAX_RESOURCE_BODY_SIZE);
		if (executor == null) {
			int threads = endpoint.getConfig().getInt(KEY_BENCHMARK_CLIENT_THREADS);
			executorService = ExecutorsUtil.newScheduledThreadPool(threads, threadFactory);
			shutdown = true;
		} else {
			executorService = executor;
			shutdown = false;
		}
		endpoint.addInterceptor(new MessageTracer());
		endpoint.setExecutor(executorService);
		client = new CoapClient(uri);
		server = new CoapServer(endpoint.getConfig());
		Feed feed = new Feed(CoAP.Type.NON, index, maxResourceSize, intervalMin, intervalMax, executorService,
				overallReverseResponsesDownCounter, notifiesCompleteTimeouts);
		feed.addObserver(feedObserver);
		server.add(feed);
		feed = new Feed(CoAP.Type.CON, index, maxResourceSize, intervalMin, intervalMax, executorService,
				overallReverseResponsesDownCounter, notifiesCompleteTimeouts);
		feed.addObserver(feedObserver);
		server.add(feed);
		server.setExecutor(executorService, true);
		client.setExecutor(executorService, true);
		endpoint.setExecutor(executorService);
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
		Request post = Request.newPost();
		post.setURI(client.getURI());
		try {
			CoapResponse response = client.advanced(post);
			if (response != null) {
				if (response.isSuccess()) {
					LOGGER.info("Received response: {}", response.advanced());
					clientCounter.incrementAndGet();
					requestsCounter.incrementAndGet();
					long c = overallRequestsDownCounter.decrementAndGet();
					if (c == 0) {
						overallRequestsDone.countDown();
						if (overallReverseResponsesDownCounter.getCount() == 0) {
    						stop();
    					}
					}
					return true;
				} else {
					LOGGER.warn("Received error response: {} - {}", response.advanced().getCode(), response.advanced().getPayloadString());
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
		if (overallRequestsDownCounter.getAndDecrement() > 0) {
			if (requestsCounter.get() == 0) {
				clientCounter.incrementAndGet();
			}
			final Request post = Request.newPost();
			post.setURI(client.getURI());
			post.addMessageObserver(retransmissionDetector);
			client.advanced(new CoapHandler() {

				@Override
				public void onLoad(CoapResponse response) {
					if (response.isSuccess()) {
						if (!stop.get()) {
							next();
						}
						long c = overallRequestsDownCounter.get();
						LOGGER.info("Received response: {} {}", response.advanced(), c);
					} else {
						LOGGER.warn("Received error response: {}", response.advanced());
						stop();
					}
				}

				@Override
				public void onError() {
					if (!stop.get()) {
						long c = requestsCounter.get();
						String msg = post.getSendError() == null ? "" : post.getSendError().getMessage();
						if (noneStop) {
							transmissionErrorCounter.incrementAndGet();
							LOGGER.info("Error after {} requests. {}", c, msg);
							next();
						} else {
							LOGGER.error("failed after {} requests! {}", c, msg);
							stop();
						}
					}
				}

				public void next() {
					long c = overallRequestsDownCounter.get();
					while (c > 0) {
						if (overallRequestsDownCounter.compareAndSet(c, c - 1)) {
							--c;
							break;
						}
						c = overallRequestsDownCounter.get();
					}

					if (0 < c) {
						requestsCounter.incrementAndGet();
						Request post = Request.newPost();
						post.setURI(client.getURI());
						post.addMessageObserver(retransmissionDetector);
						client.advanced(this, post);
					} else {
						overallRequestsDone.countDown();
						if (overallReverseResponsesDownCounter.getCount() == 0) {
							stop();
						}
					}
				}

			}, post);
		} else {
			overallRequestsDone.countDown();
		}
	}

	/**
	 * Stop client.
	 * 
	 * @return number of requests processed by this client.
	 */
	public int stop() {
		if (stop.compareAndSet(false, true)) {
			clientCounter.decrementAndGet();
			endpoint.stop();
			server.stop();
			if (shutdown) {
				executorService.shutdownNow();
			}
			client.shutdown();
			server.destroy();
			endpoint.destroy();
		}
		return requestsCounter.get();
	}

	public static void main(String[] args) throws InterruptedException {

		if (args.length == 0) {

			System.out.println("\nCalifornium (Cf) Benchmark Client");
			System.out.println("(c) 2018, Bosch Software Innovations GmbH and others");
			System.out.println();
			System.out.println("Usage: " + BenchmarkClient.class.getSimpleName()
					+ " URI [#clients [#requests [nonestop [#notifies]]]]");
			System.out.println("  URI       : The CoAP URI of the extended Plugtest server to test");
			System.out
					.println("              (coap://<host>[:<port>]/benchmark  or coaps://<host>[:<port>]/benchmark)");
			System.out.println("  #clients  : number of clients. Default " + DEFAULT_CLIENTS + ".");
			System.out.println("  #requests : number of requests per clients. Default " + DEFAULT_REQUESTS + ".");
			System.out.println("  nonestop  : don't stop client, if request fails (timeout).");
			System.out.println("  #reverse-responses : number of reverse-responses per clients. Default "
					+ DEFAULT_REVERSE_RESPONSES + ".");
			System.out.println("              Requires reverse requests or observes!");
			System.out.println("  minimum notifies interval : minimum interval of notifies in milliseconds. Default "
					+ Feed.DEFAULT_FEED_INTERVAL_IN_MILLIS + " [ms].");
			System.out.println("  maximum notifies interval : maximum interval of notifies in milliseconds."
					+ " Default is the minimum notifies interval.");
			System.out.println();
			System.out.println("Examples:");
			System.out.println("  " + BenchmarkClient.class.getSimpleName()
					+ " coap://localhost:5783/benchmark?rlen=200 500 2000");
			System.out.println(
					"  (Benchmark 500 clients each sending about 2000 request and the response should have 200 bytes payload.)");
			System.out.println();
			System.out.println("  " + BenchmarkClient.class.getSimpleName()
					+ " coap://localhost:5783/reverse-observe?obs=25&res=feed-CON&rlen=400 50 2 x 500 2000");
			System.out.println(
					"  (Reverse-observe benchmark using 50 clients each sending about 2 request and waiting for about 500 notifies each client.");
			System.out.println("   The notifies are sent as CON every 2000ms and have 400 bytes payload.");
			System.out.println(
					"   The default use a blocksize of 64 bytes, defined in" + REVERSE_SERVER_CONFIG_FILE + ")");
			System.out.println();
			System.out.println(
					"Note: californium.eclipse.org doesn't support a benchmark and will response with 5.01, NOT_IMPLEMENTED!");
			System.exit(-1);
		}

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		NetworkConfig serverConfig = NetworkConfig.createWithFile(REVERSE_SERVER_CONFIG_FILE,
				REVERSE_SERVER_CONFIG_HEADER, REVERSE_DEFAULTS);
		Arguments arguments = ClientInitializer.init(config, args);
		// random part of PSK identity
		SecureRandom random = new SecureRandom();
		byte[] id = new byte[8];

		URI uri = null;
		int clients = DEFAULT_CLIENTS;
		int requests = DEFAULT_REQUESTS;
		int reverseResponses = DEFAULT_REVERSE_RESPONSES;
		int intervalMin = Feed.DEFAULT_FEED_INTERVAL_IN_MILLIS;
		Integer intervalMax = null;

		switch (arguments.args.length) {
		case 6:
			intervalMax = Integer.parseInt(arguments.args[5]);
		case 5:
			intervalMin = Integer.parseInt(arguments.args[4]);
		case 4:
			reverseResponses = Integer.parseInt(arguments.args[3]);
			config = serverConfig;
		case 3:
			noneStop = arguments.args[2].equalsIgnoreCase("nonestop");
		case 2:
			requests = Integer.parseInt(arguments.args[1]);
		case 1:
			clients = Integer.parseInt(arguments.args[0]);
		}

		if (intervalMax == null) {
			intervalMax = intervalMin;
		} else if (intervalMax < intervalMin) {
			int temp = intervalMax;
			intervalMax = intervalMin;
			intervalMin = temp;
		}

		try {
			uri = new URI(arguments.uri);
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}

		int overallRequests = (requests * clients);
		int overallReverseResponses = (reverseResponses * clients);
		overallRequestsDone = new CountDownLatch(1);
		overallRequestsDownCounter.set(overallRequests);
		overallReverseResponsesDownCounter = new CountDownLatch(overallReverseResponses);

		List<BenchmarkClient> clientList = new ArrayList<>(clients);
		ScheduledExecutorService executor = ExecutorsUtil
				.newScheduledThreadPool(Runtime.getRuntime().availableProcessors(), new DaemonThreadFactory("Aux#"));

		ScheduledExecutorService connectorExecutor = config.getInt(KEY_BENCHMARK_CLIENT_THREADS) == 0 ? executor : null;
		boolean secure = CoAP.isSecureScheme(uri.getScheme());

		System.out.format("Create %d %s%sbenchmark clients, expect to send %d request overall to %s%n", clients,
				noneStop ? "none-stop " : "", secure ? "secure " : "", overallRequests, uri);

		if (overallReverseResponses > 0) {
			if (intervalMin == intervalMax) {
				System.out.format("Expect %d notifies, interval %d [ms]%n", overallReverseResponses, intervalMin);
			} else {
				System.out.format("Expect %d notifies, interval %d ... %d [ms]%n", overallReverseResponses, intervalMin,
						intervalMax);
			}
		}

		final CountDownLatch start = new CountDownLatch(clients);

		// Create & start clients
		for (int index = 0; index < clients; ++index) {
			CoapEndpoint.CoapEndpointBuilder endpointBuilder = new CoapEndpoint.CoapEndpointBuilder();
			endpointBuilder.setNetworkConfig(config);
			Arguments connectionArgs = arguments;
			if (secure) {
				random.nextBytes(id);
				String name = ClientInitializer.PSK_IDENTITY_PREFIX + ByteArrayUtils.toHex(id);
				connectionArgs = arguments.create(name, null);
			}
			CoapEndpoint coapEndpoint = ClientInitializer.createEndpoint(config, connectionArgs, connectorExecutor);
			final BenchmarkClient client = new BenchmarkClient(index, intervalMin, intervalMax, uri,
					coapEndpoint, connectorExecutor);
			clientList.add(client);
			if (index == 0) {
				// first client, so test request
				client.start();
				start.countDown();
				if (!client.test()) {
					System.out.format("Request %s POST failed, exit Benchmark.%n", uri);
					System.exit(-1);
				}
				System.out.println("Benchmark clients, first request successful.");
			} else {
				executor.execute(new Runnable() {

					@Override
					public void run() {
						client.start();
						start.countDown();
					}
				});
			}
		}
		start.await();
		System.out.println("Benchmark clients created.");

		// Start Test
		boolean stale = false;
		long requestNanos = System.nanoTime();
		long reverseResponseNanos = requestNanos;
		long lastRequestsCountDown = overallRequestsDownCounter.get();
		long lastRetransmissions = retransmissionCounter.get();
		long lastTransmissionErrrors = transmissionErrorCounter.get();

		for (BenchmarkClient client : clientList) {
			client.startBenchmark();
		}

		System.out.println("Benchmark started.");

		// Wait with timeout or all requests send.
		while (!overallRequestsDone.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
			long currentRequestsCountDown = overallRequestsDownCounter.get();
			int numberOfClients = clientCounter.get();
			long requestDifference = (lastRequestsCountDown - currentRequestsCountDown);
			long currentOverallSentRequests = overallRequests - currentRequestsCountDown;
			if ((lastRequestsCountDown == currentRequestsCountDown && currentRequestsCountDown < overallRequests)
					|| (numberOfClients == 0)) {
				// no new requests, clients are stale, or no clients left
				// adjust start time with timeout
				requestNanos += DEFAULT_TIMEOUT_NANOS;
				reverseResponseNanos = requestNanos;
				stale = true;
				System.out.format("%d requests, stale (%d clients)%n", currentOverallSentRequests, numberOfClients);
				break;
			}
			long retransmissions = retransmissionCounter.get();
			long retransmissionsDifference = retransmissions - lastRetransmissions;
			long transmissionErrors = transmissionErrorCounter.get();
			long transmissionErrorsDifference = transmissionErrors - lastTransmissionErrrors;
			lastRequestsCountDown = currentRequestsCountDown;
			lastRetransmissions = retransmissions;
			lastTransmissionErrrors = transmissionErrors;
			System.out.format("%d requests (%d reqs/s, %s, %s, %d clients)%n", currentOverallSentRequests,
					requestDifference / TimeUnit.NANOSECONDS.toSeconds(DEFAULT_TIMEOUT_NANOS),
					formatRetransmissions(retransmissionsDifference, requestDifference),
					formatTransmissionErrors(transmissionErrorsDifference, requestDifference), numberOfClients);
		}
		long overallSentRequests = overallRequests - overallRequestsDownCounter.get();
		requestNanos = System.nanoTime() - requestNanos;

		boolean observe = false;
		long lastReverseResponsesCountDown = overallReverseResponsesDownCounter.getCount();
		if (lastReverseResponsesCountDown > 0) {
			System.out.println("Requests send.");
			while (!overallReverseResponsesDownCounter.await(DEFAULT_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)) {
				long currentReverseResponsesCountDown = overallReverseResponsesDownCounter.getCount();
				int numberOfClients = clientCounter.get();
				int observers = overallObserverCounter.get();
				long reverseResponsesDifference = (lastReverseResponsesCountDown - currentReverseResponsesCountDown);
				long currentOverallReverseResponses = overallReverseResponses - currentReverseResponsesCountDown;
				if (overallObservationRegistrationCounter.get() > 0) {
					observe = true;
				}
				if ((lastReverseResponsesCountDown == currentReverseResponsesCountDown
						&& currentReverseResponsesCountDown < overallReverseResponses) || (numberOfClients == 0)) {
					// no new notifies, clients are stale, or no clients left
					// adjust start time with timeout
					reverseResponseNanos += DEFAULT_TIMEOUT_NANOS;
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
							reverseResponsesDifference / TimeUnit.NANOSECONDS.toSeconds(DEFAULT_TIMEOUT_NANOS),
							numberOfClients, observers);
				} else {
					System.out.format("%d reverse-responses (%d reverse-responses/s, %d clients)%n",
							currentOverallReverseResponses,
							reverseResponsesDifference / TimeUnit.NANOSECONDS.toSeconds(DEFAULT_TIMEOUT_NANOS),
							numberOfClients);
				}
			}
		}
		long overallSentReverseResponses = overallReverseResponses - overallReverseResponsesDownCounter.getCount();
		reverseResponseNanos = System.nanoTime() - reverseResponseNanos;

		System.out.format("%d benchmark clients %s.%n", clients, stale ? "stopped" : "finished");

		// stop and collect per client requests
		int statistic[] = new int[clients];
		for (int index = 0; index < clients; ++index) {
			BenchmarkClient client = clientList.get(index);
			statistic[index] = client.stop();
		}
		executor.shutdown();

		System.out.format("%d requests sent, %d expected%n", overallSentRequests, overallRequests);
		System.out.format("%d requests in %d ms%s%n", overallSentRequests, TimeUnit.NANOSECONDS.toMillis(requestNanos),
				formatPerSecond("reqs", overallSentRequests, requestNanos));
		if (overallReverseResponses > 0) {
			if (observe) {
				System.out.format("%d notifies sent, %d expected, %d observe requests%n", overallSentReverseResponses,
						overallReverseResponses, overallObservationRegistrationCounter.get());
				System.out.format("%d notifies in %dms%s%n", overallSentReverseResponses,
						TimeUnit.NANOSECONDS.toMillis(reverseResponseNanos),
						formatPerSecond("notifies", overallSentReverseResponses, reverseResponseNanos));
				System.out.format("%d notifies could not be completed.%n", notifiesCompleteTimeouts.get());
			} else {
				System.out.format("%d reverse-responses sent, %d expected,%n", overallSentReverseResponses,
						overallReverseResponses);
				System.out.format("%d reverse-responses in %dms%s%n", overallSentReverseResponses,
						TimeUnit.NANOSECONDS.toMillis(reverseResponseNanos),
						formatPerSecond("reverse-responses", overallSentReverseResponses, reverseResponseNanos));
			}
		}
		long retransmissions = retransmissionCounter.get();
		if (retransmissions > 0) {
			System.out.println(formatRetransmissions(retransmissions, overallSentRequests));
		}
		long transmissionErrors = transmissionErrorCounter.get();
		if (transmissionErrors > 0) {
			System.out.println(formatTransmissionErrors(transmissionErrors, overallSentRequests));
		}
		if (overallSentRequests < overallRequests) {
			System.out.format("Stale at %d messages (%d%%)%n", overallSentRequests,
					(overallSentRequests * 100L) / overallRequests);
		}
		if (1 < clients) {
			Arrays.sort(statistic);
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

	private static String formatPerSecond(String units, long requests, long nanos) {
		long millis = TimeUnit.NANOSECONDS.toMillis(nanos);
		if (millis > 0) {
			try (Formatter formatter = new Formatter()) {
				return formatter.format(", %d %s/s", (requests * 1000) / millis, units).toString();
			}
		}
		return "";
	}

	private static String formatClientRequests(int statistic[], int index, int last) {
		try (Formatter formatter = new Formatter()) {
			formatter.format("%3d clients with %d", (index - last), statistic[last]);
			if (statistic[index - 1] != statistic[last]) {
				formatter.format(" to %d", statistic[index - 1]);
			}
			return formatter.format(" requests.").toString();
		}
	}
}
