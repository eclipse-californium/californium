/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove duplicated
 *                                                    endpoints destroy
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util and
 *                                                    add a detached executor
 ******************************************************************************/
package org.eclipse.californium.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.observe.ObserveHealth;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerInterface;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.ServersSerializationUtil;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.DiscoveryResource;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.PersistentComponent;
import org.eclipse.californium.elements.PersistentComponentProvider;
import org.eclipse.californium.elements.PersistentConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An execution environment for CoAP {@link Resource}s.
 * 
 * A server hosts a tree of {@link Resource}s which are exposed to clients by
 * means of one or more {@link Endpoint}s which are bound to a network
 * interface.
 * 
 * A server can be started and stopped. When the server stops the endpoint frees
 * the port it is listening on, but keeps the executors running to resume.
 * <p>
 * The following code snippet provides an example of a server with a resource
 * that responds with a <em>"hello world"</em> to any incoming GET request.
 * 
 * <pre>
 * CoapServer server = new CoapServer(port);
 * server.add(new CoapResource(&quot;hello-world&quot;) {
 * 
 * 	public void handleGET(CoapExchange exchange) {
 * 		exchange.respond(ResponseCode.CONTENT, &quot;hello world&quot;);
 * 	}
 * });
 * server.start();
 * </pre>
 * 
 * The following figure shows the server's basic architecture.
 * 
 * <pre>
 * +------------------------------------- CoapServer --------------------------------------+
 * |                                                                                       |
 * |                               +-----------------------+                               |
 * |                               |    MessageDeliverer   +--&gt; (Resource Tree)            |
 * |                               +---------A-A-A---------+                               |
 * |                                         | | |                                         |
 * |                                         | | |                                         |
 * |                 .--------&gt;&gt;&gt;------------' | '--------&lt;&lt;&lt;------------.                 |
 * |                /                          |                          \                |
 * |               |                           |                           |               |
 * |             * A                         * A                         * A               |
 * | +-----------------------+   +-----------------------+   +-----------------------+     |
 * | |        Endpoint       |   |        Endpoint       |   |      Endpoint         |     |
 * | +-----------------------+   +-----------------------+   +-----------------------+     |
 * +------------v-A--------------------------v-A-------------------------v-A---------------+
 *              v A                          v A                         v A            
 *              v A                          v A                         v A         
 *           (Network)                    (Network)                   (Network)
 * </pre>
 * 
 * @see MessageDeliverer
 * @see Endpoint
 **/
@SuppressWarnings("deprecation")
public class CoapServer implements ServerInterface, PersistentComponentProvider {

	/**
	 * Start mark for connections in stream.
	 * 
	 * @since 3.0
	 */
	private static final String MARK = "CoAP";

	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(CoapServer.class);

	/** The root resource. */
	private final Resource root;

	/** The configuration used by this server. */
	private final Configuration config;

	/** The message deliverer. */
	private MessageDeliverer deliverer;
	/**
	 * Observe health status.
	 * 
	 * @since 3.6
	 */
	private ObserveHealth observeHealth;

	/** The list of endpoints the server connects to the network. */
	private final List<Endpoint> endpoints = new CopyOnWriteArrayList<>();

	private final List<EndpointObserver> defaultObservers = new CopyOnWriteArrayList<>();

	private final List<CounterStatisticManager> statistics = new CopyOnWriteArrayList<>();

	/** The executor of the server for its endpoints (can be null). */
	private ScheduledExecutorService executor;

	/**
	 * Scheduled executor intended to be used for rare executing timers (e.g.
	 * cleanup tasks).
	 */
	private ScheduledExecutorService secondaryExecutor;
	/**
	 * Indicate, it the server-specific executor service is detached, or
	 * shutdown with this server.
	 */
	private boolean detachExecutor;

	private volatile boolean running;

	private volatile String tag;

	/**
	 * Constructs a server with the default configuration
	 * {@link Configuration#getStandard()}.
	 * 
	 * The server starts after the method {@link #start()} is called. If the
	 * server is started without assigned {@link Endpoint}s, a default coap
	 * endpoint is created using the value of {@link CoapConfig#COAP_PORT} from
	 * the {@link Configuration#getStandard()} as port, default {@code 5683}.
	 * 
	 * @see Configuration#getStandard()
	 */
	public CoapServer() {
		this(Configuration.getStandard());
	}

	/**
	 * Constructs a server with the default configuration
	 * {@link Configuration#getStandard()} and listens to the specified port(s)
	 * after method {@link #start()} is called.
	 * 
	 * @param ports the ports to bind to. If empty or {@code null} and no
	 *            endpoints are added with {@link #addEndpoint(Endpoint)}, it
	 *            will bind to CoAP's port configured in the default
	 *            configuration with {@link CoapConfig#COAP_PORT}, default
	 *            {@code 5683}, on {@link #start()}.
	 * @see Configuration#getStandard()
	 */
	public CoapServer(final int... ports) {
		this(Configuration.getStandard(), ports);
	}

	/**
	 * Constructs a server with the specified configuration that listens to the
	 * specified ports after method {@link #start()} is called.
	 *
	 * @param config the configuration, if {@code null} the configuration
	 *            returned by {@link Configuration#getStandard()} is used.
	 * @param ports the ports to bind to. If empty or {@code null} and no
	 *            endpoints are added with {@link #addEndpoint(Endpoint)}, it
	 *            will bind to CoAP's port configured in the provided
	 *            configuration with {@link CoapConfig#COAP_PORT}, default
	 *            {@code 5683}, on {@link #start()}.
	 * @since 3.0 (changed parameter to Configuration)
	 * @see Configuration#getStandard()
	 */
	public CoapServer(final Configuration config, final int... ports) {
		// global configuration that is passed down (can be observed for
		// changes)
		if (config != null) {
			this.config = config;
		} else {
			this.config = Configuration.getStandard();
		}
		setTag(null);
		// resources
		this.root = createRoot();
		this.deliverer = new ServerMessageDeliverer(root, config);

		CoapResource wellKnown = new CoapResource(".well-known");
		wellKnown.setVisible(false);
		wellKnown.add(new DiscoveryResource(root));
		root.add(wellKnown);

		// endpoints
		// create endpoint for each port
		if (ports != null) {
			for (int port : ports) {
				CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
				builder.setPort(port);
				builder.setConfiguration(config);
				addEndpoint(builder.build());
			}
		}
	}

	/**
	 * Set version for root resource.
	 * 
	 * @param version version to include in root resource
	 * @since 3.4
	 */
	public void setVersion(String version) {
		if (root instanceof RootResource) {
			((RootResource) root).setVersion(version);
		}
	}

	public synchronized void setExecutors(final ScheduledExecutorService mainExecutor,
			final ScheduledExecutorService secondaryExecutor, final boolean detach) {
		if (mainExecutor == null || secondaryExecutor == null) {
			throw new NullPointerException("executors must not be null");
		}
		if (this.executor == mainExecutor && this.secondaryExecutor == secondaryExecutor) {
			return;
		}
		if (running) {
			throw new IllegalStateException("executor service can not be set on running server");
		}

		if (!this.detachExecutor) {
			if (this.executor != null) {
				this.executor.shutdownNow();
			}
			if (this.secondaryExecutor != null) {
				this.secondaryExecutor.shutdownNow();
			}
		}
		this.executor = mainExecutor;
		this.secondaryExecutor = secondaryExecutor;
		this.detachExecutor = detach;
		for (Endpoint ep : endpoints) {
			ep.setExecutors(this.executor, this.secondaryExecutor);
		}
	}

	@Override
	public boolean isRunning() {
		return running;
	}

	/**
	 * Starts the server by starting all endpoints this server is assigned to.
	 * Each endpoint binds to its port. If no endpoint is assigned to the
	 * server, an endpoint is started on the port defined in the config.
	 */
	@Override
	public synchronized void start() {

		if (running) {
			return;
		}

		LOGGER.info("{}Starting server", getTag());

		if (executor == null) {
			// sets the central thread pool for the protocol stage over all
			// endpoints
			setExecutors(ExecutorsUtil.newScheduledThreadPool(//
					this.config.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT),
					new NamedThreadFactory("CoapServer(main)#")), //$NON-NLS-1$
					ExecutorsUtil.newDefaultSecondaryScheduler("CoapServer(secondary)#"), false);
		}

		if (endpoints.isEmpty()) {
			// servers should bind to the configured port (while clients should
			// use an ephemeral port through the default endpoint)
			int port = config.get(CoapConfig.COAP_PORT);
			LOGGER.info("{}no endpoints have been defined for server, setting up server endpoint on default port {}",
					getTag(), port);
			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			builder.setPort(port);
			builder.setConfiguration(config);
			addEndpoint(builder.build());
		}

		int started = 0;
		for (Endpoint ep : endpoints) {
			try {
				ep.start();
				// only reached on success
				++started;
			} catch (IOException e) {
				LOGGER.error("{}cannot start server endpoint [{}]", getTag(), ep.getAddress(), e);
			}
		}
		if (started == 0) {
			throw new IllegalStateException("None of the server endpoints could be started");
		} else {
			running = true;
		}
	}

	/**
	 * Stops the server.
	 * 
	 * I.e., unbinds it from all ports. Frees as much system resources as
	 * possible to still be able to be re-started with the previous binds. To
	 * free all system resources {@link #destroy()} must be called!
	 */
	@Override
	public synchronized void stop() {

		if (running) {
			running = false;
			LOGGER.info("{}Stopping server ...", getTag());
			for (Endpoint ep : endpoints) {
				ep.stop();
			}
			LOGGER.info("{}Stopped server.", getTag());
		}
	}

	/**
	 * Destroys the server.
	 * 
	 * I.e., unbinds from all ports and frees all system
	 * resources.
	 */
	@Override
	public synchronized void destroy() {
		LOGGER.info("{}Destroying server", getTag());
		// prevent new tasks from being submitted
		try {
			if (!detachExecutor)
				if (running) {
					ExecutorsUtil.shutdownExecutorGracefully(2000, executor, secondaryExecutor);
				} else {
					if (executor != null) {
						executor.shutdownNow();
					}
					if (secondaryExecutor != null) {
						secondaryExecutor.shutdownNow();
					}
				}
		} finally {
			for (Endpoint ep : endpoints) {
				ep.destroy();
			}
			LOGGER.info("{}CoAP server has been destroyed", getTag());
			running = false;
		}
	}

	/**
	 * Sets the message deliverer.
	 *
	 * @param deliverer the new message deliverer
	 */
	public void setMessageDeliverer(final MessageDeliverer deliverer) {
		if (this.deliverer instanceof ServerMessageDeliverer && this.deliverer != deliverer) {
			((ServerMessageDeliverer) this.deliverer).setObserveHealth(null);
		}
		this.deliverer = deliverer;
		for (Endpoint endpoint : endpoints) {
			endpoint.setMessageDeliverer(deliverer);
		}
		setObserveHealth(observeHealth);
	}

	/**
	 * Gets the message deliverer.
	 *
	 * @return the message deliverer
	 */
	public MessageDeliverer getMessageDeliverer() {
		return deliverer;
	}

	/**
	 * Set observe health status.
	 * 
	 * @param observeHealth health status for observe.
	 * @since 3.6
	 */
	public void setObserveHealth(ObserveHealth observeHealth) {
		this.observeHealth = observeHealth;
		if (deliverer instanceof ServerMessageDeliverer) {
			((ServerMessageDeliverer) deliverer).setObserveHealth(observeHealth);
		}
	}

	/**
	 * Adds an Endpoint to the server.
	 * 
	 * WARNING: It automatically configures the default executor of the server.
	 * Endpoints that should use their own executor (e.g., to prioritize or
	 * balance request handling) either set it afterwards before starting the
	 * server or override the setExecutor() method of the special Endpoint.
	 * 
	 * @param endpoint the endpoint to add
	 */
	@Override
	public void addEndpoint(final Endpoint endpoint) {
		endpoint.setMessageDeliverer(deliverer);
		if (executor != null && secondaryExecutor != null) {
			endpoint.setExecutors(executor, secondaryExecutor);
		}
		for (EndpointObserver observer : defaultObservers) {
			endpoint.addObserver(observer);
		}
		endpoints.add(endpoint);
	}

	/**
	 * Gets the list of endpoints this server is connected to.
	 *
	 * @return the endpoints
	 */
	@Override
	public List<Endpoint> getEndpoints() {
		return endpoints;
	}

	/**
	 * Returns the endpoint with a specific port.
	 * 
	 * @param port the port
	 * @return the endpoint
	 */
	@Override
	public Endpoint getEndpoint(int port) {
		Endpoint endpoint = null;

		for (Endpoint ep : endpoints) {
			if (ep.getAddress().getPort() == port) {
				endpoint = ep;
			}
		}
		return endpoint;
	}

	@Override
	public Endpoint getEndpoint(URI uri) {
		Endpoint endpoint = null;

		for (Endpoint ep : endpoints) {
			if (uri.equals(ep.getUri())) {
				endpoint = ep;
				break;
			}
		}

		return endpoint;
	}

	/**
	 * Returns the endpoint with a specific socket address.
	 * 
	 * @param address the socket address
	 * @return the endpoint
	 */
	@Override
	public Endpoint getEndpoint(InetSocketAddress address) {
		Endpoint endpoint = null;

		for (Endpoint ep : endpoints) {
			if (address.equals(ep.getAddress())) {
				endpoint = ep;
				break;
			}
		}

		return endpoint;
	}

	@Override
	public Collection<PersistentComponent> getComponents() {
		List<PersistentComponent> components = new ArrayList<>();
		for (Endpoint endpoint : endpoints) {
			if (endpoint instanceof CoapEndpoint) {
				Connector connector = ((CoapEndpoint) endpoint).getConnector();
				if (connector instanceof PersistentComponent) {
					components.add((PersistentComponent) connector);
				}
			}
		}
		return components;
	}

	/**
	 * Add a resource to the server.
	 * 
	 * @param resources the resource(s)
	 * @return the server
	 */
	@Override
	public CoapServer add(Resource... resources) {
		for (Resource r : resources)
			root.add(r);
		return this;
	}

	@Override
	public boolean remove(Resource resource) {
		return root.delete(resource);
	}

	/**
	 * Add endpoint observer to all endpoints.
	 * 
	 * @param observer endpoint observer
	 * @since 3.1
	 */
	public void addDefaultEndpointObserver(EndpointObserver observer) {
		defaultObservers.add(observer);
		for (Endpoint ep : getEndpoints()) {
			ep.addObserver(observer);
		}
	}

	/**
	 * Remove endpoint observer from all endpoints.
	 * 
	 * @param observer endpoint observer
	 * @since 3.1
	 */
	public void removeDefaultEndpointObserver(EndpointObserver observer) {
		defaultObservers.remove(observer);
		for (Endpoint ep : getEndpoints()) {
			ep.removeObserver(observer);
		}
	}

	public void add(CounterStatisticManager statistic) {
		statistics.add(statistic);
	}

	public void remove(CounterStatisticManager statistic) {
		statistics.remove(statistic);
	}

	public void dump() {
		for (CounterStatisticManager statistic : statistics) {
			statistic.dump();
		}
	}

	/**
	 * Set server's tag.
	 * 
	 * Used for logging and as marker for persistence.
	 * 
	 * @param tag tag
	 * @since 3.0
	 */
	public void setTag(String tag) {
		this.tag = StringUtil.normalizeLoggingTag(tag);
	}

	@Override
	public String getTag() {
		return tag;
	}

	/**
	 * Save all connector's connections.
	 * 
	 * {@link #stop()}s before saving. Each entry contains the {@link #tag},
	 * followed by the {@link Endpoint#getUri()} as ASCII string.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param out output stream to write to
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 * @return number of saved connections.
	 * @throws IOException if an i/o-error occurred
	 * @see ServersSerializationUtil#saveServers(OutputStream, long, List)
	 * @see PersistentConnector#saveConnections(OutputStream, long)
	 * @since 3.0
	 */
	public int saveAllConnectors(OutputStream out, long maxQuietPeriodInSeconds) throws IOException {
		stop();
		int count = 0;
		DatagramWriter writer = new DatagramWriter();
		for (Endpoint endpoint : getEndpoints()) {
			if (endpoint instanceof CoapEndpoint) {
				Connector connector = ((CoapEndpoint) endpoint).getConnector();
				if (connector instanceof PersistentConnector) {
					SerializationUtil.write(writer, MARK, Byte.SIZE);
					SerializationUtil.write(writer, getTag(), Byte.SIZE);
					SerializationUtil.write(writer, endpoint.getUri().toASCIIString(), Byte.SIZE);
					writer.writeTo(out);
					int saved = ((PersistentConnector) connector).saveConnections(out, maxQuietPeriodInSeconds);
					count += saved;
				}
			}
		}
		return count;
	}

	/**
	 * Read connector identifier from provided input stream.
	 * 
	 * @param in input stream to read from
	 * @return connector identifier, or {@code null}, if no connector identifier
	 *         is left.
	 * @throws IOException if the stream doesn't contain a valid connector
	 *             identifier.
	 * @see #loadConnector(ConnectorIdentifier, InputStream, long)
	 * @see ServersSerializationUtil#loadServers(InputStream, List)
	 * @see PersistentConnector#loadConnections(InputStream, long)
	 * @since 3.0
	 */
	public static ConnectorIdentifier readConnectorIdentifier(InputStream in) throws IOException {
		DataStreamReader reader = new DataStreamReader(in);
		try {
			if (!SerializationUtil.verifyString(reader, MARK, Byte.SIZE)) {
				return null;
			}
		} catch (IllegalArgumentException ex) {
			LOGGER.warn("loading failed, out of sync!");
			throw new IOException(ex.getMessage() + " " + in.available() + " bytes left.");
		}

		String tag = SerializationUtil.readString(reader, Byte.SIZE);
		if (tag == null) {
			throw new IOException("Missing server's tag!");
		}
		String uri = SerializationUtil.readString(reader, Byte.SIZE);
		try {
			return new ConnectorIdentifier(tag, new URI(uri));
		} catch (URISyntaxException e) {
			LOGGER.warn("{}bad URI {}!", tag, uri, e);
			throw new IOException("Bad URI '" + uri + "'!");
		}
	}

	/**
	 * Read connections for the connector of the provided uri.
	 * 
	 * @param identifier connector's identifier
	 * @param in input stream
	 * @param delta adjust-delta for nano-uptime. In nanoseconds. The stream
	 *            contains timestamps based on nano-uptime. On loading, this
	 *            requires to adjust these timestamps according the current nano
	 *            uptime and the passed real time.
	 * @return number of read connections, {@code -1}, if no persistent
	 *         connector is available for the provided uri.
	 * @throws IOException if an i/o-error occurred
	 * @see #readConnectorIdentifier(InputStream)
	 * @see ServersSerializationUtil#loadServers(InputStream, List)
	 * @see PersistentConnector#loadConnections(InputStream, long)
	 * @since 3.0
	 */
	public int loadConnector(ConnectorIdentifier identifier, InputStream in, long delta) throws IOException {
		Endpoint endpoint = getEndpoint(identifier.uri);
		if (endpoint == null && identifier.wildcard != null) {
			// Seems, that ipv4 wildcards are not equal to ipv6 wildcards.
			// And a wildcard may be changed into the other ip version when
			// starting the connector
			for (Endpoint ep : endpoints) {
				if (identifier.matchWildcard(ep.getUri())) {
					endpoint = ep;
					break;
				}
			}
		}
		if (endpoint == null) {
			LOGGER.warn("{}connector {} not available!", getTag(), identifier.uri.toASCIIString());
			return -1;
		}
		PersistentConnector persistentConnector = null;
		if (endpoint instanceof CoapEndpoint) {
			Connector connector = ((CoapEndpoint) endpoint).getConnector();
			if (connector instanceof PersistentConnector) {
				persistentConnector = (PersistentConnector) connector;
			}
		}
		if (persistentConnector != null) {
			try {
				return persistentConnector.loadConnections(in, delta);
			} catch (IllegalArgumentException e) {
				LOGGER.warn("{}loading failed:", getTag(), e);
				return 0;
			}
		} else {
			LOGGER.warn("{}connector {} doesn't support persistence!", getTag(), identifier.uri.toASCIIString());
		}
		return -1;
	}

	/**
	 * Gets the root of this server.
	 *
	 * @return the root
	 */
	public Resource getRoot() {
		return root;
	}

	/**
	 * Get the configuration of this server.
	 * 
	 * @return the configuration
	 * @since 3.0 (changed return type to Configuration)
	 */
	public Configuration getConfig() {
		return config;
	}

	/**
	 * Creates a root for this server. Can be overridden to create another root.
	 *
	 * @return the resource
	 */
	protected Resource createRoot() {
		return new RootResource();
	}

	/**
	 * Represents the root of a resource tree.
	 */
	private class RootResource extends CoapResource {

		// get version from Maven package
		private volatile String msg;

		public RootResource() {
			super("");
			setVersion(StringUtil.CALIFORNIUM_VERSION);
		}

		private void setVersion(String version) {
			String title = "CoAP RFC 7252";
			if (version != null && !version.isEmpty()) {
				title = String.format("%s %50s", title, "Cf " + version);
			}
			title += "\n";
			StringBuilder builder = new StringBuilder()
					.append("****************************************************************\n")
					.append(title)
					.append("****************************************************************\n")
					.append("This server is using the Eclipse Californium (Cf) CoAP framework\n")
					.append("published under EPL+EDL: http://www.eclipse.org/californium/\n\n");
			String note = StringUtil.getConfiguration("COAP_ROOT_RESOURCE_NOTE");
			if (note != null) {
				builder.append(note).append("\n\n");
			}
			builder.append("(c) 2014-2023 Institute for Pervasive Computing, ETH Zurich\n" + 
			               "              and others\n");
			String footer = StringUtil.getConfiguration("COAP_ROOT_RESOURCE_FOOTER");
			if (footer != null) {
				builder.append(footer).append("\n");
			}
			builder.append("****************************************************************");
			msg = builder.toString();
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, msg);
		}

	}

	/**
	 * Connector identifier.
	 * 
	 * @since 3.0
	 */
	public static class ConnectorIdentifier {

		/**
		 * Server's tag.
		 * 
		 * @see CoapServer#setTag(String)
		 * @see CoapServer#getTag()
		 */
		public final String tag;
		/**
		 * Connectors URI.
		 */
		public final URI uri;
		/**
		 * IPv4/IPv6 wildcard address.
		 * 
		 * @since 3.4
		 */
		public final String wildcard;

		private ConnectorIdentifier(String tag, URI uri) {
			this.tag = tag;
			this.uri = uri;
			String local = uri.getHost();
			if (local.equals("0.0.0.0")) {
				wildcard = "[0:0:0:0:0:0:0:0]";
			} else if (local.equals("[0:0:0:0:0:0:0:0]")) {
				wildcard = "0.0.0.0";
			} else {
				wildcard = null;
			}
		}

		private boolean matchWildcard(URI uri) {
			if (wildcard != null) {
				if (this.uri.getScheme().equalsIgnoreCase(uri.getScheme()) && this.uri.getPort() == uri.getPort()) {
					if (wildcard.equalsIgnoreCase(uri.getHost())) {
						return true;
					}
				}
			}
			return false;
		}

		@Override
		public String toString() {
			return tag + uri.toASCIIString();
		}
	}
}
