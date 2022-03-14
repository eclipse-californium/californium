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
package org.eclipse.californium.core.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.PersistentComponent;
import org.eclipse.californium.elements.PersistentComponentProvider;
import org.eclipse.californium.elements.PersistentConnector;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.PersistentComponentUtil;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Save and load coap servers.
 * 
 * Currently only the dtls connections are serialized.
 * 
 * The coaps server are stopped before saving. And are intended to be not
 * started on loading.
 * 
 * Note: the stream will contain not encrypted critical credentials. It is
 * required to protect this data before exporting it.
 * 
 * Note: the local address is used to identify the connection. If the servers
 * are restarted on the same host, that also works, if the server uses
 * connectors on each network interface in order to overcome some IPv6 issues of
 * ambiguous outgoing addresses (see
 * <a href="https://github.com/eclipse/californium/issues/315" target=
 * "_blank">Source IP address for response returned by a COAP server created
 * with wildcard IP address</a>). If the server runs on a virtualized
 * environment, that fails. Currently you need to use the wildcard address as
 * local address.
 * 
 * @deprecated use {@link PersistentComponentUtil} instead
 * @since 3.0
 */
@Deprecated
public class ServersSerializationUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(ServersSerializationUtil.class);

	/**
	 * List of {@link CoapServer} to save and load.
	 * 
	 * @since 3.3
	 */
	private List<CoapServer> servers = new CopyOnWriteArrayList<>();

	private boolean useDeprecatedSerialization;

	protected PersistentComponentUtil persistentUtil = new PersistentComponentUtil();

	/**
	 * Create servers serialization utility.
	 * 
	 * @since 3.3
	 */
	public ServersSerializationUtil() {
		this(false);
	}

	/**
	 * Create servers serialization utility.
	 * 
	 * @param useDeprecatedSerialization {@code true}, save using the deprecated
	 *            format. Used for test only.
	 * @since 3.4
	 */
	protected ServersSerializationUtil(boolean useDeprecatedSerialization) {
		this.useDeprecatedSerialization = useDeprecatedSerialization;
	}

	/**
	 * Add coap-server to serialization list.
	 * 
	 * @param server coap-server to serialization
	 * @see #loadServers(InputStream)
	 * @see #saveServers(OutputStream, long)
	 * @since 3.3
	 */
	public void add(CoapServer server) {
		servers.add(server);
		persistentUtil.addProvider(server);
	}

	/**
	 * Update all {@link PersistentComponentProvider}s.
	 * 
	 * @return {@code true}, if at least one {@link PersistentComponent} is
	 *         available, {@code false}, if not.
	 * @since 3.4
	 */
	private boolean updateUtil() {
		persistentUtil.updateProvidersComponents();
		return !persistentUtil.isEmpty();
	}

	/**
	 * Load all added servers from input stream.
	 * 
	 * The coap-servers must not be {@link CoapServer#start()}ed before loading.
	 * 
	 * @param in input stream to read data from
	 * @see #add(CoapServer)
	 * @since 3.3
	 */
	public void loadServers(InputStream in) {
		int count = -1;
		if (updateUtil()) {
			count = persistentUtil.loadComponents(in);
		}
		if (count < 0) {
			// no items/connections loaded, retry the old deprecated format.
			loadServers(in, servers);
		}
	}

	/**
	 * Save all added servers to output stream.
	 * 
	 * The coap-servers are {@link CoapServer#stop()}ed before saving.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param out output stream to write data to
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 * @throws IOException if an i/o-error occurred
	 * @see #add(CoapServer)
	 * @since 3.3
	 */
	public void saveServers(OutputStream out, long maxQuietPeriodInSeconds) throws IOException {
		if (useDeprecatedSerialization || !updateUtil()) {
			// either test or no PersistentComponent found, use the old deprecated format.
			saveServers(out, maxQuietPeriodInSeconds, servers);
		} else {
			for (CoapServer server : servers) {
				server.stop();
			}
			persistentUtil.saveComponents(out, maxQuietPeriodInSeconds);
		}
	}

	/**
	 * Start all added servers.
	 * 
	 * @see CoapServer#start()
	 * @see #add(CoapServer)
	 * @since 3.3
	 */
	public void start() {
		for (CoapServer server : servers) {
			server.start();
		}
	}

	/**
	 * Stop all added servers.
	 * 
	 * @see CoapServer#stop()
	 * @see #add(CoapServer)
	 * @since 3.3
	 */
	public void stop() {
		for (CoapServer server : servers) {
			server.stop();
		}
	}

	/**
	 * Destroy all added servers.
	 * 
	 * @see CoapServer#destroy()
	 * @see #add(CoapServer)
	 * @since 3.3
	 */
	public void destroy() {
		for (CoapServer server : servers) {
			server.destroy();
		}
	}

	/**
	 * Load coap servers from input stream.
	 * 
	 * The coap-servers must not be {@link CoapServer#start()}ed before loading.
	 * Reads a
	 * {@link SerializationUtil#readNanotimeSynchronizationMark(DataStreamReader)}
	 * ahead in order to synchronize the nano-uptimes.
	 * 
	 * @param in input stream to load from
	 * @param servers servers to load
	 * @return number of loaded connections.
	 * @see #loadServers(InputStream, List)
	 * @see CoapServer#loadConnector(org.eclipse.californium.core.CoapServer.ConnectorIdentifier,
	 *      InputStream, long)
	 * @see CoapServer#readConnectorIdentifier(InputStream)
	 * @see PersistentConnector#loadConnections(InputStream, long)
	 */
	public static int loadServers(InputStream in, CoapServer... servers) {
		return loadServers(in, Arrays.asList(servers));
	}

	/**
	 * Load coap servers from input stream.
	 * 
	 * The coap-servers must not be {@link CoapServer#start()}ed before loading.
	 * Reads a
	 * {@link SerializationUtil#readNanotimeSynchronizationMark(DataStreamReader)}
	 * ahead in order to synchronize the nano-uptimes.
	 * 
	 * @param in input stream to load from
	 * @param servers servers to load
	 * @return number of loaded connections.
	 * @see #loadServers(InputStream, CoapServer...)
	 * @see CoapServer#loadConnector(org.eclipse.californium.core.CoapServer.ConnectorIdentifier,
	 *      InputStream, long)
	 * @see CoapServer#readConnectorIdentifier(InputStream)
	 * @see PersistentConnector#loadConnections(InputStream, long)
	 */
	public static int loadServers(InputStream in, List<CoapServer> servers) {
		int count = 0;
		long time = System.nanoTime();
		List<CoapServer.ConnectorIdentifier> failed = new ArrayList<>();
		try {
			DataStreamReader reader = new DataStreamReader(in);
			long delta = SerializationUtil.readNanotimeSynchronizationMark(reader);
			CoapServer.ConnectorIdentifier id;
			while ((id = CoapServer.readConnectorIdentifier(in)) != null) {
				boolean foundTag = false;
				int loaded = -1;
				for (CoapServer server : servers) {
					if (id.tag.equals(server.getTag())) {
						foundTag = true;
						loaded = server.loadConnector(id, in, delta);
						if (loaded >= 0) {
							count += loaded;
							break;
						}
					}
				}
				if (foundTag) {
					if (loaded < 0) {
						int skip = SerializationUtil.skipItems(new DataStreamReader(in), Short.SIZE);
						LOGGER.warn("{}loading {} failed, {} connections skipped, no connector in {} servers!", id.tag,
								id.uri, skip, servers.size());
						failed.add(id);
					} else {
						LOGGER.info("{}loading {}, {} connections, {} servers.", id.tag, id.uri, loaded,
								servers.size());
					}
				} else {
					int skip = SerializationUtil.skipItems(new DataStreamReader(in), Short.SIZE);
					LOGGER.warn("{}loading {} failed, {} connections skipped, no server in {} servers!", id.tag, id.uri,
							skip, servers.size());
					failed.add(id);
				}
			}
		} catch (IllegalArgumentException e) {
			LOGGER.warn("loading failed:", e);
		} catch (IOException e) {
			LOGGER.warn("loading failed:", e);
		}
		if (!failed.isEmpty()) {
			LOGGER.warn("Loading failures:");
			for (int index = 0; index < failed.size(); ++index) {
				LOGGER.warn("[CON {}] {}", index, failed.get(index));
			}
			int index2 = 0;
			for (CoapServer server : servers) {
				List<Endpoint> endpoints = server.getEndpoints();
				for (Endpoint endpoint : endpoints) {
					if (endpoint instanceof CoapEndpoint) {
						Connector connector = ((CoapEndpoint) endpoint).getConnector();
						if (connector instanceof PersistentConnector) {
							LOGGER.warn("[SRV {}] {}{}", index2, server.getTag(), endpoint.getUri().toASCIIString());
							++index2;
						}
					}
				}
			}
		}
		time = System.nanoTime() - time;
		LOGGER.info("load: {} ms, {} connections", TimeUnit.NANOSECONDS.toMillis(time), count);
		return count;
	}

	/**
	 * Save coap servers to output stream.
	 * 
	 * The coap-servers are {@link CoapServer#stop()}ed before saving. A
	 * {@link SerializationUtil#writeNanotimeSynchronizationMark(DatagramWriter)}
	 * is written ahead in order to synchronize the nano-uptimes.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param out output stream
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 * @param servers servers to save
	 * @return number of saved connections
	 * @throws IOException if an i/o error occurred
	 * @see #saveServers(OutputStream, long, List)
	 * @see CoapServer#saveAllConnectors(OutputStream, long)
	 * @see PersistentConnector#saveConnections(OutputStream, long)
	 */
	public static int saveServers(OutputStream out, long maxQuietPeriodInSeconds, CoapServer... servers)
			throws IOException {
		return saveServers(out, maxQuietPeriodInSeconds, Arrays.asList(servers));
	}

	/**
	 * Save coap servers to output stream.
	 * 
	 * The coap-servers are {@link CoapServer#stop()}ed before saving. A
	 * {@link SerializationUtil#writeNanotimeSynchronizationMark(DatagramWriter)}
	 * is written ahead in order to synchronize the nano-uptimes.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param out output stream
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 * @param servers servers to save
	 * @return number of saved connections
	 * @throws IOException if an i/o error occurred
	 * @see #saveServers(OutputStream, long, CoapServer...)
	 * @see CoapServer#saveAllConnectors(OutputStream, long)
	 * @see PersistentConnector#saveConnections(OutputStream, long)
	 */
	public static int saveServers(OutputStream out, long maxQuietPeriodInSeconds, List<CoapServer> servers)
			throws IOException {
		int count = 0;
		for (CoapServer server : servers) {
			server.stop();
		}
		long start = System.nanoTime();
		DatagramWriter writer = new DatagramWriter();
		SerializationUtil.writeNanotimeSynchronizationMark(writer);
		writer.writeTo(out);
		for (CoapServer server : servers) {
			count += server.saveAllConnectors(out, maxQuietPeriodInSeconds);
		}
		SerializationUtil.write(writer, (String) null, Byte.SIZE);
		writer.writeTo(out);
		long time = System.nanoTime() - start;
		LOGGER.info("save: {} ms, {} connections", TimeUnit.NANOSECONDS.toMillis(time), count);
		return count;
	}

}
