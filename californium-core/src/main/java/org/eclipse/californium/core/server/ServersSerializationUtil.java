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
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.elements.PersistentConnector;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
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
 * @since 3.0
 */
public class ServersSerializationUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(ServersSerializationUtil.class);

	/**
	 * List of {@link CoapServer} to save and load.
	 * 
	 * @since 3.3
	 */
	private List<CoapServer> servers = new CopyOnWriteArrayList<>();

	/**
	 * Create servers serialization utility.
	 * 
	 * @since 3.3
	 */
	public ServersSerializationUtil() {

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
		loadServers(in, servers);
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
		saveServers(out, maxQuietPeriodInSeconds, servers);
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
						LOGGER.warn("{}loading {} failed, no connector in {} servers!", id.tag, id.uri, servers.size());
						SerializationUtil.skipItems(in, Short.SIZE);
					} else {
						LOGGER.info("{}loading {}, {} connections, {} servers.", id.tag, id.uri, loaded,
								servers.size());
					}
				} else {
					SerializationUtil.skipItems(in, Short.SIZE);
				}
			}
		} catch (IllegalArgumentException e) {
			LOGGER.warn("loading failed:", e);
		} catch (IOException e) {
			LOGGER.warn("loading failed:", e);
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
