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
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.elements.PersistentConnector;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.WipAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Save and load coap servers.
 * 
 * Currently only the dtls connections are serialized.
 * 
 * Note: this is "Work In Progress"; the stream will contain not encrypted
 * critical credentials. It is required to protect this data before exporting
 * it. The encoding of the content may also change in the future.
 * 
 * @since 3.0
 */
@WipAPI
public class ServersSerializationUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(ServersSerializationUtil.class);

	/**
	 * Load coap servers from input stream.
	 * 
	 * Reads a
	 * {@link SerializationUtil#readNanotimeSynchronizationMark(DataStreamReader)}
	 * ahead in order to synchronize the nano-uptimes.
	 * 
	 * Note: this is "Work In Progress"; the stream will contain not encrypted
	 * critical credentials. The encoding of the content may also change in the
	 * future.
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
	@WipAPI
	public static int loadServers(InputStream in, CoapServer... servers) {
		return loadServers(in, Arrays.asList(servers));
	}

	/**
	 * Load coap servers from input stream.
	 * 
	 * Reads a
	 * {@link SerializationUtil#readNanotimeSynchronizationMark(DataStreamReader)}
	 * ahead in order to synchronize the nano-uptimes.
	 * 
	 * Note: this is "Work In Progress"; the stream will contain not encrypted
	 * critical credentials. The encoding of the content may also change in the
	 * future.
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
	@WipAPI
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
	 * Writes a
	 * {@link SerializationUtil#writeNanotimeSynchronizationMark(DatagramWriter)}
	 * ahead in order to synchronize the nano-uptimes.
	 * 
	 * Note: this is "Work In Progress"; the stream will contain not encrypted
	 * critical credentials. It is required to protect this data before
	 * exporting it. The encoding of the content may also change in the future.
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
	@WipAPI
	public static int saveServers(OutputStream out, long maxQuietPeriodInSeconds, CoapServer... servers)
			throws IOException {
		return saveServers(out, maxQuietPeriodInSeconds, Arrays.asList(servers));
	}

	/**
	 * Save coap servers to output stream.
	 * 
	 * Writes a
	 * {@link SerializationUtil#writeNanotimeSynchronizationMark(DatagramWriter)}
	 * ahead in order to synchronize the nano-uptimes.
	 * 
	 * Note: this is "Work In Progress"; the stream will contain not encrypted
	 * critical credentials. It is required to protect this data before
	 * exporting it. The encoding of the content may also change in the future.
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
	@WipAPI
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
