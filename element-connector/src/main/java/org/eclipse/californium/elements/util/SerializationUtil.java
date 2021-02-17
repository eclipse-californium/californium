/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility to use serialize and deserialize standard type using
 * {@link DatagramWriter} and {@link DatagramReader}.
 * 
 * @since 3.0
 */
public class SerializationUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(SerializationUtil.class);

	/**
	 * Serialization version for no items.
	 * 
	 * Must not be used as version for
	 * {@link #writeStartItem(DatagramWriter, int, int)} nor
	 * {@link #readStartItem(DataStreamReader, int, int)}.
	 */
	public static final int NO_VERSION = 0;

	/**
	 * Serialization version for {@link InetSocketAddress}.
	 */
	private static final int ADDRESS_VERSION = 1;
	/**
	 * Address type is literal.
	 */
	private static final int ADDRESS_LITERAL = 1;
	/**
	 * Address type is hostname.
	 */
	private static final int ADDRESS_NAME = 2;

	/**
	 * Serialization version for {@link Attributes}.
	 */
	private static final int ATTRIBUTES_VERSION = 1;
	/**
	 * Attribute type {@link String}.
	 */
	private static final int ATTRIBUTES_STRING = 1;
	/**
	 * Attribute type {@link Bytes}.
	 */
	private static final int ATTRIBUTES_BYTES = 2;
	/**
	 * Attribute type {@link Integer}.
	 */
	private static final int ATTRIBUTES_INTEGER = 3;
	/**
	 * Attribute type {@link Long}.
	 */
	private static final int ATTRIBUTES_LONG = 4;
	/**
	 * Serialization version for nanotime synchronization mark.
	 */
	private static final int NANOTIME_SNYC_MARK_VERSION = 1;

	/**
	 * Write no item to output stream.
	 * 
	 * @param out output stream.
	 * @throws IOException if an i/o error occurred
	 * @see #NO_VERSION
	 */
	public static void writeNoItem(OutputStream out) throws IOException {
		out.write(NO_VERSION);
	}

	/**
	 * Write no item to writer.
	 * 
	 * @param writer writer
	 * @see #NO_VERSION
	 */
	public static void writeNoItem(DatagramWriter writer) {
		writer.writeByte((byte) NO_VERSION);
	}

	/**
	 * Write start of item.
	 * 
	 * @param writer writer
	 * @param version version of item's serialization
	 * @param numBits number of bits for the item length
	 * @return position of the item length
	 * @see #writeFinishedItem(DatagramWriter, int, int)
	 */
	public static int writeStartItem(DatagramWriter writer, int version, int numBits) {
		if (version == NO_VERSION) {
			throw new IllegalArgumentException("version must not be " + NO_VERSION + "!");
		}
		writer.writeByte((byte) version);
		return writer.space(numBits);
	}

	/**
	 * Write finished.
	 * 
	 * @param writer writer
	 * @param position position returned by
	 *            {@link #writeStartItem(DatagramWriter, int, int)}.
	 * @param numBits number of bits for the item length used for
	 *            {@link #writeStartItem(DatagramWriter, int, int)}.
	 * @see #writeStartItem(DatagramWriter, int, int)
	 */
	public static void writeFinishedItem(DatagramWriter writer, int position, int numBits) {
		writer.writeSize(position, numBits);
	}

	/**
	 * Read item start.
	 * 
	 * @param reader reader
	 * @param version version of item's serialization
	 * @param numBits number of bits for the item length
	 * @return length of the item, or {@code -1}, if
	 *         {@link #writeNoItem(DatagramWriter)} was used.
	 * @throws IllegalArgumentException if version doesn't match or the read
	 *             length exceeds the available bytes.
	 * @see #writeStartItem(DatagramWriter, int, int)
	 * @see #writeFinishedItem(DatagramWriter, int, int)
	 */
	public static int readStartItem(DataStreamReader reader, int version, int numBits) {
		if (version == NO_VERSION) {
			throw new IllegalArgumentException("version must not be " + NO_VERSION + "!");
		}
		int read = reader.readNextByte() & 0xff;
		if (read == NO_VERSION) {
			return -1;
		} else if (read != version) {
			throw new IllegalArgumentException("Version mismatch! " + version + " is required, not " + read);
		}
		return reader.read(numBits);
	}

	/**
	 * Write {@link String} using {@link StandardCharsets#UTF_8}.
	 * 
	 * @param writer writer to write to.
	 * @param value value to write.
	 * @param numBits number of bits for encoding the length.
	 * @see #readString(DataStreamReader, int)
	 */
	public static void write(DatagramWriter writer, String value, int numBits) {
		writer.writeVarBytes(value == null ? null : value.getBytes(StandardCharsets.UTF_8), numBits);
	}

	/**
	 * Read {@link String} using {@link StandardCharsets#UTF_8}.
	 * 
	 * @param reader reader to read
	 * @param numBits number of bits for encoding the length.
	 * @return String, or {@code null}, if size was {@code 0}.
	 * @see #write(DatagramWriter, String, int)
	 */
	public static String readString(DataStreamReader reader, int numBits) {
		byte[] data = reader.readVarBytes(numBits);
		if (data != null) {
			return new String(data, StandardCharsets.UTF_8);
		} else {
			return null;
		}
	}

	/**
	 * Write inet socket address.
	 * 
	 * @param writer writer to write to.
	 * @param address inet socket address.
	 * @see #readAddress(DataStreamReader)
	 */
	public static void write(DatagramWriter writer, InetSocketAddress address) {
		if (address == null) {
			writeNoItem(writer);
		} else {
			int position = writeStartItem(writer, ADDRESS_VERSION, Byte.SIZE);
			writer.write(address.getPort(), Short.SIZE);
			if (address.isUnresolved()) {
				writer.writeByte((byte) ADDRESS_NAME);
				writer.writeBytes(address.getHostName().getBytes(StandardCharsets.US_ASCII));
			} else {
				writer.writeByte((byte) ADDRESS_LITERAL);
				writer.writeBytes(address.getAddress().getAddress());
			}
			writeFinishedItem(writer, position, Byte.SIZE);
		}
	}

	/**
	 * Read inet socket address.
	 * 
	 * @param reader reader to read
	 * @return read inet socket address, or {@code null}, if no address was
	 *         written.
	 * @see #write(DatagramWriter, InetSocketAddress)
	 */
	public static InetSocketAddress readAddress(DataStreamReader reader) {
		int length = readStartItem(reader, ADDRESS_VERSION, Byte.SIZE);
		if (length <= 0) {
			return null;
		}
		DatagramReader rangeReader = reader.createRangeReader(length);
		int port = rangeReader.read(Short.SIZE);
		int type = rangeReader.readNextByte() & 0xff;
		byte[] address = rangeReader.readBytesLeft();
		switch (type) {
		case ADDRESS_NAME:
			return new InetSocketAddress(new String(address, StandardCharsets.US_ASCII), port);
		case ADDRESS_LITERAL:
			try {
				return new InetSocketAddress(InetAddress.getByAddress(address), port);
			} catch (UnknownHostException e) {
			}
			break;
		default:
			return null;
		}
		return null;
	}

	/**
	 * Write {@link EndpointContext} attributes.
	 * 
	 * @param writer writer
	 * @param entries attributes.
	 */
	public static void write(DatagramWriter writer, Map<String, Object> entries) {
		if (entries == null) {
			writeNoItem(writer);
		}
		int position = writeStartItem(writer, ATTRIBUTES_VERSION, Short.SIZE);
		for (Map.Entry<String, Object> entry : entries.entrySet()) {
			write(writer, entry.getKey(), Byte.SIZE);
			Object value = entry.getValue();
			if (value instanceof String) {
				writer.writeByte((byte) ATTRIBUTES_STRING);
				write(writer, (String) value, Byte.SIZE);
			} else if (value instanceof Bytes) {
				writer.writeByte((byte) ATTRIBUTES_BYTES);
				writer.writeVarBytes((Bytes) value, Byte.SIZE);
			} else if (value instanceof Integer) {
				writer.writeByte((byte) ATTRIBUTES_INTEGER);
				writer.write((Integer) value, Integer.SIZE);
			} else if (value instanceof Long) {
				writer.writeByte((byte) ATTRIBUTES_LONG);
				writer.writeLong((Long) value, Long.SIZE);
			}
		}
		writeFinishedItem(writer, position, Short.SIZE);
	}

	/**
	 * Read {@link EndpointContext} attributes.
	 * 
	 * @param reader reader
	 * @return read attributes, or {@code null}, if no attributes are written.
	 */
	public static Attributes readEndpointContexAttributes(DataStreamReader reader) {
		int length = readStartItem(reader, ATTRIBUTES_VERSION, Short.SIZE);
		if (length < 0) {
			return null;
		}
		DatagramReader rangeReader = reader.createRangeReader(length);
		Attributes attributes = new Attributes();
		while (rangeReader.bytesAvailable()) {
			String key = readString(rangeReader, Byte.SIZE);
			try {
				int type = rangeReader.readNextByte() & 0xff;
				switch (type) {
				case ATTRIBUTES_STRING:
					String stringValue = readString(rangeReader, Byte.SIZE);
					attributes.add(key, stringValue);
					break;
				case ATTRIBUTES_BYTES:
					byte[] data = rangeReader.readVarBytes(Byte.SIZE);
					attributes.add(key, new Bytes(data));
					break;
				case ATTRIBUTES_INTEGER:
					int intValue = rangeReader.read(Integer.SIZE);
					attributes.add(key, intValue);
					break;
				case ATTRIBUTES_LONG:
					long longValue = rangeReader.readLong(Long.SIZE);
					attributes.add(key, longValue);
					break;
				}
			} catch (IllegalArgumentException ex) {
				LOGGER.warn("Read attribute {}:", key, ex);
			}
		}
		return attributes;
	}

	/**
	 * Write nanotime synchronization mark.
	 * 
	 * Write {@link System#currentTimeMillis()} and
	 * {@link ClockUtil#nanoRealtime()} to align uptime with system-time on
	 * reading.
	 * 
	 * @param writer writer to write to.
	 * @see #readNanotimeSynchronizationMark(DataStreamReader)
	 */
	public static void writeNanotimeSynchronizationMark(DatagramWriter writer) {
		int position = writeStartItem(writer, NANOTIME_SNYC_MARK_VERSION, Byte.SIZE);
		long millis = System.currentTimeMillis();
		long nanos = ClockUtil.nanoRealtime();
		writer.writeLong(millis, Long.SIZE);
		writer.writeLong(nanos, Long.SIZE);
		writeFinishedItem(writer, position, Byte.SIZE);
	}

	/**
	 * Read nanotime synchronization mark.
	 * 
	 * @param reader reader to read
	 * @return delta in nanoseconds for nanotime synchronization.
	 * @throws IllegalArgumentException if version doesn't match or the read
	 *             length exceeds the available bytes.
	 * @see SerializationUtil#writeNanotimeSynchronizationMark(DatagramWriter)
	 */
	public static long readNanotimeSynchronizationMark(DataStreamReader reader) {
		int length = readStartItem(reader, NANOTIME_SNYC_MARK_VERSION, Byte.SIZE);
		if (length <= 0) {
			return 0;
		}
		DatagramReader rangeReader = reader.createRangeReader(length);
		long millis = rangeReader.readLong(Long.SIZE);
		long nanos = rangeReader.readLong(Long.SIZE);
		rangeReader.assertFinished("times");
		long startMillis = System.currentTimeMillis();
		long startNanos = ClockUtil.nanoRealtime();
		long deltaSystemtime = Math.max(TimeUnit.MILLISECONDS.toNanos(startMillis - millis), 0L);
		long deltaUptime = startNanos - nanos;
		long delta = deltaUptime - deltaSystemtime;
		return delta;
	}

	/**
	 * Skip items until "no item" is read.
	 * 
	 * Note: this "Work In Progress"; the format may change!
	 * 
	 * @param in stream to skip items.
	 */
	@WipAPI
	public static void skipItems(InputStream in, int numBits) {
		DataStreamReader reader = new DataStreamReader(in);
		while ((reader.readNextByte() & 0xff) != NO_VERSION) {
			int len = reader.read(numBits);
			reader.skip(len);
		}
	}
}
