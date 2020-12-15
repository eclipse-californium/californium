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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Map;

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

	private static final int ADDRESS_VERSION = 1;
	private static final int ADDRESS_NONE = 0;
	private static final int ADDRESS_LITERAL = 1;
	private static final int ADDRESS_NAME = 2;

	/**
	 * Version number for serialization of {@link Attributes}.
	 */
	private static final int ATTRIBUTES_VERSION = 1;
	private static final int ATTRIBUTES_STRING = 0;
	private static final int ATTRIBUTES_BYTES = 1;
	private static final int ATTRIBUTES_INTEGER = 2;
	private static final int ATTRIBUTES_LONG = 3;

	/**
	 * Write {@link String} using {@link StandardCharsets#UTF_8}.
	 * 
	 * @param writer writer to write to.
	 * @param value value to write.
	 * @param numBits number of bits for encoding the length.
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
	 */
	public static String readString(DatagramReader reader, int numBits) {
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
	 */
	public static void write(DatagramWriter writer, InetSocketAddress address) {
		writer.writeByte((byte) ADDRESS_VERSION);
		if (address == null) {
			writer.writeByte((byte) ADDRESS_NONE);
		} else {
			if (address.isUnresolved()) {
				writer.writeByte((byte) ADDRESS_NAME);
				write(writer, address.getHostName(), Byte.SIZE);
			} else {
				writer.writeByte((byte) ADDRESS_LITERAL);
				writer.writeVarBytes(address.getAddress().getAddress(), Byte.SIZE);
			}
			writer.write(address.getPort(), Short.SIZE);
		}
	}

	/**
	 * Read inet socket address.
	 * 
	 * @param reader reader to read
	 * @return read inet socket address, or {@code null}, if size was {@code 0}.
	 */
	public static InetSocketAddress readAddress(DatagramReader reader) {
		int version = reader.readNextByte() & 0xff;
		if (version != ADDRESS_VERSION) {
			throw new IllegalArgumentException("Version " + ADDRESS_VERSION + " is required! Not " + version);
		}
		String name = null;
		InetAddress address = null;
		int type = reader.readNextByte() & 0xff;
		switch (type) {
		case ADDRESS_NAME:
			name = readString(reader, Byte.SIZE);
			break;
		case ADDRESS_LITERAL:
			byte[] data = reader.readVarBytes(Byte.SIZE);
			try {
				address = InetAddress.getByAddress(data);
			} catch (UnknownHostException e) {
			}
			break;
		default:
			return null;
		}
		int port = reader.read(Short.SIZE);
		if (name != null) {
			return new InetSocketAddress(name, port);
		} else if (address != null) {
			return new InetSocketAddress(address, port);
		}
		return null;
	}

	public static void write(DatagramWriter writer, Map<String, Object> entries) {
		writer.writeByte((byte) ATTRIBUTES_VERSION);
		int position = writer.space(Short.SIZE);
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
		writer.writeSize(position, Short.SIZE);
	}

	public static Attributes readEndpointContexAttributes(DatagramReader reader) {
		int version = reader.readNextByte() & 0xff;
		if (version != ATTRIBUTES_VERSION) {
			throw new IllegalArgumentException("Version " + ATTRIBUTES_VERSION + " is required! Not " + version);
		}
		int length = reader.read(Short.SIZE);
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

}
