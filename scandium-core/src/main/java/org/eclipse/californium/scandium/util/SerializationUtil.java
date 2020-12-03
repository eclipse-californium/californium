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
package org.eclipse.californium.scandium.util;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StandardCharsets;

/**
 * Utility to use serialize and deserialize standard type using
 * {@link DatagramWriter} and {@link DatagramReader}.
 * 
 * @since 3.0
 */
public class SerializationUtil {

	/**
	 * Write {@link String} using {@link StandardCharsets#UTF_8}.
	 * 
	 * @param writer writer to write to.
	 * @param String value to write.
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
		if (address == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.writeVarBytes(address.getAddress().getAddress(), Byte.SIZE);
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
		byte[] data = reader.readVarBytes(Byte.SIZE);
		if (data != null) {
			int port = reader.read(Short.SIZE);
			try {
				InetAddress address = InetAddress.getByAddress(data);
				return new InetSocketAddress(address, port);
			} catch (UnknownHostException e) {
			}
		}
		return null;
	}

	/**
	 * Write secret key.
	 * 
	 * @param writer writer to write to.
	 * @param key secret key to write
	 */
	public static void write(DatagramWriter writer, SecretKey key) {
		if (key == null || SecretUtil.isDestroyed(key)) {
			writer.write(0, Byte.SIZE);
		} else {
			byte[] encoded = key.getEncoded();
			writer.writeVarBytes(encoded, Byte.SIZE);
			Bytes.clear(encoded);
			write(writer, key.getAlgorithm(), Byte.SIZE);
		}
	}

	/**
	 * Read secret key.
	 * 
	 * @param reader reader to read
	 * @return read secret key, or {@code null}, if size was {@code 0}.
	 */
	public static SecretKey readSecretKey(DatagramReader reader) {
		byte[] data = reader.readVarBytes(Byte.SIZE);
		if (data != null) {
			String algo = readString(reader, Byte.SIZE);
			SecretKey key = SecretUtil.create(data, algo.intern());
			Bytes.clear(data);
			return key;
		} else {
			return null;
		}
	}

	/**
	 * Write iv.
	 * 
	 * @param writer writer to write to.
	 * @param iv iv to write.
	 */
	public static void write(DatagramWriter writer, SecretIvParameterSpec iv) {
		if (iv == null || SecretUtil.isDestroyed(iv)) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(iv.size(), Byte.SIZE);
			iv.writeTo(writer);
		}
	}

	/**
	 * Read iv.
	 * 
	 * @param reader reader to read
	 * @return read iv, or {@code null}, if size was {@code 0}.
	 */
	public static SecretIvParameterSpec readIv(DatagramReader reader) {
		byte[] data = reader.readVarBytes(Byte.SIZE);
		if (data != null) {
			SecretIvParameterSpec iv = SecretUtil.createIv(data);
			Bytes.clear(data);
			return iv;
		} else {
			return null;
		}
	}

}
