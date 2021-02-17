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

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.SerializationUtil;

/**
 * Utility to use serialize and deserialize standard type using
 * {@link DatagramWriter} and {@link DatagramReader}.
 * 
 * @since 3.0
 */
public class SecretSerializationUtil {

	/**
	 * Write secret key.
	 * 
	 * @param writer writer to write to.
	 * @param key secret key to write
	 */
	public static void write(DatagramWriter writer, SecretKey key) {
		if (key == null || SecretUtil.isDestroyed(key)) {
			writer.writeVarBytes((byte[]) null, Byte.SIZE);
		} else {
			byte[] encoded = key.getEncoded();
			writer.writeVarBytes(encoded, Byte.SIZE);
			Bytes.clear(encoded);
			SerializationUtil.write(writer, key.getAlgorithm(), Byte.SIZE);
		}
	}

	/**
	 * Read secret key.
	 * 
	 * @param reader reader to read
	 * @return read secret key, or {@code null}, if {@code null} was written.
	 * @throws IllegalArgumentException if the data is erroneous
	 */
	public static SecretKey readSecretKey(DatagramReader reader) {
		SecretKey key = null;
		byte[] data = reader.readVarBytes(Byte.SIZE);
		if (data != null) {
			if (data.length == 0) {
				throw new IllegalArgumentException("key must not be empty!");
			}
			try {
				String algo = SerializationUtil.readString(reader, Byte.SIZE);
				if (algo == null) {
					throw new IllegalArgumentException("key must have algorithm!");
				}
				key = SecretUtil.create(data, algo.intern());
			} finally {
				Bytes.clear(data);
			}
		}
		return key;
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
