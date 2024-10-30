/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;

/**
 * Formatter for simple data objects.
 * 
 * @since 3.12
 */
public interface Formatter {

	/**
	 * Add a text property.
	 * 
	 * @param name name of property
	 * @param value text value of property
	 */
	void add(String name, String value);

	/**
	 * Add a number property.
	 * 
	 * @param name name of property
	 * @param value number value of property
	 */
	void add(String name, Long value);

	/**
	 * Add a boolean property.
	 * 
	 * @param name name of property
	 * @param value boolean value of property
	 */
	void add(String name, Boolean value);

	/**
	 * Add a list property.
	 * 
	 * @param name name of property
	 * @param values text values of property
	 */
	void addList(String name, String... values);

	/**
	 * Add a map property.
	 * 
	 * @param name name of property
	 * @param values text values of property
	 */
	void addMap(String name, Map<String, String> values);

	/**
	 * Get encoded payload with all properties.
	 * 
	 * @return encoded payload
	 */
	byte[] getPayload();

	/**
	 * Text formatter.
	 * 
	 * Using {@code name:value\n} lines.
	 */
	public static class Text implements Formatter {

		private StringBuilder payload = new StringBuilder();

		@Override
		public void add(String name, String value) {
			payload.append(name).append(": ").append(value).append("\n");
		}

		@Override
		public void add(String name, Long value) {
			payload.append(name).append(": ").append(value).append("\n");
		}

		@Override
		public void add(String name, Boolean value) {
			payload.append(name).append(": ").append(value).append("\n");
		}

		@Override
		public void addList(String name, String... values) {
			payload.append(name).append(": ");
			for (String value : values) {
				payload.append(value).append(",");
			}
			// remove trailing ' ' or ','
			payload.setLength(payload.length() - 1);
			payload.append("\n");
		}

		@Override
		public void addMap(String name, Map<String, String> values) {
			payload.append(name).append(": ");
			for (Map.Entry<String, String> entry : values.entrySet()) {
				payload.append(entry.getKey()).append("=").append(entry.getValue()).append(",");
			}
			// remove trailing ' ' or ','
			payload.setLength(payload.length() - 1);
			payload.append("\n");
		}

		@Override
		public byte[] getPayload() {
			return payload.toString().getBytes(StandardCharsets.UTF_8);
		}

	}

	/**
	 * CBOR formatter.
	 */
	public static class Cbor implements Formatter {

		CBORObject map = CBORObject.NewMap();

		@Override
		public void add(String name, String value) {
			map.set(name, CBORObject.FromObject(value));
		}

		@Override
		public void add(String name, Long value) {
			map.set(name, CBORObject.FromObject(value));
		}

		@Override
		public void add(String name, Boolean value) {
			map.set(name, CBORObject.FromObject(value));
		}

		@Override
		public void addList(String name, String... values) {
			CBORObject array = CBORObject.NewArray();
			for (String value : values) {
				array.Add(CBORObject.FromObject(value));
			}
			map.set(name, array);
		}

		@Override
		public void addMap(String name, Map<String, String> values) {
			CBORObject map = CBORObject.NewMap();
			for (Map.Entry<String, String> entry : values.entrySet()) {
				map.set(entry.getKey(), CBORObject.FromObject(entry.getValue()));
			}
			this.map.set(name, map);
		}

		@Override
		public byte[] getPayload() {
			return map.EncodeToBytes();
		}

	}

	/**
	 * JSON formatter.
	 */
	public static class Json implements Formatter {

		private StringBuilder payload = new StringBuilder("{\n");

		@Override
		public void add(String name, String value) {
			payload.append("  \"").append(name).append("\": \"").append(value).append("\",\n");
		}

		@Override
		public void add(String name, Long value) {
			payload.append("  \"").append(name).append("\": ").append(value).append(",\n");
		}

		@Override
		public void add(String name, Boolean value) {
			payload.append("  \"").append(name).append("\": ").append(value).append(",\n");
		}

		@Override
		public void addList(String name, String... values) {
			payload.append("  \"").append(name).append("\": [");
			if (values != null && values.length > 0) {
				for (String value : values) {
					payload.append('"').append(value).append("\",");
				}
				payload.setLength(payload.length() - 1);
			}
			payload.append("],\n");
		}

		@Override
		public void addMap(String name, Map<String, String> values) {
			payload.append("  \"").append(name).append("\": {\n");
			if (values != null && !values.isEmpty()) {
				for (Map.Entry<String, String> entry : values.entrySet()) {
					add(entry.getKey(), entry.getValue());
				}
				payload.setLength(payload.length() - 2);
				payload.append("\n");
			}
			payload.append("},\n");
		}

		@Override
		public byte[] getPayload() {
			if (payload.length() > 2) {
				// remove last ",\n"
				payload.setLength(payload.length() - 2);
				payload.append("\n}");
			} else {
				payload.append("}");
			}
			return payload.toString().getBytes(StandardCharsets.UTF_8);
		}

	}

	/**
	 * XML formatter
	 */
	public static class Xml implements Formatter {

		private StringBuilder payload = new StringBuilder();

		public Xml(String element) {
			payload.append("<").append(element).append(" ");
		}

		@Override
		public void add(String name, String value) {
			payload.append(name).append("=\"").append(value).append("\" ");
		}

		@Override
		public void add(String name, Long value) {
			payload.append(name).append("=\"").append(value).append("\" ");
		}

		@Override
		public void add(String name, Boolean value) {
			payload.append(name).append("=\"").append(value).append("\" ");
		}

		@Override
		public void addList(String name, String... values) {
			payload.append(name).append("=\"");
			for (String value : values) {
				payload.append(value).append(',');
			}
			payload.setLength(payload.length() - 1);
			payload.append("\" ");
		}

		@Override
		public void addMap(String name, Map<String, String> values) {
			payload.append(name).append(": ");
			for (Map.Entry<String, String> entry : values.entrySet()) {
				payload.append(entry.getKey()).append("=").append(entry.getValue()).append(",");
			}
			payload.setLength(payload.length() - 1);
			payload.append("\n");
		}

		@Override
		public byte[] getPayload() {
			payload.append("/>");
			return payload.toString().getBytes(StandardCharsets.UTF_8);
		}

	}

}
