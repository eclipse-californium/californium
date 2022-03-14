/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.PersistentComponent;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@link PersistentComponentUtil} and
 * {@link EncryptedPersistentComponentUtil}.
 * 
 * @since 3.4
 */
@Category(Medium.class)
public class PersistentComponentUtilTest {

	@Rule
	public LoggingRule logging = new LoggingRule();

	private DummyComponent connector1 = new DummyComponent("5684");
	private DummyComponent connector2 = new DummyComponent("5784");
	private DummyComponent connector3 = new DummyComponent("5884");
	private DummyComponent connector4 = new DummyComponent("5984");

	private EncryptedPersistentComponentUtil setup(PersistentComponent... connectors) {
		EncryptedPersistentComponentUtil util = new EncryptedPersistentComponentUtil();
		for (PersistentComponent connector : connectors) {
			util.add(connector);
		}
		return util;
	}

	@Test
	public void testSaveAndLoad() throws IOException {
		PersistentComponentUtil util = setup(connector1, connector2);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util.loadComponents(in);
		assertArrayEquals(connector1.mark, connector1.data);
		assertArrayEquals(connector2.mark, connector2.data);
	}

	@Test
	public void testSaveSkipAndLoad() throws IOException {
		PersistentComponentUtil util = setup(connector1, connector2);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util = setup(connector2);
		util.loadComponents(in);
		assertThat(connector1.data, is(nullValue()));
		assertArrayEquals(connector2.mark, connector2.data);
	}

	@Test
	public void testSaveLoadAndSkip() throws IOException {
		PersistentComponentUtil util = setup(connector1, connector2);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util = setup(connector1);
		util.loadComponents(in);
		assertArrayEquals(connector1.mark, connector1.data);
		assertThat(connector2.data, is(nullValue()));
	}

	@Test
	public void testEncryptedSaveAndLoad() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector2);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, key, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util.loadComponents(in, key);
		assertArrayEquals(connector1.mark, connector1.data);
		assertArrayEquals(connector2.mark, connector2.data);
	}

	@Test
	public void testEncryptedSaveSkipAndLoad() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector2);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, key, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util = setup(connector2);
		util.loadComponents(in, key);
		assertThat(connector1.data, is(nullValue()));
		assertArrayEquals(connector2.mark, connector2.data);
	}

	@Test
	public void testEncryptedSaveLoadAndSkip() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector2);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, key, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util = setup(connector1);
		util.loadComponents(in, key);
		assertArrayEquals(connector1.mark, connector1.data);
		assertThat(connector2.data, is(nullValue()));
	}

	@Test
	public void testEncryptedSaveLoadSkipAndLoad() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector2, connector3);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, key, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util = setup(connector1, connector3);
		util.loadComponents(in, key);
		assertArrayEquals(connector1.mark, connector1.data);
		assertThat(connector2.data, is(nullValue()));
	}

	@Test
	public void testEncryptedSaveAndLoadWrongKey() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector2);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, key, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		key = new SecretKeySpec("01234567".getBytes(), "PW");
		logging.setLoggingLevel("ERROR", PersistentComponentUtil.class);
		util.loadComponents(in, key);
		assertThat(connector1.data, is(nullValue()));
		assertThat(connector2.data, is(nullValue()));
	}

	@Test
	public void testEncryptedSaveAndUnencryptedLoad() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector2);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, key, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		logging.setLoggingLevel("ERROR", PersistentComponentUtil.class);
		util.loadComponents(in);
		assertThat(connector1.data, is(nullValue()));
		assertThat(connector2.data, is(nullValue()));
	}

	@Test
	public void testUnencryptedSaveAndEncryptedLoad() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector2);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		logging.setLoggingLevel("ERROR", PersistentComponentUtil.class);
		util.loadComponents(in, key);
		assertThat(connector1.data, is(nullValue()));
		assertThat(connector2.data, is(nullValue()));
	}

	@Test
	public void testEncryptedSaveAndLoadWithLabel() throws IOException {
		EncryptedPersistentComponentUtil util = setup(connector1, connector4);
		SecretKey key = new SecretKeySpec("1234567".getBytes(), "PW");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		util.saveComponents(out, key, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		util.loadComponents(in, key);
		assertArrayEquals(connector1.mark, connector1.data);
		assertArrayEquals(connector4.mark, connector4.data);
	}

	private static class DummyComponent implements PersistentComponent {

		private String label;

		private byte[] mark;

		private byte[] data;

		private DummyComponent(String label) {
			this.label = label;
			this.mark = String.format("dummy-%sd", label).getBytes(StandardCharsets.UTF_8);
		}

		@Override
		public String getLabel() {
			return label;
		}

		@Override
		public int save(OutputStream out, long maxQuietPeriodInSeconds) throws IOException {
			DatagramWriter writer = new DatagramWriter();
			int pos = SerializationUtil.writeStartItem(writer, 1, Short.SIZE);
			writer.writeVarBytes(mark, Byte.SIZE);
			SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
			writer.writeTo(out);
			pos = SerializationUtil.writeStartItem(writer, 1, Short.SIZE);
			writer.writeVarBytes(mark, Byte.SIZE);
			SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
			writer.writeTo(out);
			pos = SerializationUtil.writeStartItem(writer, 1, Short.SIZE);
			writer.writeVarBytes(mark, Byte.SIZE);
			SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE);
			writer.writeTo(out);
			SerializationUtil.writeNoItem(out);
			return 3;
		}

		@Override
		public int load(InputStream in, long delta) throws IOException {
			DataStreamReader reader = new DataStreamReader(in);
			SerializationUtil.readStartItem(reader, 1, Short.SIZE);
			data = reader.readVarBytes(Byte.SIZE);
			int len = SerializationUtil.readStartItem(reader, 1, Short.SIZE);
			SerializationUtil.skipBits(reader, len * Byte.SIZE);
			len = SerializationUtil.readStartItem(reader, 1, Short.SIZE);
			SerializationUtil.skipBits(reader, len * Byte.SIZE);
			int version = reader.readNextByte() & 0xff;
			assertThat(version, is(SerializationUtil.NO_VERSION));
			return 3;
		}

	}

}
