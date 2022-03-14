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
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.CipherInputStream;

import org.eclipse.californium.elements.Definition;
import org.eclipse.californium.elements.Definitions;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.exception.VersionMismatchException;
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
	 * Attribute type {@link Boolean}.
	 */
	private static final int ATTRIBUTES_BOOLEAN = 5;
	/**
	 * Attribute type {@link InetSocketAddress}.
	 */
	private static final int ATTRIBUTES_INET_SOCKET_ADDRESS = 6;
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
	 * @see #readStartItem(DataStreamReader, int, int)
	 * @see #readStartItem(DataStreamReader, SupportedVersionsMatcher, int)
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
	 * @see #readStartItem(DataStreamReader, int, int)
	 * @see #readStartItem(DataStreamReader, SupportedVersionsMatcher, int)
	 */
	public static void writeFinishedItem(DatagramWriter writer, int position, int numBits) {
		writer.writeSize(position, numBits);
	}

	/**
	 * Read item start.
	 * 
	 * <b>Note</b>: on version mismatch, it's not supported to retry with a
	 * different version! Use
	 * {@link #readStartItem(DataStreamReader, SupportedVersionsMatcher, int)}
	 * instead!
	 * 
	 * @param reader reader
	 * @param version version of item's serialization
	 * @param numBits number of bits for the item length
	 * @return length of the item, or {@code -1}, if
	 *         {@link #writeNoItem(DatagramWriter)} was used.
	 * @throws VersionMismatchException if version doesn't match.
	 * @throws IllegalArgumentException if the read length exceeds the available
	 *             bytes.
	 * @see #writeStartItem(DatagramWriter, int, int)
	 * @see #writeFinishedItem(DatagramWriter, int, int)
	 * @see #readStartItem(DataStreamReader, SupportedVersionsMatcher, int)
	 */
	public static int readStartItem(DataStreamReader reader, int version, int numBits) {
		if (version == NO_VERSION) {
			throw new IllegalArgumentException("Version must not be " + NO_VERSION + "!");
		}
		int read = reader.readNextByte() & 0xff;
		if (read == NO_VERSION) {
			return -1;
		} else if (read != version) {
			throw new VersionMismatchException("Version mismatch! " + version + " is required, not " + read + "!",
					read);
		}
		return reader.read(numBits);
	}

	/**
	 * Read item start.
	 * 
	 * <pre>
	 * final SupportedVersions VERSIONS = new SupportedVersions(V1, V2, V3);
	 * ...
	 * SupportedVersionsMatcher matcher = VERSIONS.matcher();
	 * int len = readStartItem(reader, matcher, 16);
	 * ...
	 * matcher.getReadVersion();
	 * ...
	 * </pre>
	 * 
	 * @param reader reader
	 * @param versions supported versions matcher
	 * @param numBits number of bits for the item length
	 * @return length of the item, or {@code -1}, if
	 *         {@link #writeNoItem(DatagramWriter)} was used.
	 * @throws VersionMismatchException if version doesn't match.
	 * @throws IllegalArgumentException if the read length exceeds the available
	 *             bytes.
	 * @see #writeStartItem(DatagramWriter, int, int)
	 * @see #writeFinishedItem(DatagramWriter, int, int)
	 * @see #readStartItem(DataStreamReader, int, int)
	 */
	public static int readStartItem(DataStreamReader reader, SupportedVersionsMatcher versions, int numBits) {
		if (versions == null) {
			throw new NullPointerException("Version must not be null!");
		}
		int read = reader.readNextByte() & 0xff;
		if (read == NO_VERSION) {
			return -1;
		} else if (!versions.supports(read)) {
			throw new VersionMismatchException("Version mismatch! " + versions + " are required, not " + read + "!",
					read);
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
	 * @param reader reader to read.
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
	 * Verify {@link String} using {@link StandardCharsets#UTF_8}.
	 * 
	 * @param reader reader to read.
	 * @param expectedValue expected value to verify.
	 * @param numBits number of bits for encoding the length.
	 * @return {@code true}, if verify mark is read, {@code false}, if
	 *         {@code null} is read.
	 * @throws NullPointerException if the provided expected value is
	 *             {@code null}
	 * @throws IllegalArgumentException if read value doesn't match expected
	 *             value
	 * @see #write(DatagramWriter, String, int)
	 */
	public static boolean verifyString(DataStreamReader reader, String expectedValue, int numBits) {
		if (expectedValue == null) {
			throw new NullPointerException("Expected value must not be null!");
		}
		byte[] data = reader.readVarBytes(numBits);
		if (data == null) {
			return false;
		} else {
			byte[] mark = expectedValue.getBytes(StandardCharsets.UTF_8);
			if (Arrays.equals(mark, data)) {
				return true;
			}
			String read = StringUtil.toDisplayString(data, 16);
			if (!read.startsWith("\"") && !read.startsWith("<")) {
				expectedValue = StringUtil.byteArray2HexString(mark, ' ', 16);
			}
			throw new IllegalArgumentException("Mismatch, read " + read + ", expected " + expectedValue + ".");
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
	public static void write(DatagramWriter writer, Map<Definition<?>, Object> entries) {
		if (entries == null) {
			writeNoItem(writer);
		} else {
			int position = writeStartItem(writer, ATTRIBUTES_VERSION, Short.SIZE);
			for (Map.Entry<Definition<?>, Object> entry : entries.entrySet()) {
				write(writer, entry.getKey().getKey(), Byte.SIZE);
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
				} else if (value instanceof Boolean) {
					writer.writeByte((byte) ATTRIBUTES_BOOLEAN);
					writer.writeByte((Boolean) value ? (byte) 1 : (byte) 0);
				} else if (value instanceof InetSocketAddress) {
					writer.writeByte((byte) ATTRIBUTES_INET_SOCKET_ADDRESS);
					write(writer, (InetSocketAddress) value);
				}
			}
			writeFinishedItem(writer, position, Short.SIZE);
		}
	}

	/**
	 * Read {@link EndpointContext} attributes.
	 * 
	 * @param <T> definitions type
	 * @param reader reader
	 * @param definitions set of definitions to read
	 * @return read attributes, or {@code null}, if no attributes are written.
	 */
	@SuppressWarnings("unchecked")
	public static <T extends Definition<?>> Attributes readEndpointContexAttributes(DataStreamReader reader,
			Definitions<T> definitions) {
		int length = readStartItem(reader, ATTRIBUTES_VERSION, Short.SIZE);
		if (length < 0) {
			return null;
		}
		DatagramReader rangeReader = reader.createRangeReader(length);
		Attributes attributes = new Attributes();
		while (rangeReader.bytesAvailable()) {
			String key = readString(rangeReader, Byte.SIZE);
			Definition<?> definition = definitions.get(key);
			if (definition == null) {
				throw new IllegalArgumentException("'" + key + "' is not in definitions!");
			}
			try {
				int type = rangeReader.readNextByte() & 0xff;
				switch (type) {
				case ATTRIBUTES_STRING:
					String stringValue = readString(rangeReader, Byte.SIZE);
					attributes.add((Definition<String>) definition, stringValue);
					break;
				case ATTRIBUTES_BYTES:
					byte[] data = rangeReader.readVarBytes(Byte.SIZE);
					attributes.add((Definition<Bytes>) definition, new Bytes(data));
					break;
				case ATTRIBUTES_INTEGER:
					int intValue = rangeReader.read(Integer.SIZE);
					attributes.add((Definition<Integer>) definition, Integer.valueOf(intValue));
					break;
				case ATTRIBUTES_LONG:
					long longValue = rangeReader.readLong(Long.SIZE);
					attributes.add((Definition<Long>) definition, Long.valueOf(longValue));
					break;
				case ATTRIBUTES_BOOLEAN:
					byte booleanValue = rangeReader.readNextByte();
					attributes.add((Definition<Boolean>) definition, booleanValue == 1 ? Boolean.TRUE : Boolean.FALSE);
					break;
				case ATTRIBUTES_INET_SOCKET_ADDRESS:
					InetSocketAddress address = readAddress(rangeReader);
					attributes.add((Definition<InetSocketAddress>) definition, address);
					break;
				}
			} catch (ClassCastException ex) {
				LOGGER.warn("Read attribute {}:", key, ex);
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
	 * The delta considers different uptimes of hosts, e.g. because the one host
	 * runs for a week, the other for a day. It also uses the
	 * {@link System#currentTimeMillis()} in order to include the past calendar
	 * time between writing and reading.
	 * 
	 * @param reader reader to read
	 * @return delta in nanoseconds for nanotime synchronization. Considers
	 *         different uptimes and past calendar time.
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
	 * @param in stream to skip items.
	 * @param numBits number of bits of the item length.
	 * @throws IllegalArgumentException if stream isn't a valid stream of items
	 */
	public static void skipItems(InputStream in, int numBits) {
		DataStreamReader reader = new DataStreamReader(in);
		skipItems(reader, numBits);
	}

	/**
	 * Skip items until "no item" is read and return the number.
	 * 
	 * @param reader stream reader to skip items.
	 * @param numBits number of bits of the item length.
	 * @return number of skipped items.
	 * @throws IllegalArgumentException if stream isn't a valid stream of items
	 * @since 3.3.1
	 */
	public static int skipItems(DataStreamReader reader, int numBits) {
		int count = 0;
		while ((reader.readNextByte() & 0xff) != NO_VERSION) {
			int len = reader.read(numBits);
			skipBits(reader, len * Byte.SIZE);
			++count;
		}
		return count;
	}

	/**
	 * Skip bits.
	 * 
	 * If not enough bits are available without blocking, try to read a byte.
	 * That seems to be required for {@link CipherInputStream}.
	 * 
	 * @param reader reader to skip bits.
	 * @param numBits number of bits to be skipped
	 * @return number of actual skipped bits
	 * @throws IllegalArgumentException if not enough bits are available
	 * @since 3.3.1
	 */
	public static long skipBits(DataStreamReader reader, long numBits) {
		long bits = numBits;
		while (bits > 0) {
			long skipped = reader.skip(bits);
			if (skipped <= 0) {
				// CipherInputStream seems to require that
				// readNextByte fails with IllegalArgumentException
				// at the End Of Stream
				reader.readNextByte();
				bits -= Byte.SIZE;
			} else {
				bits -= skipped;
			}
		}
		return numBits - bits;
	}

	/**
	 * Supported versions.
	 * 
	 * Intended to be used as factory for {@code SupportedVersionsMatcher} using
	 * {@link #matcher()}.
	 */
	public static class SupportedVersions {

		/**
		 * List of supported version.
		 */
		private final int[] versions;

		/**
		 * Create list of supported versions.
		 * 
		 * @param versions list of supported versions
		 */
		public SupportedVersions(int... versions) {
			this(true, versions);
		}

		/**
		 * Create list of supported versions.
		 * 
		 * @param copy {@code true} to copy list of supported versions,
		 *            {@code false}, share list.
		 * @param versions list of supported versions
		 */
		protected SupportedVersions(boolean copy, int... versions) {
			if (versions == null) {
				throw new NullPointerException("Versions must not be null!");
			}
			if (versions.length == 0) {
				throw new IllegalArgumentException("Versions must not be empty!");
			}
			this.versions = copy ? Arrays.copyOf(versions, versions.length) : versions;
			if (supports(NO_VERSION)) {
				throw new IllegalArgumentException("Versions must not contain NO_VERSION!");
			}
		}

		/**
		 * Check, if read version is supported.
		 * 
		 * @param readVersion read version
		 * @return {@code true}, if the read version is supported,
		 *         {@code false}, otherwise.
		 */
		public boolean supports(int readVersion) {
			for (int version : versions) {
				if (readVersion == version) {
					return true;
				}
			}
			return false;
		}

		@Override
		public String toString() {
			return Arrays.toString(versions);
		}

		/**
		 * Create matcher based on this supported versions.
		 * 
		 * @return matcher
		 * @see SerializationUtil#readStartItem(DataStreamReader,
		 *      SupportedVersionsMatcher, int)
		 */
		public SupportedVersionsMatcher matcher() {
			return new SupportedVersionsMatcher(versions);
		}
	}

	/**
	 * Supported versions.
	 */
	public static class SupportedVersionsMatcher extends SupportedVersions {

		/**
		 * Read version. {@link SerializationUtil#NO_VERSION} on mismatch.
		 */
		private int readVersion;

		/**
		 * Create list of supported versions.
		 * 
		 * @param versions list of supported versions
		 */
		private SupportedVersionsMatcher(int... versions) {
			super(false, versions);
			this.readVersion = NO_VERSION;
		}

		@Override
		public boolean supports(int readVersion) {
			if (super.supports(readVersion)) {
				this.readVersion = readVersion;
				return true;
			} else {
				this.readVersion = NO_VERSION;
				return false;
			}
		}

		/**
		 * Get read version.
		 * 
		 * @return read version, or {@link SerializationUtil#NO_VERSION}, if not
		 *         supported.
		 */
		public int getReadVersion() {
			return readVersion;
		}
	}
}
