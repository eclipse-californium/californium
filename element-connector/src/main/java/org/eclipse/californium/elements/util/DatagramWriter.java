/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add methods to reduce
 *                                                    required clones.
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class describes the functionality to write raw network-ordered datagrams
 * on bit-level.
 */
public final class DatagramWriter {
	private static final Logger LOGGER = LoggerFactory.getLogger(DatagramWriter.class);

	// Attributes //////////////////////////////////////////////////////////////
	private final ByteArrayOutputStream byteStream;

	private byte currentByte;
	private int currentBitIndex;

	// Constructors ////////////////////////////////////////////////////////////

	/**
	 * Creates a new empty writer.
	 */
	public DatagramWriter() {
		this(false);
	}

	/**
	 * Creates a new empty writer with provided {@link #close()} behaviour.
	 * 
	 * @param secureClose {@code true}, clear internal buffer on {@link
	 *            #close()}, {@code false}, don't clear internal buffer.
	 */
	public DatagramWriter(boolean secureClose) {
		// initialize underlying byte stream
		byteStream = secureClose ? new ByteArrayOutputStream() {

			@Override
			public void close() throws IOException {
				Bytes.clear(buf);
				super.close();
			}
		} : new ByteArrayOutputStream();

		// initialize bit buffer
		resetCurrentByte();
	}

	/**
	 * Creates a new empty writer with provided initial size.
	 * 
	 * @param size initial size
	 */
	public DatagramWriter(int size) {
		// initialize underlying byte stream
		byteStream = new ByteArrayOutputStream(size);

		// initialize bit buffer
		resetCurrentByte();
	}

	// Methods /////////////////////////////////////////////////////////////////

	/**
	 * Writes a sequence of bits to the stream.
	 * 
	 * @param data A Long containing the bits to write.
	 * @param numBits The number of bits to write. 1 to 64.
	 * @throws IllegalArgumentException if the number of bits is not in range
	 *             1..64, or the provided data contains more bits than that
	 *             number.
	 */
	public void writeLong(final long data, final int numBits) {

		if (numBits < 0 || numBits > 64) {
			throw new IllegalArgumentException(String.format("Number of bits must be 1 to 64, not %d", numBits));
		}
		if (numBits < 64 && (data >> numBits) != 0) {
			throw new IllegalArgumentException(String.format("Truncating value %d to %d-bit integer", data, numBits));
		}

		if ((numBits & 0x7) == 0 && !isBytePending()) {
			// byte-wise, no maverick bits left
			for (int i = numBits - 8; i >= 0; i -= 8) {
				byteStream.write((byte)(data >> i));
			}
		} else {
			for (int i = numBits - 1; i >= 0; i--) {

				// test bit
				boolean bit = (data >> i & 1) != 0;
				if (bit) {
					// set bit in current byte
					currentByte |= (1 << currentBitIndex);
				}

				// decrease current bit index
				--currentBitIndex;

				// check if current byte can be written
				if (currentBitIndex < 0) {
					writeCurrentByte();
				}
			}
		}
	}

	/**
	 * Writes a sequence of bits to the stream.
	 * 
	 * @param data An integer containing the bits to write.
	 * @param numBits The number of bits to write. 1 to 32.
	 * @throws IllegalArgumentException if the number of bits is not in range
	 *             1..32, or the provided data contains more bits than that
	 *             number.
	 */
	public void write(final int data, final int numBits) {
		if (numBits < 0 || numBits > 32) {
			throw new IllegalArgumentException(String.format("Number of bits must be 1 to 32, not %d", numBits));
		}
		if (numBits < 32 && (data >> numBits) != 0) {
			throw new IllegalArgumentException(String.format("Truncating value %d to %d-bit integer", data, numBits));
		}

		if ((numBits & 0x7) == 0 && !isBytePending()) {
			// byte-wise, no maverick bits left
			for (int i = numBits - 8; i >= 0; i -= 8) {
				byteStream.write((byte)(data >> i));
			}
		} else {
			for (int i = numBits - 1; i >= 0; i--) {

				// test bit
				boolean bit = (data >> i & 1) != 0;
				if (bit) {
					// set bit in current byte
					currentByte |= (1 << currentBitIndex);
				}

				// decrease current bit index
				--currentBitIndex;

				// check if current byte can be written
				if (currentBitIndex < 0) {
					writeCurrentByte();
				}
			}
		}
	}

	/**
	 * Writes a sequence of bytes to the stream.
	 * 
	 * @param bytes
	 *            The sequence of bytes to write.
	 */
	public void writeBytes(final byte[] bytes) {

		// check if anything to do at all
		if (bytes == null)
			return;

		// are there bits left to write in buffer?
		if (isBytePending()) {

			for (int i = 0; i < bytes.length; i++) {
				write(bytes[i] & 0xff, Byte.SIZE);
			}

		} else {

			// if bit buffer is empty, call can be delegated
			// to byte stream to increase
			byteStream.write(bytes, 0, bytes.length);
		}
	}

	/**
	 * Writes one byte to the stream.
	 * 
	 * @param b
	 *            The byte to be written.
	 */
	public void writeByte(final byte b) {
		if (isBytePending()) {
			write(b & 0xff, Byte.SIZE);
		} else {
			byteStream.write(b);
		}
	}

	// Functions ///////////////////////////////////////////////////////////////

	/**
	 * Returns a byte array containing the sequence of bits written.
	 * 
	 * @return The byte array containing the written bits.
	 */
	public byte[] toByteArray() {

		// write any bits left in the buffer to the stream
		writeCurrentByte();

		// retrieve the byte array from the stream
		byte[] byteArray = byteStream.toByteArray();

		// reset stream for the sake of consistency
		byteStream.reset();

		// return the byte array
		return byteArray;
	}

	public void write(DatagramWriter data) {
		try {
			data.writeCurrentByte();
			data.byteStream.writeTo(byteStream);
		} catch (IOException e) {
		}
	}

	/**
	 * Current size of written data.
	 * @return number of currently written bytes.
	 */
	public int size() {
		return byteStream.size();
	}

	/**
	 * Close writer, release resources. If {@link #DatagramWriter(boolean)}
	 * secure close is enabled, clear the related byte array before releasing
	 * it.
	 */
	public void close() {
		try {
			byteStream.close();
		} catch (IOException e) {
			// Using ByteArrayOutputStream should not cause this
			LOGGER.warn("{}.close() failed!", byteStream.getClass(), e);
		}
	}

	/**
	 * Writes pending bits to the stream.
	 */
	public void writeCurrentByte() {
		if (isBytePending()) {
			byteStream.write(currentByte);
			resetCurrentByte();
		}
	}

	public final boolean isBytePending() {
		return currentBitIndex < Byte.SIZE - 1;
	}

	private final void resetCurrentByte() {
		currentByte = 0;
		currentBitIndex = Byte.SIZE - 1;
	}

	// Utilities ///////////////////////////////////////////////////////////////

	@Override
	public String toString() {
		byte[] byteArray = byteStream.toByteArray();
		if (byteArray != null && byteArray.length != 0) {

			StringBuilder builder = new StringBuilder(byteArray.length * 3);
			for (int i = 0; i < byteArray.length; i++) {
				builder.append(String.format("%02X", 0xFF & byteArray[i]));

				if (i < byteArray.length - 1) {
					builder.append(' ');
				}
			}
			return builder.toString();
		} else {
			return "--";
		}
	}
}
