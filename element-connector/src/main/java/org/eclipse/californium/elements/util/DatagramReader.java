/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add "mark" and "reset"
 *    Achim Kraus (Bosch Software Innovations GmbH) - add constructor without 
 *                                                    cloning of the provided data.
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

/**
 * This class describes the functionality to read raw network-ordered datagrams
 * on bit-level.
 */
public final class DatagramReader {

	// Attributes //////////////////////////////////////////////////////////////

	private final ByteArrayInputStream byteStream;

	private byte currentByte;
	private int currentBitIndex;

	/**
	 * Copy of {@link #currentByte}, when {@link #mark()} is called.
	 */
	private byte markByte;
	/**
	 * Copy of {@link #currentBitIndex}, when {@link #mark()} is called.
	 */
	private int markBitIndex;

	// Constructors ////////////////////////////////////////////////////////////

	/**
	 * Creates a new reader for an array of bytes.
	 * 
	 * @param byteArray The byte array to read from.
	 */
	public DatagramReader(final byte[] byteArray) {
		this(new ByteArrayInputStream(Arrays.copyOf(byteArray, byteArray.length)));
	}

	/**
	 * Creates a new reader for an bytes stream.
	 * 
	 * @param byteStream The byte stream to read from.
	 * @throws NullPointerException if byte stream is {@code null}
	 */
	public DatagramReader(final ByteArrayInputStream byteStream) {
		if (byteStream == null) {
			throw new NullPointerException("byte stream must not be null!");
		}
		// initialize underlying byte stream
		this.byteStream = byteStream;

		// initialize bit buffer
		currentByte = 0;
		currentBitIndex = -1; // indicates that no byte read yet
		markByte = currentByte;
		markBitIndex = currentBitIndex;
	}

	// Methods /////////////////////////////////////////////////////////////////

	/**
	 * Mark current position to be reseted afterwards.
	 * 
	 * @see #reset()
	 */
	public void mark() {
		markByte = currentByte;
		markBitIndex = currentBitIndex;
		byteStream.mark(0);
	}

	/**
	 * Reset reader to last mark.
	 * 
	 * @see #mark()
	 */
	public void reset() {
		byteStream.reset();
		currentByte = markByte;
		currentBitIndex = markBitIndex;
	}

	/**
	 * Close reader.
	 * Free resource and clear left bytes.
	 */
	public void close() {
		byteStream.skip(byteStream.available());
		currentByte = 0;
		currentBitIndex = -1; // indicates that no byte read yet
	}

	/**
	 * 
	 * Reads a sequence of bits from the stream.
	 * 
	 * @param numBits
	 *            The number of bits to read.
	 * 
	 * @return A Long containing the bits read.
	 * @throws IllegalArgumentException if provided numBits exceeds available bytes
	 */
	public long readLong(final int numBits) {

		long bits = 0; // initialize all bits to zero

		for (int i = numBits - 1; i >= 0; i--) {

			// check whether new byte needs to be read
			if (currentBitIndex < 0) {
				readCurrentByte();
			}

			// test current bit
			boolean bit = (currentByte >> currentBitIndex & 1) != 0;
			if (bit) {
				// set bit at i-th position
				bits |= (1L << i);
			}

			// decrease current bit index
			--currentBitIndex;

		}

		return bits;
	}

	/**
	 * Reads a sequence of bits from the stream.
	 * 
	 * @param numBits
	 *            The number of bits to read.
	 * 
	 * @return An integer containing the bits read.
	 * @throws IllegalArgumentException if provided numBits exceeds available bytes
	 */
	public int read(final int numBits) {

		int bits = 0; // initialize all bits to zero

		for (int i = numBits - 1; i >= 0; i--) {

			// check whether new byte needs to be read
			if (currentBitIndex < 0) {
				readCurrentByte();
			}

			// test current bit
			boolean bit = (currentByte >> currentBitIndex & 1) != 0;
			if (bit) {
				// set bit at i-th position
				bits |= (1 << i);
			}

			// decrease current bit index
			--currentBitIndex;

		}

		return bits;
	}

	/**
	 * Reads a sequence of bytes from the stream.
	 * 
	 * @param count
	 *            The number of bytes to read.
	 * 
	 * @return The sequence of bytes read from the stream.
	 * @throws IllegalArgumentException if provided count exceeds available bytes
	 */
	public byte[] readBytes(final int count) {

		int available = byteStream.available();
		int bytesToRead = count;

		// for negative count values, read all bytes left
		if (bytesToRead < 0) {
			bytesToRead = available;
		} else if (bytesToRead > available) {
			throw new IllegalArgumentException("requested bytes " + count + " exceeds available bytes " + available);
		}

		// allocate byte array
		byte[] bytes = new byte[bytesToRead];

		// are there bits left to read in buffer?
		if (currentBitIndex >= 0) {

			for (int i = 0; i < bytesToRead; i++) {
				bytes[i] = (byte) read(Byte.SIZE);
			}

		} else {

			// if bit buffer is empty, call can be delegated
			// to byte stream to increase performance
			byteStream.read(bytes, 0, bytes.length);
		}

		return bytes;
	}

	/**
	 * Reads the next byte from the stream.
	 * 
	 * @return The next byte.
	 * @throws IllegalArgumentException if no bytes are available
	 */
	public byte readNextByte() {
		byte[] bytes = readBytes(1);

		return bytes[0];
	}

	/**
	 * Reads the complete sequence of bytes left in the stream.
	 * 
	 * @return The sequence of bytes left in the stream.
	 */
	public byte[] readBytesLeft() {
		return readBytes(-1);
	}

	/**
	 * Checks if there are any more bytes available on the stream.
	 * 
	 * @return <code>true</code> if there are bytes left to read,
	 *         <code>false</code> otherwise.
	 */
	public boolean bytesAvailable() {
		return byteStream.available() > 0;
	}

	/**
	 * Checks whether a given number of bytes can be read.
	 * 
	 * @param expectedBytes the number of bytes. 
	 * @return {@code true} if the remaining number of bytes in the buffer is at least
	 *         <em>expectedBytes</em>.
	 */
	public boolean bytesAvailable(final int expectedBytes) {
		int bytesLeft = byteStream.available();
		return bytesLeft >= expectedBytes;
	}

	/**
	 * Gets the number of remaining bits that can be read from the datagram.
	 *  
	 * @return the number of bits
	 */
	public int bitsLeft() {
		return (byteStream.available() * Byte.SIZE) + (currentBitIndex + 1);
	}

	// Utilities ///////////////////////////////////////////////////////////////

	/**
	 * Reads new bits from the stream.
	 * 
	 * @throws IllegalArgumentException if no bytes are available
	 */
	private void readCurrentByte() {

		// try to read from byte stream
		int val = byteStream.read();

		if (val >= 0) {
			// byte successfully read
			currentByte = (byte) val;
		} else {
			// end of stream reached
			throw new IllegalArgumentException("requested byte exceeds available bytes!");
		}

		// reset current bit index
		currentBitIndex = Byte.SIZE - 1;
	}
}
