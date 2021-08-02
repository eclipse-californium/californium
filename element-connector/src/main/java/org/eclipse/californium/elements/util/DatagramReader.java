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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add "mark" and "reset"
 *    Achim Kraus (Bosch Software Innovations GmbH) - add constructor without 
 *                                                    cloning of the provided data.
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * This class describes the functionality to read raw network-ordered datagrams
 * on bit-level.
 * 
 * For a {@link InputStream} the specification of the returned value of
 * {@link InputStream#available()} is weak. Therefore the methods in the
 * base-class {@link DataStreamReader} are not based on that. If the data is
 * already read into a byte-array, this class may be used in order to used
 * methods, which are based on {@link ByteArrayInputStream#available()}.
 */
public final class DatagramReader extends DataStreamReader {
	/**
	 * Copy of {@link #currentByte}, when {@link #mark()} is called.
	 */
	private byte markByte;
	/**
	 * Copy of {@link #currentBitIndex}, when {@link #mark()} is called.
	 */
	private int markBitIndex;

	/**
	 * Creates a new reader for an copied array of bytes.
	 * 
	 * @param byteArray The byte array to read from.
	 */
	public DatagramReader(final byte[] byteArray) {
		this(byteArray, true);
	}

	/**
	 * Creates a new reader for an array of bytes.
	 * 
	 * @param byteArray The byte array to read from.
	 * @param copy {@code true} to copy the array, {@code false} to us it
	 *            directly.
	 */
	public DatagramReader(final byte[] byteArray, boolean copy) {
		this(copy ? Arrays.copyOf(byteArray, byteArray.length) : byteArray, 0, byteArray.length);
	}

	/**
	 * Creates a new reader for a range within an array of bytes.
	 * 
	 * The array is used directly and is not copied. If a copy is required, copy
	 * the range and provide that to {@link #DatagramReader(byte[])}.
	 * 
	 * @param byteArray The byte array to read from.
	 * @param offset starting offset of the range.
	 * @param length length of the range.
	 * 
	 * @since 2.4
	 */
	public DatagramReader(final byte[] byteArray, int offset, int length) {
		this(new RangeInputStream(byteArray, offset, length));
	}

	/**
	 * Creates a new reader for an bytes stream.
	 * 
	 * @param byteStream The byte stream to read from.
	 * @throws NullPointerException if byte stream is {@code null}
	 */
	public DatagramReader(final ByteArrayInputStream byteStream) {
		super(byteStream);
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
		try {
			byteStream.reset();
		} catch (IOException e) {
		}
		currentByte = markByte;
		currentBitIndex = markBitIndex;
	}

	/**
	 * Close reader. Free resource and clear left bytes.
	 */
	@Override
	public void close() {
		try {
			byteStream.skip(byteStream.available());
		} catch (IOException e) {
		}
		super.close();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param count The number of bytes to read. If value is negative, read left
	 *            bytes.
	 */
	@Override
	public byte[] readBytes(final int count) {

		int available = available();
		int bytesToRead = count;

		// for negative count values, read all bytes left
		if (bytesToRead < 0) {
			bytesToRead = available;
		} else if (bytesToRead > available) {
			throw new IllegalArgumentException(
					"requested " + count + " bytes exceeds available " + available + " bytes.");
		}

		return super.readBytes(bytesToRead);
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
	 * Assert, that all data is read.
	 * 
	 * @param message message to include in {@link IllegalArgumentException}
	 *            message.
	 * @throws IllegalArgumentException if bits are left unread
	 * @since 3.0
	 */
	public void assertFinished(String message) {
		int left = bitsLeft();
		if (left > 0) {
			throw new IllegalArgumentException(message + " not finished! " + left + " bits left.");
		}
	}

	/**
	 * Checks if there are any more bytes available on the stream.
	 * 
	 * @return {@code true}, if there are bytes left to read, {@code false},
	 *         otherwise.
	 */
	public boolean bytesAvailable() {
		return available() > 0;
	}

	/**
	 * Checks whether a given number of bytes can be read.
	 * 
	 * @param expectedBytes the number of bytes.
	 * @return {@code true} if the remaining number of bytes in the buffer is at
	 *         least <em>expectedBytes</em>. {@code false}, otherwise.
	 */
	public boolean bytesAvailable(final int expectedBytes) {
		int bytesLeft = available();
		return bytesLeft >= expectedBytes;
	}

	/**
	 * Gets the number of remaining bits that can be read from the datagram.
	 *  
	 * @return the number of bits
	 */
	public int bitsLeft() {
		return (available() * Byte.SIZE) + (currentBitIndex + 1);
	}

	// Utilities ///////////////////////////////////////////////////////////////

	/**
	 * Get available bytes from {@link #byteStream}.
	 * 
	 * @return available bytes, or {@code -1}, if an error occurred.
	 * @since 3.0
	 */
	private int available() {
		try {
			return byteStream.available();
		} catch (IOException e) {
			return -1;
		}
	}
}
