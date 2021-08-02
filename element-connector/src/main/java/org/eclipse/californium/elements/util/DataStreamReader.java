/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from DatagramReader
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class describes the functionality to read raw network-ordered data
 * streams on bit-level.
 * 
 * For a {@link InputStream} the specification of the returned value of
 * {@link InputStream#available()} is weak, therefore the methods in this class
 * are not based on that. If the data is already read into a byte-array,
 * {@link DatagramReader} may be used, in order to use methods, which are based
 * on {@link ByteArrayInputStream#available()}.
 * 
 * @since 3.0
 */
public class DataStreamReader {

	/**
	 * Input stream with improved range reading.
	 */
	protected static class RangeInputStream extends ByteArrayInputStream {

		/**
		 * Create reader from byte array.
		 * 
		 * @param buffer directly used byte array
		 */
		protected RangeInputStream(byte[] buffer) {
			super(buffer);
		}

		/**
		 * Create reader from byte array range.
		 * 
		 * @param buffer directly used byte array
		 * @param offset offset in buffer
		 * @param length length of range
		 */
		protected RangeInputStream(byte[] buffer, int offset, int length) {
			super(buffer, offset, length);
		}

		/**
		 * Create reader for range. Read range and pass it to the returned
		 * reader.
		 * 
		 * @param count number of bytes for the range
		 * @return reader containing the range
		 * @throws IllegalArgumentException if provided count exceeds available
		 *             bytes
		 */
		private RangeInputStream range(int count) {
			int offset = pos;
			long available = skip(count);
			if (available < count) {
				throw new IllegalArgumentException(
						"requested " + count + " bytes exceeds available " + available + " bytes.");
			}
			return new RangeInputStream(buf, offset, count);
		}

	}
	// Attributes //////////////////////////////////////////////////////////////

	protected final InputStream byteStream;

	protected byte currentByte;
	protected int currentBitIndex;

	// Constructors ////////////////////////////////////////////////////////////

	/**
	 * Creates a new reader for an bytes stream.
	 * 
	 * @param byteStream The byte stream to read from.
	 * @throws NullPointerException if byte stream is {@code null}
	 */
	public DataStreamReader(final InputStream byteStream) {
		if (byteStream == null) {
			throw new NullPointerException("byte stream must not be null!");
		}
		// initialize underlying byte stream
		this.byteStream = byteStream;

		// initialize bit buffer
		currentByte = 0;
		currentBitIndex = -1; // indicates that no byte read yet
	}

	// Methods /////////////////////////////////////////////////////////////////

	/**
	 * Close reader. Free resource and clear left bytes.
	 */
	public void close() {
		try {
			byteStream.close();
		} catch (IOException e) {
		}
		currentByte = 0;
		currentBitIndex = -1; // indicates that no byte read yet
	}

	/**
	 * Skip bits.
	 * 
	 * @param numBits number of bits to skip
	 * @return actual number of skipped bits
	 */
	public long skip(long numBits) {
		int skipped = 0;
		if (currentBitIndex >= 0) {
			skipped = currentBitIndex + 1;
			numBits -= skipped;
			currentBitIndex = -1;
		}
		int left = (int) (numBits & 0x07);
		long skipBytes = numBits / Byte.SIZE;
		long bytes = skipBytes(skipBytes);
		if (bytes < 0) {
			return skipped;
		} else if (bytes < skipBytes) {
			left = 0;
		} else {
			try {
				readCurrentByte();
				currentBitIndex -= left;
			} catch (IllegalArgumentException ex) {
				left = 0;
			}
		}

		return (bytes * Byte.SIZE) + left + skipped;
	}

	/**
	 * 
	 * Reads a sequence of bits from the stream.
	 * 
	 * @param numBits The number of bits to read.
	 * 
	 * @return A Long containing the bits read.
	 * @throws IllegalArgumentException if provided numBits exceeds available
	 *             bytes, or that value is out of the range {@code [0...64]}.
	 */
	public long readLong(final int numBits) {
		if (numBits < 0 || numBits > Long.SIZE) {
			throw new IllegalArgumentException("bits must be in range 0 ... 64!");
		}
		long bits = 0; // initialize all bits to zero

		if (currentBitIndex < 0 && (numBits & 0x7) == 0) {
			// byte-wise, no maverick bits left
			for (int i = 0; i < numBits; i += 8) {
				bits <<= 8;
				bits |= readByte();
			}
		} else {
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
		}

		return bits;
	}

	/**
	 * Reads a sequence of bits from the stream.
	 * 
	 * @param numBits The number of bits to read.
	 * 
	 * @return An integer containing the bits read.
	 * @throws IllegalArgumentException if provided numBits exceeds available
	 *             bytes, or that value is out of the range {@code [0...32]}.
	 */
	public int read(final int numBits) {
		if (numBits < 0 || numBits > Integer.SIZE) {
			throw new IllegalArgumentException("bits must be in range 0 ... 32!");
		}

		int bits = 0; // initialize all bits to zero

		if (currentBitIndex < 0 && (numBits & 0x7) == 0) {
			// byte-wise, no maverick bits left
			for (int i = 0; i < numBits; i += 8) {
				bits <<= 8;
				bits |= readByte();
			}
		} else {
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
		}

		return bits;
	}

	/**
	 * Reads a sequence of bytes from the stream.
	 * 
	 * @param count The number of bytes to read.
	 * 
	 * @return The sequence of bytes read from the stream.
	 * @throws IllegalArgumentException if provided count is negative
	 */
	public byte[] readBytes(final int count) {
		if (count < 0) {
			throw new IllegalArgumentException("Count " + count + " must not be negative!");
		} else if (count == 0) {
			return Bytes.EMPTY;
		}

		// allocate byte array
		byte[] bytes = new byte[count];

		// are there bits left to read in buffer?
		if (currentBitIndex >= 0) {

			for (int i = 0; i < count; i++) {
				bytes[i] = (byte) read(Byte.SIZE);
			}

		} else {

			// if bit buffer is empty, call can be delegated
			// to byte stream to increase performance
			readBytes(bytes, 0, bytes.length, true);
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
		if (currentBitIndex >= 0) {
			return (byte) read(Byte.SIZE);
		} else {
			return (byte) readByte();
		}
	}

	/**
	 * Read variable length byte arrays.
	 * 
	 * Read first the length of the variable bytes according the size in
	 * {@code numBits}. For the length {@code -1}, {@code null} is returned, and
	 * for the length {@code 0}, {@link Bytes#EMPTY} is returned.
	 * 
	 * @param numBits number of bits used for the size.
	 * @return read byte array, {@code null}, or empty array.
	 */
	public byte[] readVarBytes(int numBits) {
		int varLengthBits = DatagramWriter.getVarLengthBits(numBits);
		int nullLengthValue = DatagramWriter.getNullLengthValue(varLengthBits);
		int len = read(varLengthBits);
		if (len == nullLengthValue) {
			return null;
		} else {
			return readBytes(len);
		}
	}

	/**
	 * Create reader for provided range.
	 * 
	 * @param count size of the range in bytes
	 * @return reader
	 * @throws IllegalStateException if some bits of the current byte are unread
	 * @throws IllegalArgumentException if provided count exceeds available
	 *             bytes
	 */
	public DatagramReader createRangeReader(int count) {
		return new DatagramReader(createRangeInputStream(count));
	}

	/**
	 * Create input stream for provided range.
	 * 
	 * @param count size of the range in bytes
	 * @return input stream
	 * @throws IllegalStateException if some bits of the current byte are unread
	 * @throws IllegalArgumentException if provided count exceeds available
	 *             bytes
	 */
	public ByteArrayInputStream createRangeInputStream(int count) {
		if (currentBitIndex > 0) {
			throw new IllegalStateException(currentBitIndex + " bits unread!");
		}
		if (byteStream instanceof RangeInputStream) {
			RangeInputStream range = (RangeInputStream) byteStream;
			return range.range(count);
		} else {
			byte[] range = new byte[count];
			readBytes(range, 0, count, true);
			return new RangeInputStream(range);
		}
	}

	// Utilities ///////////////////////////////////////////////////////////////

	/**
	 * Skip bytes in {@link #byteStream}.
	 * 
	 * @param skip number of bytes to skip
	 * @return actually skipped bytes, or {@code -1}, if an error occurred.
	 */
	private long skipBytes(long skip) {
		try {
			return byteStream.skip(skip);
		} catch (IOException e) {
			return -1;
		}
	}

	/**
	 * Reads new bits from the stream.
	 * 
	 * @throws IllegalArgumentException if no bytes are available
	 */
	private void readCurrentByte() {
		// try to read from byte stream
		currentByte = (byte) readByte();
		// reset current bit index
		currentBitIndex = Byte.SIZE - 1;
	}

	/**
	 * Reads new bits from the stream.
	 * 
	 * @return read byte
	 * @throws IllegalArgumentException if no bytes are available
	 */
	private int readByte() {
		try {
			// try to read from byte stream
			int val = byteStream.read();

			if (val < 0) {
				// end of stream reached
				throw new IllegalArgumentException("requested byte exceeds available bytes!");
			}
			return val;
		} catch (IOException e) {
			throw new IllegalArgumentException("request byte fails!", e);
		}
	}

	/**
	 * Read bytes from stream.
	 * 
	 * @param buffer buffer to read bytes in
	 * @param offset offset in buffer to start to read bytes in
	 * @param length number of bytes to read
	 * @param full read always full length, may cause multiple reads on input
	 *            stream.
	 * @return number of actual read bytes.
	 * @throws IllegalArgumentException if no bytes are available
	 */
	private int readBytes(byte[] buffer, int offset, int length, boolean full) {
		try {
			int left = length;
			int read = 0;
			int available;
			while (length > 0 && (available = byteStream.read(buffer, offset + read, left)) > 0) {
				read += available;
				left -= available;
				if (!full) {
					break;
				}
			}
			if (read < length) {
				throw new IllegalArgumentException(
						"requested " + length + " bytes exceeds available " + read + " bytes.");
			}
			return read;
		} catch (IOException e) {
			throw new IllegalArgumentException("request bytes fails!", e);
		}
	}
}
