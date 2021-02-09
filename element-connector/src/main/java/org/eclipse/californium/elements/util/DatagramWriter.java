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

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

/**
 * This class describes the functionality to write raw network-ordered datagrams
 * on bit-level.
 */
public final class DatagramWriter {

	private static final int DEFAULT_ARRAY_SIZE = 32;
	private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE >> 1;

	public static final AtomicLong COPIES = new AtomicLong();
	public static final AtomicLong TAKES = new AtomicLong();

	// Attributes //////////////////////////////////////////////////////////////
	private byte[] buffer;
	private int count;

	private byte currentByte;
	private int currentBitIndex;
	private final boolean secureClose;

	// Constructors ////////////////////////////////////////////////////////////

	/**
	 * Creates a new empty writer.
	 */
	public DatagramWriter() {
		this(DEFAULT_ARRAY_SIZE, false);
	}

	/**
	 * Creates a new empty writer with provided {@link #close()} behaviour.
	 * 
	 * @param secureClose {@code true}, clear internal buffer on
	 *            {@link #close()}, {@code false}, don't clear internal buffer.
	 */
	public DatagramWriter(boolean secureClose) {
		this(DEFAULT_ARRAY_SIZE, secureClose);
	}

	/**
	 * Creates a new empty writer with provided initial size.
	 * 
	 * @param size initial size
	 */
	public DatagramWriter(int size) {
		this(size, false);
	}

	/**
	 * Creates a new empty writer with provided initial size.
	 * 
	 * @param size initial size
	 * @param secureClose {@code true}, clear internal buffer on
	 *            {@link #close()}, {@code false}, don't clear internal buffer.
	 */
	public DatagramWriter(int size, boolean secureClose) {
		// initialize underlying byte stream
		this.secureClose = secureClose;
		buffer = new byte[size];
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

		int additional = (numBits + 7) / 8;

		if ((numBits & 0x7) == 0 && !isBytePending()) {
			// byte-wise, no maverick bits left
			ensureBufferSize(additional);
			for (int i = numBits - 8; i >= 0; i -= 8) {
				write((byte) (data >> i));
			}
		} else {
			ensureBufferSize(additional + 1);
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
	 * Writes a sequence of bits to the stream at provided position.
	 * 
	 * @param position position to write.
	 * @param data A Long containing the bits to write.
	 * @param numBits The number of bits to write. 1 to 64.
	 * @throws IllegalArgumentException if the number of bits is not in range
	 *             1..64, or the provided data contains more bits than that
	 *             number.
	 * @since 3.0
	 */
	public void writeLongAt(int position, final long data, final int numBits) {
		int additional = (numBits + 7) / 8;
		if (position + additional > count) {
			ensureBufferSize(position + additional - count);
		}
		int lastCount = count;
		int lastBitIndex = currentBitIndex;
		byte lastByte = currentByte;
		resetCurrentByte();
		count = position;
		writeLong(data, numBits);
		if (count < lastCount) {
			count = lastCount;
			currentByte = lastByte;
			currentBitIndex = lastBitIndex;
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

		int additional = (numBits + 7) / 8;

		if ((numBits & 0x7) == 0 && !isBytePending()) {
			// byte-wise, no maverick bits left
			ensureBufferSize(additional);
			for (int i = numBits - 8; i >= 0; i -= 8) {
				write((byte) (data >> i));
			}
		} else {
			ensureBufferSize(additional + 1);
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
	 * Writes a sequence of bits to the stream at provided position.
	 * 
	 * @param position position to write.
	 * @param data An integer containing the bits to write.
	 * @param numBits The number of bits to write. 1 to 32.
	 * @throws IllegalArgumentException if the number of bits is not in range
	 *             1..32, or the provided data contains more bits than that
	 *             number.
	 * @since 3.0
	 */
	public void writeAt(int position, final int data, final int numBits) {
		int additional = (numBits + 7) / 8;
		if (position + additional > count) {
			ensureBufferSize(position + additional - count);
		}
		int lastCount = count;
		int lastBitIndex = currentBitIndex;
		byte lastByte = currentByte;
		resetCurrentByte();
		count = position;
		write(data, numBits);
		if (count < lastCount) {
			count = lastCount;
			currentByte = lastByte;
			currentBitIndex = lastBitIndex;
		}
	}

	/**
	 * Writes a sequence of bytes to the stream.
	 * 
	 * @param bytes The sequence of bytes to write.
	 */
	public void writeBytes(final byte[] bytes) {

		// check if anything to do at all
		if (bytes == null)
			return;

		writeBytes(bytes, 0, bytes.length);
	}

	/**
	 * Writes a sequence of bytes to the stream.
	 * 
	 * @param bytes The sequence of bytes to write.
	 * @param offset offset of bytes to write
	 * @param length length of bytes to write
	 * @since 3.0
	 */
	public void writeBytes(final byte[] bytes, int offset, int length) {

		// check if anything to do at all
		if (bytes == null || length == 0)
			return;

		// are there bits left to write in buffer?
		if (isBytePending()) {

			for (int i = 0; i < length; i++) {
				write(bytes[i + offset] & 0xff, Byte.SIZE);
			}

		} else {

			// if bit buffer is empty, call can be delegated
			// to byte stream to increase
			write(bytes, offset, length);
		}
	}

	/**
	 * Writes one byte to the stream.
	 * 
	 * @param b The byte to be written.
	 */
	public void writeByte(final byte b) {
		if (isBytePending()) {
			write(b & 0xff, Byte.SIZE);
		} else {
			ensureBufferSize(1);
			write(b);
		}
	}

	/**
	 * Write variable bytes with length.
	 * 
	 * Write first the length of the variable bytes according the size in
	 * {@code numBits}. For {@code null}, {@code -1} is written as length.
	 * 
	 * @param bytes bytes to write
	 * @param numBits number of bits for encoding the length.
	 * @since 3.0
	 */
	public void writeVarBytes(byte[] bytes, int numBits) {
		int varLengthBits = getVarLengthBits(numBits);
		int nullLengthValue = getNullLengthValue(varLengthBits);
		if (bytes == null) {
			write(nullLengthValue, varLengthBits);
		} else {
			if (nullLengthValue == bytes.length) {
				throw new IllegalArgumentException(bytes.length + " bytes is too large for " + numBits + "!");
			}
			if (numBits < varLengthBits && (bytes.length >> numBits) != 0) {
				throw new IllegalArgumentException(String.format("Truncating value %d to %d-bit integer", bytes.length, numBits));
			}
			write(bytes.length, varLengthBits);
			writeBytes(bytes);
		}
	}

	/**
	 * Write Bytes with length.
	 * 
	 * Write first the length of the variable bytes according the size in
	 * {@code numBits}. For {@code null}, {@code -1} is written as length.
	 * 
	 * @param bytes bytes to write
	 * @param numBits number of bits for encoding the length.
	 * @since 3.0
	 */
	public void writeVarBytes(Bytes bytes, int numBits) {
		writeVarBytes(bytes == null ? null : bytes.getBytes(), numBits);
	}

	/**
	 * Create/reserve space in output.
	 * 
	 * @param numBits number of bits to reserve
	 * @return position of created space.
	 * @throws IllegalArgumentException if number of bits doesn't align to bytes
	 *             (multiple of 8).
	 * @throws IllegalStateException if left bits are pending to be written.
	 * @since 3.0
	 */
	public int space(int numBits) {
		if (numBits % Byte.SIZE != 0) {
			throw new IllegalArgumentException(
					"Number of bits must be multiple of " + Byte.SIZE + ", not " + numBits + "!");
		}
		if (isBytePending()) {
			throw new IllegalStateException("bits are pending!");
		}
		int position = count;
		int bytes = numBits / Byte.SIZE;
		ensureBufferSize(bytes);
		count += bytes;
		return position;
	}

	/**
	 * Returns a byte array containing the sequence of bits written.
	 * 
	 * @return The byte array containing the written bits.
	 */
	public byte[] toByteArray() {

		// write any bits left in the buffer to the stream
		writeCurrentByte();

		byte[] byteArray;
		if (buffer.length == count) {
			byteArray = buffer;
			buffer = Bytes.EMPTY;
			TAKES.incrementAndGet();
		} else {
			// retrieve the byte array from the stream
			byteArray = Arrays.copyOf(buffer, count);
			if (secureClose) {
				Arrays.fill(buffer, 0, count, (byte) 0);
			}
			COPIES.incrementAndGet();
		}

		// reset stream for the sake of consistency
		count = 0;

		// return the byte array
		return byteArray;
	}

	/**
	 * Write content of provided writer.
	 * 
	 * @param data writer with content to write
	 */
	public void write(DatagramWriter data) {
		data.writeCurrentByte();
		write(data.buffer, 0, data.count);
	}

	/**
	 * Write content to provided stream.
	 * 
	 * @param out stream to write
	 * @throws IOException if an i/o-error occurred
	 * @since 3.0
	 */
	public void writeTo(OutputStream out) throws IOException {
		writeCurrentByte();
		out.write(buffer, 0, count);
		count = 0;
	}

	/**
	 * Write size at the provided position.
	 * 
	 * This size includes all bytes after the size-field up to the current end.
	 * Intended for fast and simple length encoding.
	 * 
	 * <pre>
	 * writer.writeByte(type);
	 * int position = writer.space(Short.SIZE);
	 * writer.write ... n-bytes
	 * ...
	 * writer.writeSize(position, Short.SIZE);
	 * </pre>
	 * 
	 * Results is.
	 * 
	 * <pre>
	 *  type, n (Short, 16bit), n-bytes
	 * </pre>
	 * 
	 * @param position byte position of size. Maybe return value of
	 *            {@link #space(int)}.
	 * @param numBits number of bits used for the size.
	 * @throws IllegalArgumentException if number of bits doesn't align to bytes
	 *             (multiple of 8).
	 * @since 3.0
	 */
	public void writeSize(int position, int numBits) {
		if (numBits % Byte.SIZE != 0) {
			throw new IllegalArgumentException(
					"Number of bits must be multiple of " + Byte.SIZE + ", not " + numBits + "!");
		}
		int size = count - position - (numBits / Byte.SIZE);
		writeAt(position, size, numBits);
	}

	/**
	 * Current size of written data.
	 * 
	 * @return number of currently written bytes.
	 */
	public int size() {
		return count;
	}

	/**
	 * Reset writer. If {@link #DatagramWriter(boolean)} secure close is
	 * enabled, clear the related byte array before releasing it.
	 * 
	 * @since 3.0
	 */
	public void reset() {
		if (secureClose) {
			Arrays.fill(buffer, 0, count, (byte) 0);
		}
		count = 0;
	}

	/**
	 * Close writer, release resources. If {@link #DatagramWriter(boolean)}
	 * secure close is enabled, clear the related byte array before releasing
	 * it.
	 */
	public void close() {
		reset();
		buffer = Bytes.EMPTY;
	}

	/**
	 * Writes pending bits to the stream.
	 */
	public void writeCurrentByte() {
		if (isBytePending()) {
			ensureBufferSize(1);
			write(currentByte);
			resetCurrentByte();
		}
	}

	/**
	 * Check, if a incomplete byte pending.
	 * @return {@code true}, if bits are pending, {@code false}, otherwise.
	 */
	public final boolean isBytePending() {
		return currentBitIndex < Byte.SIZE - 1;
	}

	/**
	 * Reset the current pending byte.
	 */
	private final void resetCurrentByte() {
		currentByte = 0;
		currentBitIndex = Byte.SIZE - 1;
	}

	/**
	 * Write bytes array (internal).
	 * 
	 * Calls {@link #ensureBufferSize(int)}.
	 * 
	 * @param b bytes to write
	 * @param offset offset of bytes to write
	 * @param length length of bytes to write
	 * @since 3.0
	 */
	private final void write(byte[] b, int offset, int length) {
		if (b != null && length > 0) {
			ensureBufferSize(length);
			System.arraycopy(b, offset, buffer, count, length);
			count += length;
		}
	}

	/**
	 * Write byte (internal).
	 * 
	 * Doesn't call {@link #ensureBufferSize(int)}, that must be called ahead!
	 * 
	 * @param b byte to write
	 * @since 3.0
	 */
	private final void write(byte b) {
		buffer[count++] = b;
	}

	/**
	 * Ensure buffer size.
	 * 
	 * Enlarge buffer, if additional size exceed the current allocated buffer.
	 * 
	 * @param add additional bytes
	 * @since 3.0
	 */
	private final void ensureBufferSize(int add) {
		int size = count + add;
		if (size > buffer.length) {
			int newSize = calculateBufferSize(size);
			setBufferSize(newSize);
		}
	}

	/**
	 * Set new buffer size.
	 * 
	 * Increase buffer size, copy already written data.
	 * 
	 * @param size new buffer size.
	 * @since 3.0
	 */
	private final void setBufferSize(int size) {
		byte[] newBuffer = new byte[size];
		System.arraycopy(buffer, 0, newBuffer, 0, count);
		if (secureClose) {
			Arrays.fill(buffer, 0, count, (byte) 0);
		}
		buffer = newBuffer;
	}

	/**
	 * Calculate new buffer size.
	 * 
	 * @param size new desired size
	 * @return new calculated size
	 * @since 3.0
	 */
	private final int calculateBufferSize(int size) {
		int newSize = buffer.length;
		if (newSize == 0) {
			newSize = DEFAULT_ARRAY_SIZE;
		}
		if (newSize < size) {
			newSize = size;
		} else if (newSize > MAX_ARRAY_SIZE) {
			newSize = MAX_ARRAY_SIZE;
		}
		return newSize;
	}

	public static int getVarLengthBits(int numBits) {
		if (numBits % 8 != 0) {
			numBits &= 0xfffffff8;
			numBits += 8;
		}
		return numBits;
	}

	public static int getNullLengthValue(int varLengthBits) {
		switch (varLengthBits) {
		case 8:
			return 0xff;
		case 16:
			return 0xffff;
		case 24:
			return 0xffffff;
		case 32:
			return 0xffffffff;
		}
		throw new IllegalArgumentException("Var length Bits must be a multiple of 8, not " + varLengthBits + "!");
	}

	// Utilities ///////////////////////////////////////////////////////////////

	@Override
	public String toString() {
		byte[] byteArray = Arrays.copyOf(buffer, count);
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
