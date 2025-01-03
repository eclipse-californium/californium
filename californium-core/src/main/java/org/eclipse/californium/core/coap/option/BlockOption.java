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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - add block size also in bytes
 *                                                    to return value of toString() 
 *                                                    (for message tracing)
 ******************************************************************************/
package org.eclipse.californium.core.coap.option;

import org.eclipse.californium.elements.util.Bytes;

/**
 * BlockOption represents a Block1 or Block2 option in a CoAP message.
 * 
 * @since 4.0 (moved from package org.eclipse.californium.core.coap)
 */
public final class BlockOption extends IntegerOption {

	/**
	 * SZX for BERT blockwise.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc8323#section-6" target=
	 * "_blank">RFC8323, 6. Block-Wise Transfer and Reliable Transports</a>.
	 * 
	 * @since 3.0
	 */
	public static final int BERT_SZX = 7;

	private final int szx;
	private final boolean m;
	private final int num;

	/**
	 * Creates a new block option for given values.
	 *
	 * @param szx the szx
	 * @param m the more indicator
	 * @param num the num
	 * @throws IllegalArgumentException if the szx is &lt; 0 or &gt; 7 or if num
	 *             is not a 20-bit uint.
	 */
	public BlockOption(Definition definition, final int szx, final boolean m, final int num) {
		super(definition, encode(szx, m, num));
		this.szx = szx;
		this.m = m;
		this.num = num;
	}

	/**
	 * Instantiates a new block option from the specified bytes (1-3 bytes).
	 *
	 * @param value the bytes
	 * @throws NullPointerException if the specified bytes are null
	 * @throws IllegalArgumentException if the specified value's length is
	 *             larger than 3
	 */
	public BlockOption(Definition definition, final byte[] value) {
		super(definition, value);
		if (value == null) {
			throw new NullPointerException();
		} else if (value.length > 3) {
			throw new IllegalArgumentException(
					"Block option's length " + value.length + " must be at most 3 bytes inclusive");
		} else if (value.length == 0) {
			this.szx = 0;
			this.m = false;
			this.num = 0;

		} else {
			byte end = value[value.length - 1];
			this.szx = end & 0x7;
			this.m = (end >> 3 & 0x1) == 1;
			int tempNum = (end & 0xFF) >> 4;
			for (int i = 1; i < value.length; i++) {
				tempNum += ((value[value.length - i - 1] & 0xff) << (i * 8 - 4));
			}
			this.num = tempNum;
		}
	}

	@Override
	public Definition getDefinition() {
		return (Definition) super.getDefinition();
	}

	/**
	 * Indicates, that BERT is used.
	 * 
	 * @return {@code true}, if BERT is used, {@code false}, otherwise.
	 * @see #BERT_SZX See
	 *      <a href="https://tools.ietf.org/html/rfc8323#section-6" target=
	 *      "_blank">RFC8323, 6. Block-Wise Transfer and Reliable
	 *      Transports</a>.
	 * @since 3.0
	 */
	public boolean isBERT() {
		return szx == BERT_SZX;
	}

	/**
	 * Assert, that the payload-size doesn't exceed blocksize.
	 * 
	 * @param payloadSize payload-size to check.
	 * @throws IllegalStateException if the payload-size exceeds the blocksize.
	 */
	public void assertPayloadSize(int payloadSize) {
		if (szx < BERT_SZX && payloadSize > 0) {
			int size = getSize();
			if (payloadSize > size) {
				throw new IllegalStateException(
						"Message with " + payloadSize + " bytes payload exceeds the blocksize of " + size + " bytes!");
			}
		}
	}

	/**
	 * Gets the szx.
	 *
	 * @return the szx
	 */
	public int getSzx() {
		return szx;
	}

	/**
	 * Gets the size where {@code size == 1 << (4 + szx)}.
	 * 
	 * If {@link #getSzx()} is {@link #BERT_SZX}, 1024 is returned.
	 *
	 * @return the size
	 * @since 3.0 limit size to 1024 to support BERT.
	 */
	public int getSize() {
		return szx2Size(szx);
	}

	/**
	 * Checks if is m. The value m is true if there are more block that follow
	 * the message with this block option.
	 * 
	 * @return true, if is m
	 */
	public boolean isM() {
		return m;
	}

	/**
	 * Gets the num. This is the number of the block message.
	 *
	 * @return the num
	 */
	public int getNum() {
		return num;
	}

	/**
	 * Gets the encoded block option as 0-3 byte array.
	 * 
	 * The value of the Block Option is a variable-size (0 to 3 byte).
	 * <hr>
	 * <blockquote>
	 * 
	 * <pre>
	 *  0
	 *  0 1 2 3 4 5 6 7
	 * +-+-+-+-+-+-+-+-+
	 * |  NUM  |M| SZX |
	 * +-+-+-+-+-+-+-+-+
	 *  0                   1
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |          NUM          |M| SZX |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  0                   1                   2
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                   NUM                 |M| SZX |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * </pre>
	 * 
	 * </blockquote>
	 * <hr>
	 * 
	 * @return the value
	 */
	public byte[] getValue() {
		return super.getValue();
	}

	/**
	 * Gets the offset into a body this block option represents.
	 * 
	 * @return The offset calculated as num * size.
	 */
	public int getOffset() {
		return num * szx2Size(szx);
	}

	@Override
	public String toValueString() {
		return String.format("(szx=%d/%d, m=%b, num=%d)", szx, szx2Size(szx), m, num);
	}

	@Override
	public boolean equals(final Object o) {
		if (!(o instanceof BlockOption)) {
			return false;
		}
		BlockOption block = (BlockOption) o;
		return szx == block.szx && num == block.num && m == block.m;
	}

	@Override
	public int hashCode() {
		int result = szx;
		result = 31 * result + (m ? 1 : 0);
		result = 31 * result + num;
		return result;
	}

	/**
	 * Gets the 3-bit SZX code for a block size as specified by
	 * <a href="https://tools.ietf.org/html/rfc7959#section-2.2" target=
	 * "_blank">RFC 7959, Section 2.2</a>:
	 * 
	 * <pre>
	 * 16 bytes = 2^4 --&gt; 0
	 * ... 
	 * 1024 bytes = 2^10 -&gt; 6
	 * </pre>
	 * <p>
	 * This method is tolerant towards <em>illegal</em> block sizes that are
	 * &lt; 16 or &gt; 1024 bytes in that it will return the corresponding codes
	 * for sizes 16 or 1024 respectively.
	 * 
	 * @param blockSize The block size in bytes.
	 * @return The szx code for the largest number of bytes that is less than or
	 *         equal to the block size.
	 */
	public static int size2Szx(int blockSize) {

		if (blockSize >= 1024) {
			return 6;
		} else if (blockSize <= 16) {
			return 0;
		} else {
			int maxOneBit = Integer.highestOneBit(blockSize);
			return Integer.numberOfTrailingZeros(maxOneBit) - 4;
		}
	}

	/**
	 * Gets the number of bytes corresponding to a szx code.
	 * <p>
	 * This method is tolerant towards <em>illegal</em> codes that are &lt; 0 or
	 * &gt; 6 in that it will return the corresponding values for codes 0 or 6
	 * respectively.
	 * 
	 * @param szx The code.
	 * @return The corresponding number of bytes.
	 */
	public static int szx2Size(final int szx) {
		if (szx <= 0) {
			return 16;
		} else if (szx >= 6) {
			return 1024;
		} else {
			return 1 << (szx + 4);
		}
	}

	public static byte[] encode(final int szx, final boolean m, final int num) {
		if (szx < 0 || 7 < szx) {
			throw new IllegalArgumentException("Block option's szx " + szx + " must be between 0 and 7 inclusive");
		} else if (num < 0 || (1 << 20) - 1 < num) {
			throw new IllegalArgumentException(
					"Block option's num " + num + " must be between 0 and " + (1 << 20 - 1) + " inclusive");
		}
		int last = szx | (m ? 1 << 3 : 0);
		if (num == 0 && !m && szx == 0) {
			return Bytes.EMPTY;
		} else if (num < 1 << 4) {
			return new byte[] { (byte) (last | (num << 4)) };
		} else if (num < 1 << 12) {
			return new byte[] { (byte) (num >> 4), (byte) (last | (num << 4)) };
		} else {
			return new byte[] { (byte) (num >> 12), (byte) (num >> 4), (byte) (last | (num << 4)) };
		}
	}

	/**
	 * Definition for {@link BlockOption}.
	 * 
	 * @since 4.0
	 */
	static public class Definition extends IntegerOption.Definition {

		/**
		 * Creates option definition for an block option.
		 * 
		 * @param number option number
		 * @param name option name
		 */
		public Definition(int number, String name) {
			super(number, name, true, 0, 3);
		}

		@Override
		public BlockOption create(byte[] value) {
			if (value == null) {
				throw new NullPointerException("Option " + getName() + " value must not be null.");
			}
			return new BlockOption(this, value);
		}

		/**
		 * Creates {@link BlockOption} for this definition.
		 * 
		 * @param szx the szx
		 * @param m the more block indicator
		 * @param num the number of block
		 * @return created {@link BlockOption}
		 */
		public BlockOption create(int szx, boolean m, int num) {
			return new BlockOption(this, szx, m, num);
		}

	}

}
