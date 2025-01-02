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

import org.eclipse.californium.elements.util.DatagramReader;

/**
 * BlockOption represents a Block1 or Block2 option in a CoAP message.
 * <p>
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
 * See <a href="https://tools.ietf.org/html/rfc7959#section-2.2" target=
 * "_blank">RFC 7959, Section 2.2</a> for details.
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

	/**
	 * Maximum block number.
	 * 
	 * @since 4.0
	 */
	public static final int MAXIMUM_BLOCK_NUM = (1 << 20) - 1;

	/**
	 * The encoded block size.
	 * <p>
	 * Values 0 to 6. The resulting block size is calculated by
	 * {@code 2**(SZX + 4)}. The value 7 indicates a special case, see
	 * {@link #BERT_SZX}.
	 */
	private final int szx;
	/**
	 * The "more blocks" indicator.
	 */
	private final boolean m;
	/**
	 * The block number.
	 * <p>
	 * Values 0 to {@code 2**20 - 1}.
	 */
	private final int num;

	/**
	 * Creates a new block option for given values.
	 *
	 * @param szx the szx (encoded block size). Values 0 to 6, and 7 for BERT.
	 * @param m the more indicator
	 * @param num the block number. Values 0 to {@code 2**20-1}.
	 * @throws NullPointerException if definition is {@code null}.
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
	 * @param value the integer representation
	 * @throws NullPointerException if the specified bytes are null
	 * @throws NullPointerException if definition is {@code null}.
	 * @throws IllegalArgumentException if the specified value's length is
	 *             larger than 3
	 */
	public BlockOption(Definition definition, final int value) {
		super(definition, value);
		szx = value & 7;
		m = (value & 8) != 0;
		num = value >> 4;
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
	 * Gets the szx (encoded block size).
	 *
	 * @return the szx (encoded block size). Values 0 to 6. The resulting block
	 *         size is calculated by {@code 2**(SZX + 4)}. The value 7 indicates
	 *         a special case, see {@link #isBERT()}.
	 */
	public int getSzx() {
		return szx;
	}

	/**
	 * Gets the block size where {@code size == 1 << (4 + szx)}.
	 * <p>
	 * If {@link #getSzx()} is {@link #BERT_SZX}, 1024 is returned.
	 *
	 * @return the size
	 * @since 3.0 limit size to 1024 to support BERT.
	 */
	public int getSize() {
		return szx2Size(szx);
	}

	/**
	 * Get the "more blocks" indicator.
	 * <p>
	 * If {@code true} there are more block that follow the message with this
	 * block option.
	 * 
	 * @return {@code true}, if "more blocks" to follow.
	 */
	public boolean isM() {
		return m;
	}

	/**
	 * Gets the num.
	 * <p>
	 * This is the block number of the block message.
	 *
	 * @return the num
	 */
	public int getNum() {
		return num;
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

	/**
	 * Encodes the block parameters into an integer representation.
	 * 
	 * @param szx the encoded block size.
	 * @param m the more blocks indicator
	 * @param num the block number
	 * @return the encoded block parameters
	 * @throws IllegalArgumentException if the szx is &lt; 0 or &gt; 7 or if num
	 *             is not a 20-bit uint.
	 * @since 4.0
	 */
	public static int encode(final int szx, final boolean m, final int num) {
		if (szx < 0 || 7 < szx) {
			throw new IllegalArgumentException("Block option's szx " + szx + " must be between 0 and 7 inclusive");
		} else if (num < 0 || MAXIMUM_BLOCK_NUM < num) {
			throw new IllegalArgumentException(
					"Block option's num " + num + " must be between 0 and " + MAXIMUM_BLOCK_NUM + " inclusive");
		}
		return szx | (m ? 1 << 3 : 0) | num << 4;
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
		public BlockOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			return new BlockOption(this, getIntegerValue(reader, length));
		}

		/**
		 * Creates {@link BlockOption} for this definition.
		 * 
		 * @param szx the szx (encoded block size)
		 * @param m the more block indicator
		 * @param num the number of block
		 * @return created {@link BlockOption}
		 * @throws IllegalArgumentException if values doesn't match the
		 *             definition.
		 */
		public BlockOption create(int szx, boolean m, int num) {
			return new BlockOption(this, szx, m, num);
		}

	}

}
