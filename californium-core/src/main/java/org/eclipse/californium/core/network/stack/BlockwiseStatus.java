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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.nio.ByteBuffer;

import org.eclipse.californium.core.coap.Message;

/**
 * This class represents the status of a blockwise transfer of a request or a
 * response.
 * 
 * This class is package private. Instances of this class are stored inside an
 * exchange and only accessed/modified by the class BlockwiseLayer.
 */
public class BlockwiseStatus {

	public static final int NO_OBSERVE = -1;

	/** The first token to manage blockwise Observe */
	private Message first;

	/** The current num. */
	private int currentNum;

	/** The current szx. */
	private int currentSzx;

	private boolean randomAccess;

	private final int contentFormat;

	/** Indicates whether the blockwise transfer has completed. */
	private boolean complete;

	private int blockCount;

	/*
	 * It would be nice if we could get rid of this. Currently, the Cf client
	 * needs it to mark a blockwise transferred notification as such. The
	 * problem is, that the server includes the observe option only in the first
	 * block of the notification and we still need to remember it, when the
	 * last block arrives (block-14).
	 */
	/** The observe sequence number of this blockwise transfer */
	private int observe = NO_OBSERVE;

	private ByteBuffer buf;

	/**
	 * Instantiates a new blockwise status.
	 * 
	 * @param maxSize The maximum size of the body to be buffered.
	 * @param contentFormat The Content-Format of the body.
	 */
	public BlockwiseStatus(final int maxSize, final int contentFormat) {
		this.buf = ByteBuffer.allocate(maxSize);
		this.contentFormat = contentFormat;
	}

	/**
	 * Instantiates a new blockwise status.
	 *
	 * @param contentFormat the initial Content-Format
	 * @param num the num
	 * @param szx the szx
	 */
	public BlockwiseStatus(int contentFormat, int num, int szx) {
		this.contentFormat = contentFormat;
		this.currentNum = num;
		this.currentSzx = szx;
	}
	
	/**
	 * Gets the first block.
	 *
	 * @return the first block
	 */
	public Message getFirst() {
		return first;
	}

	/**
	 * Sets the first block for transparent blockwise notifications.
	 *
	 * @param first the block to store
	 */
	public void setFirst(final Message first) {
		this.first = first;
	}
	
	/**
	 * Gets the current block number.
	 *
	 * @return The current number.
	 */
	public int getCurrentNum() {
		return currentNum;
	}

	/**
	 * Sets the current block number.
	 *
	 * @param currentNum The new current number.
	 */
	public void setCurrentNum(final int currentNum) {
		this.currentNum = currentNum;
	}

	/**
	 * Gets the current szx.
	 *
	 * @return the current szx
	 */
	public int getCurrentSzx() {
		return currentSzx;
	}

	/**
	 * Sets the current szx.
	 *
	 * @param currentSzx the new current szx
	 */
	public void setCurrentSzx(final int currentSzx) {
		this.currentSzx = currentSzx;
	}

	/**
	 * Checks whether a given content format matches the content format of this
	 * blockwise transfer.
	 * 
	 * @param format The format to check.
	 * @return {@code true} if this transfer's content format matches the given format.
	 */
	public boolean hasContentFormat(final int format) {
		return this.contentFormat == format;
	}

	/**
	 * Checks if is complete.
	 *
	 * @return true, if is complete
	 */
	public boolean isComplete() {
		return complete;
	}

	/**
	 * Sets the complete.
	 *
	 * @param complete the new complete
	 */
	public void setComplete(final boolean complete) {
		this.complete = complete;
	}

	/**
	 * Adds a block to the buffer.
	 *
	 * @param block The block to add.
	 * @return {@code true} if the block could be added to the buffer.
	 */
	public boolean addBlock(final byte[] block) {
		boolean result = false;
		if (block == null) {
			result = true;
		} else if (block != null && buf.remaining() >= block.length) {
			result = true;
			buf.put(block);
		}
		blockCount++;
		return result;
	}

	/**
	 * Gets the number of blocks that have been added to the buffer.
	 *
	 * @return The block count.
	 */
	public int getBlockCount() {
		return blockCount;
	}

	/**
	 * Gets the buffer's content.
	 * <p>
	 * The buffer will be cleared as part of this method, thus this method should
	 * only be invoked once there are no more blocks to add.
	 * 
	 * @return The bytes contained in the buffer.
	 */
	public byte[] getBody() {
		buf.flip();
		byte[] body = new byte[buf.remaining()];
		buf.get(body).clear();
		return body;
	}

	public int getObserve() {
		return observe;
	}

	public void setObserve(final int observe) {
		this.observe = observe;
	}

	@Override
	public String toString() {
		return String.format("[currentNum=%d, currentSzx=%d, complete=%b, random access=%b]",
				currentNum, currentSzx, complete, randomAccess);
	}

	public boolean isRandomAccess() {
		return randomAccess;
	}

	public void setRandomAccess(final boolean randomAccess) {
		this.randomAccess = randomAccess;
	}
}
