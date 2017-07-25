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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Move isNotification and getObserve
 *                                                    to Block2BlockwiseStatus
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.nio.ByteBuffer;
import java.util.concurrent.ScheduledFuture;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;

/**
 * A tracker for the status of a blockwise transfer of a request or response body.
 * <p>
 * Instances of this class are accessed/modified by the {@code BlockwiseLayer} only.
 */
abstract class BlockwiseStatus {

	private static final Logger LOGGER = Logger.getLogger(BlockwiseStatus.class.getName());

	private final int contentFormat;

	protected boolean randomAccess;
	protected final ByteBuffer buf;

	private ScheduledFuture<?> cleanUpTask;
	private Message first;
	private int currentNum;
	private int currentSzx;
	private boolean complete;
	private int blockCount;

	/**
	 * Creates a new blockwise status.
	 * 
	 * @param maxSize The maximum size of the body to be buffered.
	 * @param contentFormat The Content-Format of the body.
	 */
	protected BlockwiseStatus(final int maxSize, final int contentFormat) {
		this.buf = ByteBuffer.allocate(maxSize);
		this.contentFormat = contentFormat;
	}

	/**
	 * Creates a new blockwise status.
	 * <p>
	 * This constructor also sets the maximum size of the body to be buffered to 0.
	 * 
	 * @param contentFormat The Content-Format of the body.
	 * @param num The initial block number.
	 * @param szx The initial block size code.
	 */
	protected BlockwiseStatus(final int contentFormat, final int num, final int szx) {
		this(0, contentFormat);
		this.currentNum = num;
		this.currentSzx = szx;
	}

	/**
	 * Sets the message containing the first block of a blockwise transfer.
	 * <p>
	 * The options of this message are later used when creating the message
	 * containing the re-assembled body.
	 * 
	 * @param first The message.
	 * @see #assembleMessage(Message)
	 */
	final synchronized void setFirst(final Message first) {
		this.first = first;
	}
	
	/**
	 * Gets the current block number.
	 *
	 * @return The current number.
	 */
	final synchronized int getCurrentNum() {
		return currentNum;
	}

	/**
	 * Sets the current block number.
	 *
	 * @param currentNum The new current number.
	 */
	final synchronized void setCurrentNum(final int currentNum) {
		this.currentNum = currentNum;
	}

	/**
	 * Gets the current szx.
	 *
	 * @return the current szx
	 */
	final synchronized int getCurrentSzx() {
		return currentSzx;
	}

	/**
	 * Gets the current size in bytes.
	 * 
	 * @return The number of bytes corresponding to the current szx code.
	 */
	final synchronized int getCurrentSize() {
		return BlockOption.szx2Size(currentSzx);
	}

	/**
	 * Sets the current szx.
	 *
	 * @param currentSzx the new current szx
	 */
	final synchronized void setCurrentSzx(final int currentSzx) {
		this.currentSzx = currentSzx;
	}

	/**
	 * Checks whether a given content format matches the content format of this
	 * blockwise transfer.
	 * 
	 * @param format The format to check.
	 * @return {@code true} if this transfer's content format matches the given format.
	 */
	final boolean hasContentFormat(final int format) {
		return this.contentFormat == format;
	}

	/**
	 * Checks if the transfer has completed.
	 * 
	 * @return {@code true} if all blocks have been transferred.
	 */
	final synchronized boolean isComplete() {
		return complete;
	}

	/**
	 * Marks the transfer as complete.
	 * <p>
	 * Also cancels the <em>cleanUpTask</em> if the transfer is complete.
	 * 
	 * @param complete {@code true} if all blocks have been transferred.
	 */
	protected final synchronized void setComplete(final boolean complete) {
		this.complete = complete;
		if (complete && cleanUpTask != null) {
			cleanUpTask.cancel(false);
			cleanUpTask = null;
		}
	}

	/**
	 * Adds a block to the buffer.
	 *
	 * @param block The block to add.
	 * @return {@code true} if the block could be added to the buffer.
	 */
	final synchronized boolean addBlock(final byte[] block) {

		boolean result = false;
		if (block == null) {
			result = true;
		} else if (block != null && buf.remaining() >= block.length) {
			result = true;
			buf.put(block);
		} else {
			LOGGER.log(
				Level.FINE,
				"resource body exceeds buffer size [{0}]",
				getBufferSize());
		}
		blockCount++;
		return result;
	}

	/**
	 * Gets the capacity of the buffer.
	 * 
	 * @return The capacity in bytes.
	 */
	final synchronized int getBufferSize() {
		return buf.capacity();
	}

	/**
	 * Gets the number of blocks that have been added to the buffer.
	 *
	 * @return The block count.
	 */
	final synchronized int getBlockCount() {
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
	final synchronized byte[] getBody() {
		buf.flip();
		byte[] body = new byte[buf.remaining()];
		buf.get(body).clear();
		return body;
	}

	@Override
	public synchronized String toString() {
		return String.format("[currentNum=%d, currentSzx=%d, bufferSize=%d, complete=%b, random access=%b]",
				currentNum, currentSzx, getBufferSize(), complete, randomAccess);
	}

	/**
	 * Checks whether this status object is used for tracking random block access only.
	 * 
	 * @return {@code true} if this tracker is used for random block access only.
	 */
	final synchronized boolean isRandomAccess() {
		return randomAccess;
	}

	/**
	 * Copies the properties of the original message this tracker has been
	 * created for to a given message.
	 * 
	 * @param message The message.
	 * @throws NullPointerException if the message is {@code null}.
	 */
	final synchronized void assembleMessage(final Message message) {

		if (message == null) {
			throw new NullPointerException("message must not be null");
		} else if (first == null) {
			throw new IllegalStateException("first message is not set");
		}
		// The assembled request will contain the options of the first block
		message.setSource(first.getSource());
		message.setSourcePort(first.getSourcePort());
		message.setType(first.getType());
		message.setMID(first.getMID());
		message.setToken(first.getToken());
		message.setOptions(new OptionSet(first.getOptions()));
		message.getOptions().removeBlock1();
		message.getOptions().removeBlock2();
		message.setPayload(getBody());
	}

	/**
	 * Sets or replaces the handle for this tracker's corresponding clean-up task.
	 * <p>
	 * An already existing handle is used to cancel the existing task before the new handle is
	 * set.
	 * 
	 * @param blockCleanupHandle The handle (may be {@code null}).
	 */
	final synchronized void setBlockCleanupHandle(final ScheduledFuture<?> blockCleanupHandle) {

		if (this.cleanUpTask != null) {
			this.cleanUpTask.cancel(false);
		}
		this.cleanUpTask = blockCleanupHandle;
	}
}
