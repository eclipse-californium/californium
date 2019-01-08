/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace striped executor
 *                                                    with serial executor
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix openjdk-11 covariant return types
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.concurrent.ScheduledFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.network.Exchange;

/**
 * A tracker for the status of a blockwise transfer of a request or response body.
 * <p>
 * Instances of this class are accessed/modified by the {@code BlockwiseLayer} only.
 */
public abstract class BlockwiseStatus {

	private static final Logger LOGGER = LoggerFactory.getLogger(BlockwiseStatus.class.getName());

	private final int contentFormat;

	protected boolean randomAccess;
	protected final ByteBuffer buf;
	protected Exchange exchange;

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
	 * @see #assembleReceivedMessage(Message)
	 */
	final synchronized void setFirst(final Message first) {
		this.first = first;
	}
	
	/**
	 * Gets the current block number.
	 *
	 * @return The current number.
	 */
	public final synchronized int getCurrentNum() {
		return currentNum;
	}

	/**
	 * Sets the current block number.
	 *
	 * @param currentNum The new current number.
	 */
	public final synchronized void setCurrentNum(final int currentNum) {
		this.currentNum = currentNum;
	}

	/**
	 * Gets the current szx.
	 *
	 * @return the current szx
	 */
	public final synchronized int getCurrentSzx() {
		return currentSzx;
	}

	/**
	 * Gets the current size in bytes.
	 * 
	 * @return The number of bytes corresponding to the current szx code.
	 */
	public final synchronized int getCurrentSize() {
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
	public final boolean hasContentFormat(final int format) {
		return this.contentFormat == format;
	}

	/**
	 * Checks if the transfer has completed.
	 * 
	 * @return {@code true} if all blocks have been transferred.
	 */
	public final synchronized boolean isComplete() {
		return complete;
	}

	/**
	 * Marks the transfer as complete.
	 * <p>
	 * Also cancels the <em>cleanUpTask</em> if the transfer is complete.
	 * 
	 * @param complete {@code true} if all blocks have been transferred.
	 */
	public final synchronized void setComplete(final boolean complete) {
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
	public final synchronized boolean addBlock(final byte[] block) {

		boolean result = false;
		if (block == null) {
			result = true;
		} else if (block != null && buf.remaining() >= block.length) {
			result = true;
			buf.put(block);
		} else {
			LOGGER.debug("resource body exceeds buffer size [{}]", getBufferSize());
		}
		blockCount++;
		return result;
	}

	/**
	 * Gets the capacity of the buffer.
	 * 
	 * @return The capacity in bytes.
	 */
	public final synchronized int getBufferSize() {
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
		((Buffer)buf).flip();
		byte[] body = new byte[buf.remaining()];
		((Buffer)buf.get(body)).clear();
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
	public final synchronized boolean isRandomAccess() {
		return randomAccess;
	}

	/**
	 * Copies the properties of the original message this tracker has been
	 * created for to a given message.
	 * 
	 * @param message The message.
	 * @throws NullPointerException if the message is {@code null}.
	 * @throws IllegalStateException if the first message is {@code null} or the
	 *             source is not defined.
	 */
	public final synchronized void assembleReceivedMessage(final Message message) {

		if (message == null) {
			throw new NullPointerException("message must not be null");
		} else if (first == null) {
			throw new IllegalStateException("first message is not set");
		} else if (first.getSourceContext() == null) {
			throw new IllegalStateException("first message has no peer context");
		} else if (first.getSourceContext().getPeerAddress() == null) {
			throw new IllegalStateException("first message has no peer address");
		}
		// The assembled request will contain the options of the first block
		message.setSourceContext(first.getSourceContext());
		message.setType(first.getType());
		message.setMID(first.getMID());
		message.setToken(first.getToken());
		message.setOptions(new OptionSet(first.getOptions()));
		message.getOptions().removeBlock1();
		message.getOptions().removeBlock2();
		if (!message.isIntendedPayload()) {
			message.setUnintendedPayload();
		}
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
	public final synchronized void setBlockCleanupHandle(final ScheduledFuture<?> blockCleanupHandle) {

		if (this.cleanUpTask != null) {
			this.cleanUpTask.cancel(false);
		}
		this.cleanUpTask = blockCleanupHandle;
	}

	/**
	 * Complete current transfer.
	 */
	public void timeoutCurrentTranfer() {
		final Exchange exchange;
		synchronized (this) {
			exchange = this.exchange;
		}
		if (exchange != null && !exchange.isComplete()) {
			exchange.execute(new Runnable() {

				@Override
				public void run() {
					exchange.setTimedOut(exchange.getCurrentRequest());
				}
			});
		}
	}
}
