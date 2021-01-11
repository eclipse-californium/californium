/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextUtil;

/**
 * A tracker for the status of a blockwise transfer of a request or response
 * body.
 * <p>
 * Instances of this class are accessed/modified by the {@code BlockwiseLayer}
 * only.
 */
public abstract class BlockwiseStatus {

	protected final Message firstMessage;

	private final RemoveHandler removeHandler;
	private final KeyUri keyUri;
	private final ByteBuffer buf;
	private final int contentFormat;
	private final int maxTcpBertBulkBlocks;
	private Exchange exchange;
	private EndpointContext followUpEndpointContext;

	private int currentNum;
	private int currentSzx;
	private boolean complete;

	/**
	 * Creates a new blockwise status.
	 * 
	 * @param keyUri key uri of the blockwise transfer
	 * @param removeHandler remove handler for blockwise status
	 * @param exchange exchange of the blockwise transfer
	 * @param first first message of the blockwise transfer
	 * @param maxSize The maximum size of the body to be buffered.
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @since 3.0
	 */
	protected BlockwiseStatus(KeyUri keyUri, RemoveHandler removeHandler, Exchange exchange, Message first,
			int maxSize, int maxTcpBertBulkBlocks) {
		if (keyUri == null) {
			throw new NullPointerException("Key URI must not be null!");
		}
		if (removeHandler == null) {
			throw new NullPointerException("Remove handler must not be null!");
		}
		if (first == null) {
			throw new NullPointerException("First message must not be null!");
		}
		if (maxSize == 0) {
			throw new IllegalArgumentException("max. size must not be 0!");
		}
		this.keyUri = keyUri;
		this.removeHandler = removeHandler;
		this.firstMessage = first;
		this.firstMessage.setProtectFromOffload();
		this.exchange = exchange;
		this.contentFormat = first.getOptions().getContentFormat();
		this.buf = ByteBuffer.allocate(maxSize);
		this.maxTcpBertBulkBlocks = maxTcpBertBulkBlocks;
		if (maxTcpBertBulkBlocks > 1) {
			currentSzx = BlockOption.BERT_SZX;
		}
	}

	/**
	 * The key uri of this blockwise transfer
	 * 
	 * @return key uri
	 * @since 3.0
	 */
	public KeyUri getKeyUri() {
		return keyUri;
	}

	public synchronized boolean isStarting() {
		return currentNum == 0;
	}

	/**
	 * Gets the exchange.
	 * 
	 * @param reset {@code true}, to reset the exchange to {@code null},
	 *            {@code false}, otherwise.
	 * @return the exchange of this blockwise transfer
	 * @since 3.0
	 */
	protected synchronized Exchange getExchange(boolean reset) {
		Exchange result = exchange;
		if (reset) {
			exchange = null;
			followUpEndpointContext = null;
		}
		return result;
	}

	/**
	 * Gets the current block offset. For block2 transfers, this is equal to
	 * {@link #getCurrentPosition()}. For block1 transfers, this is the offset
	 * of the last sent block. In that case, the {@link #getCurrentPosition()}
	 * is the offset of the next block to send.
	 * 
	 * @return The current offset.
	 * @see #getCurrentPosition()
	 * @since 3.0
	 */
	protected final int getCurrentOffset() {
		return currentNum * BlockOption.szx2Size(currentSzx);
	}

	/**
	 * Gets the current block number.
	 *
	 * @return The current number.
	 */
	protected final int getCurrentNum() {
		return currentNum;
	}

	/**
	 * Sets the current block number.
	 *
	 * @param currentNum The new current number.
	 */
	protected final void setCurrentNum(final int currentNum) {
		this.currentNum = currentNum;
	}

	/**
	 * Gets the current szx.
	 *
	 * @return the current szx
	 */
	protected final int getCurrentSzx() {
		return currentSzx;
	}

	/**
	 * Gets the current size in bytes.
	 * 
	 * @return The number of bytes corresponding to the current szx code.
	 */
	protected final int getCurrentSize() {
		return BlockOption.szx2Size(currentSzx);
	}

	/**
	 * Gets the current payload size in bytes.
	 * 
	 * @return The number of bytes corresponding to the current szx code and BERT.
	 */
	protected final int getCurrentPayloadSize() {
		int size = getCurrentSize();
		if (currentSzx == BlockOption.BERT_SZX) {
			size *= maxTcpBertBulkBlocks;
		}
		return size;
	}

	/**
	 * Sets the current szx.
	 *
	 * @param currentSzx the new current szx
	 */
	protected final void setCurrentSzx(final int currentSzx) {
		this.currentSzx = currentSzx;
	}

	/**
	 * Checks whether a given content format matches the content format of this
	 * blockwise transfer.
	 * 
	 * @param format The format to check.
	 * @return {@code true} if this transfer's content format matches the given
	 *         format.
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
	 * 
	 * @param complete {@code true} if all blocks have been transferred.
	 */
	protected final void setComplete(final boolean complete) {
		this.complete = complete;
	}

	/**
	 * Marks the transfer as complete, if not already completed.
	 * <p>
	 * 
	 * @return {@code true}, if the transfer is completed, {@code false}, if the
	 *         transfer was already completed.
	 * @since 3.0
	 */
	public final synchronized boolean complete() {
		boolean complete = !this.complete;
		if (complete) {
			this.complete = true;
		}
		return complete;
	}

	/**
	 * Restart this transfer.
	 * 
	 * @since 3.0
	 */
	public synchronized void restart() {
		((Buffer) buf).position(0);
	}

	/**
	 * Get current buffer position of this transfer.
	 * 
	 * @return get current buffer position of this transfer.
	 * @since 3.0
	 */
	protected int getCurrentPosition() {
		return buf.position();
	}

	/**
	 * Flip blocks buffer.
	 * 
	 * @since 3.0
	 */
	protected final void flipBlocksBuffer() {
		((Buffer) buf).flip();
	}

	/**
	 * Get block from buffer.
	 * 
	 * @param position position of block
	 * @param length length of block
	 * @return byte array, or {@code null}, if no buffer is available. The
	 *         length is truncated to the remaining bytes in buffer.
	 * @since 3.0
	 */
	protected final byte[] getBlock(int position, int length) {
		((Buffer) buf).position(position);
		int len = Math.min(length, buf.remaining());
		byte[] payload = new byte[len];
		buf.get(payload, 0, len);
		return payload;
	}

	/**
	 * Adds a block to the buffer.
	 *
	 * @param block The block to add.
	 * @throws BlockwiseTransferException if buffer overflows.
	 */
	protected final void addBlock(final byte[] block) throws BlockwiseTransferException {
		if (block != null && block.length > 0) {
			if (buf.remaining() < block.length) {
				String msg = String.format("response %d exceeds the left buffer %d", block.length, buf.remaining());
				throw new BlockwiseTransferException(msg, ResponseCode.REQUEST_ENTITY_TOO_LARGE);
			}
			buf.put(block);
		}
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
	 * Gets the buffer's content.
	 * <p>
	 * The buffer will be cleared as part of this method, thus this method
	 * should only be invoked once there are no more blocks to add.
	 * 
	 * @return The bytes contained in the buffer.
	 */
	private final byte[] getBody() {
		((Buffer) buf).flip();
		byte[] body = new byte[buf.remaining()];
		((Buffer) buf.get(body)).clear();
		return body;
	}

	/**
	 * Get the endpoint-context to be used for followup block requests.
	 * 
	 * Use the endpoint-context of the response to support notifies from
	 * different addresses. Restores the
	 * {@link DtlsEndpointContext#KEY_HANDSHAKE_MODE}, if the value is
	 * {@link DtlsEndpointContext#HANDSHAKE_MODE_NONE}.
	 * 
	 * @param blockContext endpoint-context to be used/adapted for follow-up
	 *            requests.
	 * @return endpoint-context for follow-up-requests
	 * @since 2.1
	 */
	public synchronized EndpointContext getFollowUpEndpointContext(EndpointContext blockContext) {
		if (followUpEndpointContext == null
				|| !followUpEndpointContext.getPeerAddress().equals(blockContext.getPeerAddress())) {
			// considering notifies with address changes,
			// use the response's endpoint-context to compensate that
			if (exchange != null) {
				Request request = exchange.getRequest();
				EndpointContext messageContext = request.getDestinationContext();
				followUpEndpointContext = EndpointContextUtil.getFollowUpEndpointContext(messageContext, blockContext);
			} else {
				followUpEndpointContext = blockContext;
			}
		}
		return followUpEndpointContext;
	}

	@Override
	public synchronized String toString() {
		return String.format("[%s: currentNum=%d, currentSzx=%d, bufferSize=%d, complete=%b]", keyUri, currentNum,
				currentSzx, getBufferSize(), complete);
	}

	/**
	 * Copies the properties of the original message this tracker has been
	 * created for to a given message.
	 * 
	 * @param message The message.
	 * @throws NullPointerException if the message is {@code null}.
	 * @throws IllegalStateException if the first message is {@code null} or the
	 *             source context is not defined.
	 */
	public final synchronized void assembleReceivedMessage(final Message message) {

		if (message == null) {
			throw new NullPointerException("message must not be null");
		} else if (firstMessage == null) {
			throw new IllegalStateException("first message is not set");
		} else if (firstMessage.getSourceContext() == null) {
			throw new IllegalStateException("first message has no peer context");
		}
		// The assembled request will contain the options of the first block
		message.setSourceContext(firstMessage.getSourceContext());
		message.setType(firstMessage.getType());
		message.setMID(firstMessage.getMID());
		message.setToken(firstMessage.getToken());
		message.setOptions(firstMessage.getOptions());
		message.getOptions().removeBlock1();
		message.getOptions().removeBlock2();
		if (buf.position() > 0) {
			if (!message.isIntendedPayload()) {
				message.setUnintendedPayload();
			}
			message.setPayload(getBody());
		}
	}

	/**
	 * Prepare outgoing message.
	 * 
	 * @param initialMessage initial message
	 * @param message outgoing message
	 * @param first first outgoing message of transfer.
	 * @throws NullPointerException if one of the messages is {@code null}
	 * @throws IllegalArgumentException if the initial message doesn't have a
	 *             destination context
	 * @since 3.0
	 */
	protected void prepareOutgoingMessage(final Message initialMessage, final Message message, boolean first) {

		if (message == null) {
			throw new NullPointerException("message must not be null!");
		} else if (initialMessage == null) {
			throw new NullPointerException("initial message must not be null!");
		} else if (initialMessage.getDestinationContext() == null) {
			throw new IllegalArgumentException("initial message has no destinationcontext!");
		}
		// The assembled request will contain the options of the first block
		message.setDestinationContext(initialMessage.getDestinationContext());
		message.setType(initialMessage.getType());
		message.setOptions(initialMessage.getOptions());
		message.setMaxResourceBodySize(initialMessage.getMaxResourceBodySize());
		message.addMessageObservers(initialMessage.getMessageObservers());
		if (initialMessage.isUnintendedPayload()) {
			message.setUnintendedPayload();
		}
		if (first && (initialMessage.getToken() == null || !initialMessage.hasMID())) {
			message.addMessageObserver(0, new MessageObserverAdapter() {

				@Override
				public void onReadyToSend() {
					// when the request for transferring the first block
					// has been sent out, we copy the token to the
					// original request so that at the end of the
					// blockwise transfer the Matcher can correctly
					// close the overall exchange
					if (initialMessage.getToken() == null) {
						initialMessage.setToken(message.getToken());
					}
					if (!initialMessage.hasMID()) {
						initialMessage.setMID(message.getMID());
					}
				}
			});
		}
		message.addMessageObserver(new MessageObserverAdapter() {

			@Override
			public void onCancel() {
				removeHandler.remove(BlockwiseStatus.this);
			}

			@Override
			protected void failed() {
				removeHandler.remove(BlockwiseStatus.this);
			}
		});
	}

	/**
	 * Complete current transfer.
	 */
	public void timeoutCurrentTranfer() {
		final Exchange exchange = getExchange(true);
		if (exchange != null && !exchange.isComplete()) {
			exchange.execute(new Runnable() {

				@Override
				public void run() {
					exchange.setTimedOut(exchange.getCurrentRequest());
				}
			});
		}
	}

	/**
	 * Remove handler for blockwise status.
	 * 
	 * @since 3.0
	 */
	public static interface RemoveHandler {

		/**
		 * Remove blockwise status.
		 * 
		 * @param status blockwise status to remove
		 */
		void remove(BlockwiseStatus status);
	}
}
