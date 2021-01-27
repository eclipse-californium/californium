/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A tracker for the blockwise transfer of a request body.
 */
public final class Block1BlockwiseStatus extends BlockwiseStatus {

	private static final Logger LOGGER = LoggerFactory.getLogger(Block1BlockwiseStatus.class);

	/**
	 * Create block1wise status.
	 * 
	 * @param keyUri key uri of the blockwise transfer
	 * @param removeHandler remove handler for the blockwise status
	 * @param exchange The message exchange the blockwise transfer is part of.
	 * @param request initial request of the blockwise transfer
	 * @param maxSize The maximum size of the body to be buffered.
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @since 3.0
	 */
	private Block1BlockwiseStatus(KeyUri keyUri, RemoveHandler removeHandler, Exchange exchange, Request request,
			int maxSize, int maxTcpBertBulkBlocks) {
		super(keyUri, removeHandler, exchange, request, maxSize, maxTcpBertBulkBlocks);
	}

	/**
	 * Creates a new tracker for sending a request body.
	 * 
	 * @param keyUri key uri of the blockwise transfer
	 * @param removeHandler remove handler for blockwise status
	 * @param exchange The message exchange the transfer is part of.
	 * @param request initial request of the blockwise transfer
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @return The created tracker
	 * @since 3.0
	 */
	public static Block1BlockwiseStatus forOutboundRequest(KeyUri keyUri, RemoveHandler removeHandler,
			Exchange exchange, Request request, int maxTcpBertBulkBlocks) {
		Block1BlockwiseStatus status = new Block1BlockwiseStatus(keyUri, removeHandler, exchange, request,
				request.getPayloadSize(), maxTcpBertBulkBlocks);
		try {
			status.addBlock(request.getPayload());
			status.flipBlocksBuffer();
		} catch (BlockwiseTransferException ex) {
			LOGGER.warn("buffer overflow on start", ex);
		}
		return status;
	}

	/**
	 * Creates a new tracker for receiving a request body.
	 * 
	 * @param keyUri key uri of the blockwise transfer
	 * @param removeHandler remove handler for blockwise status
	 * @param exchange The message exchange the transfer is part of.
	 * @param block first received block request of the blockwise transfer
	 * @param maxBodySize maximum body size
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @return The created tracker
	 * @since 3.0
	 */
	public static Block1BlockwiseStatus forInboundRequest(KeyUri keyUri, RemoveHandler removeHandler, Exchange exchange,
			Request block, int maxBodySize, int maxTcpBertBulkBlocks) {
		int bufferSize = maxBodySize;
		if (block.getOptions().hasSize1()) {
			bufferSize = block.getOptions().getSize1();
		}
		Block1BlockwiseStatus status = new Block1BlockwiseStatus(keyUri, removeHandler, exchange, block, bufferSize,
				maxTcpBertBulkBlocks);
		return status;
	}

	/**
	 * Add payload for received request to blockwise transfer.
	 * 
	 * @param requestBlock received block1 request.
	 * @throws NullPointerException if requestBlock is {@code null}
	 * @throws IllegalArgumentException if requestBlock has no block1 option
	 * @throws BlockwiseTransferException if requestBlock doesn't match the
	 *             current transfer state or overflows the buffer
	 * @since 3.0
	 */
	public synchronized void addBlock(Request requestBlock) throws BlockwiseTransferException {

		if (requestBlock == null) {
			throw new NullPointerException("request block must not be null");
		}
		BlockOption block1 = requestBlock.getOptions().getBlock1();
		if (block1 == null) {
			throw new IllegalArgumentException("request block has no block1 option");
		}
		int from = getCurrentPosition();
		int offset = block1.getOffset();
		if (from != offset) {
			throw new BlockwiseTransferException(
					"request block1 offset " + offset + " doesn't match the current position " + from + "!",
					ResponseCode.REQUEST_ENTITY_INCOMPLETE);
		}
		addBlock(requestBlock.getPayload());
		if (block1.isM()) {
			setCurrentSzx(block1.getSzx());
			int size = block1.getSize();
			from = getCurrentPosition();
			if (from % size != 0) {
				throw new BlockwiseTransferException(
						"Block1 buffer position " + from + " doesn't align with blocksize " + size + "!",
						ResponseCode.REQUEST_ENTITY_INCOMPLETE);
			}
			setCurrentNum(from / size);
		}
	}

	/**
	 * Get a request for sending the next block of the body.
	 * 
	 * The returned request's payload is determined based on
	 * {@link #getCurrentPosition()}, the provided {@code blockSzx}, and the
	 * original request's body.
	 * 
	 * @param blockSzx the block szx for the request
	 * @return the create request
	 * @throws BlockwiseTransferException if blockSzx is not aligned with the
	 *             already sent payload
	 * @since 3.0
	 */
	public synchronized Request getNextRequestBlock(int blockSzx) throws BlockwiseTransferException {
		setCurrentSzx(blockSzx);
		int size = getCurrentSize();
		int from = getCurrentPosition();

		if (from % size != 0) {
			throw new BlockwiseTransferException(
					"Block1 buffer position " + from + " doesn't align with blocksize " + size + "!");
		}

		boolean m = false;
		int bodySize = getBufferSize();
		int num = from / size;
		setCurrentNum(num);

		Request block = new Request(((Request) firstMessage).getCode());
		prepareOutgoingMessage(firstMessage, block, num == 0);
		if (num == 0) {
			// indicate overall body size to peer
			if (!block.getOptions().hasSize1()) {
				block.getOptions().setSize1(bodySize);
			}
		} else {
			block.getOptions().removeSize1();
			// see https://tools.ietf.org/html/rfc7959#section-2.10
			block.getOptions().setIfNoneMatch(false);
		}

		if (0 < bodySize && from < bodySize) {
			byte[] blockPayload = getBlock(from, getCurrentPayloadSize());
			if (blockPayload != null) {
				m = from + blockPayload.length < bodySize;
				block.setPayload(blockPayload);
			}
		}
		block.getOptions().setBlock1(blockSzx, m, num);

		setComplete(!m);
		return block;
	}

	/**
	 * Cancels the request that started the block1 transfer that this is the
	 * tracker for.
	 * <p>
	 * {@link #complete()} status and invokes {@link Request#cancel()}, when
	 * {@code true} gets returned.
	 * 
	 * @return {@code true}, if the transfer is completed, {@code false}, if the
	 *         transfer was already completed.
	 * @since 3.0 the return values was added.
	 */
	public boolean cancelRequest() {
		if (complete()) {
			Request request = (Request) this.firstMessage;
			request.cancel();
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Checks whether a response has the same token as the request that
	 * initiated the block1 transfer that this is the tracker for.
	 * 
	 * @param response The response to check.
	 * @return {@code true} if the tokens match.
	 */
	public boolean hasMatchingToken(final Response response) {
		return response.getToken().equals(firstMessage.getToken());
	}
}
