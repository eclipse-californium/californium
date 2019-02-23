/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;


/**
 * A tracker for the blockwise transfer of a request body.
 *
 */
public final class Block1BlockwiseStatus extends BlockwiseStatus {

	private Request request;

	private Block1BlockwiseStatus(final int bufferSize, final int contentFormat) {
		super(bufferSize, contentFormat);
	}

	/**
	 * Creates a new tracker for sending a request body.
	 * 
	 * @param exchange The message exchange the transfer is part of.
	 * @param request The CoAP request containing the large body in its payload.
	 * @param preferredBlockSize The size to use for individual blocks.
	 * @return The tracker.
	 */
	public static Block1BlockwiseStatus forOutboundRequest(final Exchange exchange, final Request request, final int preferredBlockSize) {
		Block1BlockwiseStatus status = new Block1BlockwiseStatus(0, request.getOptions().getContentFormat());
		status.request = request;
		status.exchange = exchange;
		status.setCurrentSzx(BlockOption.size2Szx(preferredBlockSize));
		return status;
	}

	/**
	 * Creates a new tracker for receiving a request body.
	 * 
	 * @param exchange The message exchange the transfer is part of.
	 * @param block The block of the request body.
	 * @param maxBodySize The maximum body size that can be buffered.
	 * @return The tracker.
	 */
	public static Block1BlockwiseStatus forInboundRequest(final Exchange exchange, final Request block, final int maxBodySize) {
		int contentFormat = block.getOptions().getContentFormat();
		int bufferSize = maxBodySize;
		if (block.getOptions().hasSize1()) {
			bufferSize = block.getOptions().getSize1();
		}
		Block1BlockwiseStatus status = new Block1BlockwiseStatus(bufferSize, contentFormat);
		status.exchange = exchange;
		status.setFirst(block);
		return status;
	}

	/**
	 * Gets a request or sending the next block of the body.
	 * <p>
	 * This method updates the <em>currentNum</em> and <em>currentSzx</em> properties
	 * with the given block1 option's values and then invokes {@link #getNextRequestBlock()}.
	 * 
	 * @param num The block number to update this tracker with before
	 *               determining the response block.
	 * @param szx The adapted block size to update this tracker with before
	 *               determining the response block.
	 * @return The request.
	 * @throws IllegalStateException if this tracker does not contain a request body.
	 */
	public synchronized Request getNextRequestBlock(final int num, final int szx) {

		if (request == null) {
			throw new IllegalStateException("no request body");
		}

		setCurrentNum(num);
		setCurrentSzx(szx);
		return getNextRequestBlock();
	}

	/**
	 * Gets a request or sending the next block of the body.
	 * <p>
	 * The returned request's payload is determined based on <em>currentNum</em>,
	 * <em>currentSzx</em> and the original request's body.
	 * 
	 * @return The request.
	 * @throws IllegalStateException if this tracker does not contain a request body.
	 */
	public synchronized Request getNextRequestBlock() {

		if (request == null) {
			throw new IllegalStateException("no request body");
		}

		int num = getCurrentNum();
		int szx = getCurrentSzx();

		Request block = new Request(request.getCode());
		// do not enforce CON, since NON could make sense over SMS or similar transports
		block.setType(request.getType());
		block.setDestinationContext(request.getDestinationContext());
		// copy options
		block.setOptions(new OptionSet(request.getOptions()));
		// copy message observers so that a failing blockwise request
		// also notifies observers registered with the original request
		block.addMessageObservers(request.getMessageObservers());

		if (num == 0) {
			// indicate overall body size to peer
			block.getOptions().setSize1(request.getPayloadSize());
		}
		if (request.isUnintendedPayload()) {
			block.setUnintendedPayload();
		}

		int currentSize = getCurrentSize();
		int from = num * currentSize;
		int to = Math.min((num + 1) * currentSize, request.getPayloadSize());
		int length = to - from;
		if (length > 0) {
			byte[] blockPayload = new byte[length];
			System.arraycopy(request.getPayload(), from, blockPayload, 0, length);
			block.setPayload(blockPayload);
		}
		boolean m = (to < request.getPayloadSize());
		block.getOptions().setBlock1(szx, m, num);

		setComplete(!m);
		return block;
	}

	/**
	 * Cancels the request that started the block1 transfer that this is the tracker for.
	 * <p>
	 * This method simply invokes {@link Request#cancel()}.
	 */
	public void cancelRequest() {
		if (request != null) {
			request.cancel();
		}
	}

	/**
	 * Checks whether a response has the same token as the request that initiated
	 * the block1 transfer that this is the tracker for.
	 * 
	 * @param response The response to check.
	 * @return {@code true} if the tokens match.
	 */
	public boolean hasMatchingToken(final Response response) {
		return request != null && response.getToken().equals(request.getToken());
	}
}
