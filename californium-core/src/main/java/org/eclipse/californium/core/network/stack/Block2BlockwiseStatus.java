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
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;


/**
 * A tracker for the blockwise transfer of a response body.
 *
 */
final class Block2BlockwiseStatus extends BlockwiseStatus {

	private static final Logger LOGGER = Logger.getLogger(Block2BlockwiseStatus.class.getName());

	private Response response;
	private byte[] etag;

	private Block2BlockwiseStatus(final int bufferSize, final int contentFormat) {
		super(bufferSize, contentFormat);
	}

	/**
	 * Creates a new tracker for sending a response.
	 * 
	 * @param exchange The message exchange the transfer is part of.
	 * @param response The CoAP response to be transferred blockwise.
	 * @param preferredBlockSize The default size to use for individual blocks. If the exchange's request contains
	 *                           an <em> early negotation</em> block2 option then the size indicated by that
	 *                           option is used as the block size.
	 * @return The tracker.
	 */
	static Block2BlockwiseStatus forOutboundResponse(final Exchange exchange, final Response response, final int preferredBlockSize) {
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(response.getPayloadSize(), response.getOptions().getContentFormat());
		status.response = response;
		status.buf.put(response.getPayload());
		status.buf.flip();
		if (response.isNotification()) {
			status.observe = response.getOptions().getObserve();
		}
		status.setCurrentSzx(determineResponseBlock2Szx(exchange, preferredBlockSize));
		return status;
	}

	/**
	 * Creates a new tracker for receiving a response.
	 * 
	 * @param exchange The message exchange the transfer is part of.
	 * @param block The block of the response body.
	 * @param maxBodySize The maximum body size that can be buffered.
	 * @return The tracker.
	 */
	static Block2BlockwiseStatus forInboundResponse(final Exchange exchange, final Response block, final int maxBodySize) {
		int contentFormat = block.getOptions().getContentFormat();
		int bufferSize = maxBodySize;
		if (block.getOptions().hasSize2()) {
			bufferSize = block.getOptions().getSize2();
		}
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(bufferSize, contentFormat);
		status.setFirst(block);
		Integer observeCount = block.getOptions().getObserve();
		if (observeCount != null && OptionSet.isValidObserveOption(observeCount)) {
			// mark this tracker with the observe no of the block it has been created for
			status.observe = observeCount;
			exchange.setNotificationNumber(observeCount);
		}
		if (block.getOptions().getETagCount() > 0) {
			// keep track of ETag included in response
			status.etag = block.getOptions().getETags().get(0);
		}
		return status;
	}

	/**
	 * Creates a new tracker for retrieving an arbitrary block of a resource.
	 * 
	 * @param exchange The message exchange the transfer is part of.
	 * @param request The request for retrieving the block.
	 * @param block2 The options for retrieving the block.
	 * @return The tracker.
	 * @throws IllegalArgumentException if the request does not contain a block2 option.
	 */
	static Block2BlockwiseStatus forRandomAccessRequest(final Exchange exchange, final Request request) {

		BlockOption block2 = request.getOptions().getBlock2();
		if (block2 == null) {
			throw new IllegalArgumentException("request must contain block2 option");
		}
		int contentFormat = request.getOptions().getContentFormat();
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(0, contentFormat);
		status.randomAccess = true;
		status.setCurrentNum(block2.getNum());
		status.setCurrentSzx(block2.getSzx());
		return status;
	}

	private static int determineResponseBlock2Szx(final Exchange exchange, final int preferredBlockSize) {
		if (exchange.getRequest() != null) {
			BlockOption block2 = exchange.getRequest().getOptions().getBlock2();
			if (block2 != null) {
				LOGGER.log(Level.FINE, "using block2 szx from early negotiation in request: {0}", block2.getSize());
				return block2.getSzx();
			}
		}
		LOGGER.log(Level.FINE, "using default preferred block size for response: {0}", preferredBlockSize);
		return BlockOption.size2Szx(preferredBlockSize);
	}

	/**
	 * Checks if a given response is a notification that interferes with this
	 * blockwise transfer.
	 * 
	 * @param responseBlock The response block to check.
	 * @return {@code true} if the response is a new notification and this transfer's
	 *         current block number is &gt; 0.
	 * @throws NullPointerException if the response block is {@code null}.
	 * @throws IllegalArgumentException if the response block has no block2 option.
	 */
	synchronized boolean isInterferingNotification(final Response responseBlock) {
		if (responseBlock == null) {
			throw new NullPointerException("response block must not be null");
		} else {
			BlockOption block2 = responseBlock.getOptions().getBlock2();
			if (block2 == null) {
				throw new IllegalArgumentException("response has no block2 option");
			} else {
				return responseBlock.isNotification() && block2.getNum() == 0 && getCurrentNum() > 0;
			}
		}
	}

	/**
	 * Adds the payload of an incoming response to the buffer.
	 * 
	 * @param responseBlock The incoming response.
	 * @param block2 The block2 option contained in the response.
	 * @return {@code true} if the payload could be added.
	 * @throws NullPointerException if response block is {@code null}.
	 * @throws IllegalArgumentException if the response block has no block2 option.
	 */
	synchronized boolean addBlock(final Response responseBlock) {

		if (responseBlock == null) {
			throw new NullPointerException("response block must not be null");
		} else {

			final BlockOption block2 = responseBlock.getOptions().getBlock2();

			if (block2 == null) {
				throw new IllegalArgumentException("response block has no block2 option");
			} else {
				if (etag != null) {
					// response must contain the same ETag
					if (responseBlock.getOptions().getETagCount() != 1) {
						LOGGER.log(Level.FINE, "response does not contain a single ETag");
						return false;
					} else if (!Arrays.equals(etag, responseBlock.getOptions().getETags().get(0))) {
						LOGGER.log(Level.FINE, "response does not contain expected ETag");
						return false;
					}
				}
				boolean succeeded = addBlock(responseBlock.getPayload());
				if (succeeded) {
					setCurrentNum(block2.getNum());
					setCurrentSzx(block2.getSzx());
				}
				return succeeded;
			}
		}

	}

	/**
	 * Gets the next response block for this transfer.
	 * <p>
	 * This method updates the <em>currentNum</em> and <em>currentSzx</em> properties
	 * with the given block2 option's values and then invokes {@link #getNextResponseBlock()}.
	 * 
	 * @param block2 The block number and size to update this transfer with before
	 *               determining the response block.
	 * @return The response block.
	 * @throws IllegalStateException if this tracker does not contain a response.
	 */
	synchronized Response getNextResponseBlock(final BlockOption block2) {

		if (response == null) {
			throw new IllegalStateException("no response to track");
		}

		setCurrentNum(block2.getNum());
		setCurrentSzx(block2.getSzx());
		return getNextResponseBlock();
	}

	/**
	 * Gets the next response block for this transfer.
	 * <p>
	 * The returned block's payload is determined based on <em>currentNum</em>,
	 * <em>currentSzx</em> and the original response body.
	 * 
	 * @return The response block.
	 * @throws IllegalStateException if this tracker does not contain a response.
	 */
	synchronized Response getNextResponseBlock() {

		if (response == null) {
			throw new IllegalStateException("no response to track");
		}

		Response block = null;
		if (response.isNotification() && getCurrentNum() == 0) {
			block = response;

		} else {

			block = new Response(response.getCode());
			block.setDestination(response.getDestination());
			block.setDestinationPort(response.getDestinationPort());
			block.setOptions(new OptionSet(response.getOptions()));
			// observe option must only be included in first block
			block.getOptions().removeObserve();
			block.addMessageObserver(new MessageObserverAdapter() {
				@Override
				public void onTimeout() {
					response.setTimedOut(true);
				}
			});
		}

		if (getCurrentNum() == 0 && response.getOptions().getSize2() == null) {
			// indicate overall size to peer
			block.getOptions().setSize2(response.getPayloadSize());
		}

		int bodySize = getBufferSize();
		int currentSize = BlockOption.szx2Size(getCurrentSzx());
		int from = getCurrentNum() * currentSize;
		boolean m = false;

		if (0 < bodySize && from < bodySize) {
			int to = Math.min((getCurrentNum() + 1) * currentSize, bodySize);
			int length = to - from;
			byte[] blockPayload = new byte[length];
			m = to < bodySize;

			// crop payload -- do after calculation of m in case block==response
			buf.position(from);
			buf.get(blockPayload, 0, length);
			block.setPayload(blockPayload);

			// do not complete notifications
			block.setLast(!m && !response.getOptions().hasObserve());

			setComplete(!m);

		} else {

			block.setLast(true);
			setComplete(true);
		}
		block.getOptions().setBlock2(getCurrentSzx(), m, getCurrentNum());
		return block;
	}

	/**
	 * Crops a response's payload down to a given block.
	 * 
	 * @param responseToCrop The response containing the (large) payload.
	 * @param requestedBlock The block to crop down to.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 * @throws IllegalArgumentException if the response does not contain the block. Clients
	 *            can check whether a message contains a particular block using the
	 *            {@link Response#hasBlock(BlockOption)} method.
	 */
	static final void crop(final Response responseToCrop, final BlockOption requestedBlock) {

		if (responseToCrop == null) {
			throw new NullPointerException("response message must not be null");
		} else if (requestedBlock == null) {
			throw new NullPointerException("block option must not be null");
		} else if (!responseToCrop.hasBlock(requestedBlock)) {
			throw new IllegalArgumentException("given response does not contain block");
		} else {

			int bodySize = responseToCrop.getPayloadSize();
			int from = requestedBlock.getOffset();
			int to = Math.min((requestedBlock.getNum() + 1) * requestedBlock.getSize(), bodySize);
			int length = to - from;

			LOGGER.log(Level.FINE, "cropping response body [size={0}] to block {1}", new Object[]{ bodySize, requestedBlock });

			byte[] blockPayload = new byte[length];
			boolean m = to < bodySize;
			responseToCrop.getOptions().setBlock2(requestedBlock.getSzx(), m, requestedBlock.getNum());

			// crop payload -- do after calculation of m in case block==response
			System.arraycopy(responseToCrop.getPayload(), from, blockPayload, 0, length);
			responseToCrop.setPayload(blockPayload);
		}
	}
}
