/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add Exchange to cancel 
 *                                                    a pending blockwise request.
 *    Achim Kraus (Bosch Software Innovations GmbH) - Use ObserveNotificationOrderer
 *                                                    to order notifies.
 *                                                    Add isNew and matchTransfer.
 *                                                    Move isNotification and getObserve
 *                                                    from BlockwiseStatus
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove "is last", not longer meaningful
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix openjdk-11 covariant return types
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Arrays;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.observe.NotificationOrder;
import org.eclipse.californium.elements.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A tracker for the blockwise transfer of a response body.
 */
public final class Block2BlockwiseStatus extends BlockwiseStatus {

	private static final Logger LOGGER = LoggerFactory.getLogger(Block2BlockwiseStatus.class);

	/**
	 * Order for notifications according RFC 7641, 4-4.
	 * 
	 * It would be nice if we could get rid of this. Currently, the Cf client
	 * needs it to mark a blockwise transferred notification as such. The
	 * problem is, that the server includes the observe option only in the first
	 * block of the notification and we still need to remember it, when the last
	 * block arrives.
	 */
	private final NotificationOrder order;
	/**
	 * ETag.
	 */
	private final byte[] etag;

	/**
	 * Create block1wise status.
	 * 
	 * @param keyUri key uri of the blockwise transfer
	 * @param removeHandler remove handler for blockwise status
	 * @param exchange The message exchange the blockwise transfer is part of.
	 * @param response initial response of the blockwise transfer
	 * @param maxSize The maximum size of the body to be buffered.
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @since 3.0
	 */
	private Block2BlockwiseStatus(KeyUri keyUri, RemoveHandler removeHandler, Exchange exchange, Response response,
			int maxSize, int maxTcpBertBulkBlocks) {
		super(keyUri, removeHandler, exchange, response, maxSize, maxTcpBertBulkBlocks);
		Integer observeCount = response.getOptions().getObserve();
		if (observeCount != null && OptionSet.isValidObserveOption(observeCount)) {
			// mark this tracker with the observe no of the block it has been
			// created for
			order = new NotificationOrder(observeCount);
			exchange.setNotificationNumber(observeCount);
		} else {
			order = null;
		}
		if (response.getOptions().getETagCount() > 0) {
			// keep track of ETag included in response
			etag = response.getOptions().getETags().get(0);
		} else {
			etag = null;
		}
	}

	/**
	 * Creates a new tracker for sending a response.
	 * 
	 * @param keyUri key uri of the blockwise transfer
	 * @param removeHandler remove handler for blockwise status
	 * @param exchange The message exchange the blockwise transfer is part of.
	 * @param response initial response of the blockwise transfer
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @return created tracker
	 * @since 3.0
	 */
	public static Block2BlockwiseStatus forOutboundResponse(KeyUri keyUri, RemoveHandler removeHandler,
			Exchange exchange, Response response, int maxTcpBertBulkBlocks) {
		int size = response.getPayloadSize();
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(keyUri, removeHandler, exchange, response, size, maxTcpBertBulkBlocks);
		if (size > 0) {
			try {
				status.addBlock(response.getPayload());
				status.flipBlocksBuffer();
			} catch (BlockwiseTransferException ex) {
				LOGGER.warn("buffer overflow on start", ex);
			}
		}
		return status;
	}

	/**
	 * Creates a new tracker for receiving a response.
	 * 
	 * @param keyUri key uri of the blockwise transfer
	 * @param removeHandler remove handler for blockwise status
	 * @param exchange The message exchange the blockwise transfer is part of.
	 * @param block initial block response of the blockwise transfer
	 * @param maxBodySize The maximum size of the body to be buffered.
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @return created tracker
	 * @since 3.0
	 */
	public static Block2BlockwiseStatus forInboundResponse(KeyUri keyUri, RemoveHandler removeHandler,
			Exchange exchange, Response block, int maxBodySize, int maxTcpBertBulkBlocks) {
		int bufferSize = maxBodySize;
		if (block.getOptions().hasSize2()) {
			bufferSize = block.getOptions().getSize2();
		}
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(keyUri, removeHandler, exchange, block, bufferSize, maxTcpBertBulkBlocks);
		return status;
	}

	/**
	 * Gets the observe option value.
	 * 
	 * @return The value.
	 */
	public final Integer getObserve() {
		return order == null ? null : order.getObserve();
	}

	/**
	 * Check, if the provided response is newer than the current transfer.
	 * 
	 * Use {@link #order} to check according RFC7641, 4.4.
	 * 
	 * @param response response to check.
	 * @return {@code true}, if response is newer than the current transfer,
	 *         {@code false}, otherwise.
	 */
	public final boolean isNew(final Response response) {
		if (response == null) {
			throw new NullPointerException("response block must not be null");
		} else {
			if (!response.getOptions().hasObserve()) {
				// none observe exchanges are cleared on sending request
				return false;
			}
			return order == null || order.isNew(response);
		}
	}

	/**
	 * Check, if the provided exchange matches this transfer.
	 * 
	 * @param exchange exchange to check.
	 * @return {@code true}, if exchange matches this transfer, {@code false},
	 *         otherwise.
	 */
	public final boolean matchTransfer(Exchange exchange) {
		Integer notification = exchange.getNotificationNumber();
		if (notification != null && order != null) {
			return order.getObserve() == notification;
		} else {
			return notification == null && order == null;
		}
	}

	/**
	 * Adds the payload of an incoming response to the buffer.
	 * 
	 * @param responseBlock The incoming response.
	 * @throws NullPointerException if response block is {@code null}.
	 * @throws IllegalArgumentException if the response block has no block2
	 *             option.
	 * @throws BlockwiseTransferException if responseBlock doesn't match the
	 *             current transfer state.
	 */
	public synchronized void addBlock(Response responseBlock) throws BlockwiseTransferException {

		if (responseBlock == null) {
			throw new NullPointerException("response block must not be null");
		} else if (!responseBlock.getOptions().hasBlock2()) {
			throw new IllegalArgumentException("response block has no block2 option");
		}
		int currentOffset = getCurrentPosition();
		int responseOffset = responseBlock.getOptions().getBlock2().getOffset();
		if (currentOffset != responseOffset) {
			String msg = String.format("response offset %d does not match the expected offset %d!", responseOffset,
					currentOffset);
			throw new BlockwiseTransferException(msg);
		}
		if (etag != null) {
			// response must contain the same ETag
			if (responseBlock.getOptions().getETagCount() != 1) {
				throw new BlockwiseTransferException("response does not contain a single ETag");
			} else if (!Arrays.equals(etag, responseBlock.getOptions().getETags().get(0))) {
				throw new BlockwiseTransferException("response does not contain expected ETag");
			}
		}
		addBlock(responseBlock.getPayload());
		setCurrentNum(getCurrentPosition() / getCurrentSize());
	}

	/**
	 * Get a request to request the next block of the body.
	 * 
	 * @param blockSzx block szx of request
	 * @return created request
	 * @throws BlockwiseTransferException if the exchange has already been
	 *             completed.
	 * @throws IllegalArgumentException if blockSzx is not aligned with the
	 *             already sent payload.
	 * @since 3.0
	 */
	public synchronized Request getNextRequestBlock(int blockSzx) throws BlockwiseTransferException {
		Exchange exchange = getExchange(false);
		if (exchange == null) {
			throw new BlockwiseTransferException("Block2 exchange already completed!", true);
		}

		setCurrentSzx(blockSzx);
		int size = getCurrentSize();
		int from = getCurrentPosition();

		if (from % size != 0) {
			throw new BlockwiseTransferException(
					"Block2 buffer position " + from + " doesn't align with blocksize " + size + "!");
		}

		int num = from / size;
		setCurrentNum(num);

		Request request = exchange.getRequest();
		Request block = new Request(request.getCode());
		prepareOutgoingMessage(request, block, num == 0);
		block.getOptions().removeObserve();
		block.getOptions().setBlock2(blockSzx, false, num);
		return block;
	}

	/**
	 * Gets the next response block for this transfer.
	 * 
	 * The returned response's payload is determined based on
	 * {@link BlockOption#getOffset()} and {@link BlockOption#getSize()} of the
	 * provided {@link BlockOption}, and the original response's body.
	 * 
	 * @param block2 The block number and size to update this transfer with
	 *            before determining the response block.
	 * @return The response block.
	 * @throws NullPointerException if block2 is {@code null}
	 */
	public synchronized Response getNextResponseBlock(final BlockOption block2) {

		if (block2 == null) {
			throw new NullPointerException("block option must not be null.");
		}

		// parameter according incoming request
		int from = block2.getOffset();
		int szx = block2.getSzx();
		int size = block2.getSize();

		setCurrentSzx(szx);

		int num = from / size;
		setCurrentNum(num);

		final Response block = new Response(((Response) firstMessage).getCode());
		int bodySize = getBufferSize();

		prepareOutgoingMessage(firstMessage, block, num == 0);
		if (num == 0) {
			if (!block.getOptions().hasSize2()) {
				// indicate overall size to peer
				block.getOptions().setSize2(bodySize);
			}
		} else {
			// observe option must only be included in first block
			block.getOptions().removeObserve();
			// for notifies the response type may differ from the first
			block.setType(null);
		}

		boolean m = false;

		if (0 < bodySize && from < bodySize) {
			byte[] blockPayload = getBlock(from, getCurrentPayloadSize());
			m = from + blockPayload.length < bodySize;
			block.setPayload(blockPayload);
		}
		block.getOptions().setBlock2(szx, m, num);
		if (!m) {
			setComplete(true);
		}
		return block;
	}

	/**
	 * Complete transfer. If the blockwise transfer is based on the same
	 * exchange then the new response, just complete the current request and
	 * reset the currentRequest to the original request. If the exchanges are
	 * different, complete the old exchange.
	 * 
	 * @param newExchange new exchange
	 */
	public final void completeOldTransfer(Exchange newExchange) {
		Exchange oldExchange = getExchange(true);
		if (oldExchange != null) {
			if (newExchange != oldExchange) {
				// complete old exchange
				if (oldExchange.isNotification()) {
					// no pending observe request to cancel
					oldExchange.executeComplete();
				} else {
					// cancel pending observe request
					oldExchange.getRequest().setCanceled(true);
				}
			} else {
				// reset to origin request
				oldExchange.setCurrentRequest(oldExchange.getRequest());
			}
		}
	}

	/**
	 * Complete given new exchange only if this is not the one using by this
	 * current block status
	 * 
	 * @param newExchange new exchange.
	 */
	public final void completeNewTranfer(Exchange newExchange) {
		Exchange oldExchange = getExchange(false);
		if (newExchange != oldExchange) {
			if (newExchange.isNotification()) {
				// no pending observe request to cancel
				newExchange.setComplete();
			} else {
				// cancel pending observe request
				newExchange.getRequest().setCanceled(true);
			}
		}
	}

	final boolean completeResponse() {
		if (complete()) {
			Response response;
			synchronized (this) {
				response = (Response) this.firstMessage;
			}
			if (response != null) {
				response.onTransferComplete();
				return true;
			}
		}
		return false;
	}

	@Override
	public synchronized String toString() {
		String result = super.toString();
		if (order != null) {
			StringBuilder builder = new StringBuilder(result);
			if (order != null) {
				builder.setLength(result.length() - 1);
				builder.append(", observe=").append(order.getObserve()).append("]");
			}
			result = builder.toString();
		}
		return result;
	}

	/**
	 * Crops a response's payload down to a given block.
	 * 
	 * @param responseToCrop The response containing the (large) payload.
	 * @param requestedBlock The block to crop down to.
	 * @param maxTcpBertBulkBlocks The maximum number of bulk blocks for
	 *            TCP/BERT. {@code 1} or less, disable BERT.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 * @throws IllegalArgumentException if the response does not contain the
	 *             block. Clients can check whether a message contains a
	 *             particular block using the
	 *             {@link Response#hasBlock(BlockOption)} method.
	 */
	public static final void crop(final Response responseToCrop, final BlockOption requestedBlock, int maxTcpBertBulkBlocks) {

		if (responseToCrop == null) {
			throw new NullPointerException("response message must not be null");
		} else if (requestedBlock == null) {
			throw new NullPointerException("block option must not be null");
		} else if (!responseToCrop.hasBlock(requestedBlock)) {
			throw new IllegalArgumentException("given response does not contain block ");
		} else {

			int bodySize = responseToCrop.getPayloadSize();
			int from = requestedBlock.getOffset();
			if (responseToCrop.getOptions().hasBlock2()) {
				from -= responseToCrop.getOptions().getBlock2().getOffset();
			}
			int size = requestedBlock.getSize();
			if (requestedBlock.isBERT()) {
				size *= maxTcpBertBulkBlocks;
			}
			int to = Math.min(from + size, bodySize);
			int length = to - from;
			boolean m = to < bodySize;
			responseToCrop.getOptions().setBlock2(requestedBlock.getSzx(), m, requestedBlock.getNum());

			LOGGER.debug("cropping response body [size={}] to block {}", bodySize, requestedBlock);

			if (length > 0) {
				byte[] blockPayload = new byte[length];

				// crop payload -- do after calculation of m in case
				// block==response
				System.arraycopy(responseToCrop.getPayload(), from, blockPayload, 0, length);
				responseToCrop.setPayload(blockPayload);
			} else {
				responseToCrop.setPayload(Bytes.EMPTY);
			}
		}
	}
}
