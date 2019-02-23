/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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

import java.nio.Buffer;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.observe.ObserveNotificationOrderer;

/**
 * A tracker for the blockwise transfer of a response body.
 */
public final class Block2BlockwiseStatus extends BlockwiseStatus {

	private static final Logger LOGGER = LoggerFactory.getLogger(Block2BlockwiseStatus.class.getName());

	/**
	 * Order for notifications according RFC 7641, 4-4.
	 * 
	 * It would be nice if we could get rid of this. Currently, the Cf client
	 * needs it to mark a blockwise transferred notification as such. The
	 * problem is, that the server includes the observe option only in the first
	 * block of the notification and we still need to remember it, when the
	 * last block arrives.
	 */
	private ObserveNotificationOrderer orderer;
	/**
	 * Starting exchange to stop deprecated transfers. 
	 */
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
	public static Block2BlockwiseStatus forOutboundResponse(final Exchange exchange, final Response response, final int preferredBlockSize) {
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(response.getPayloadSize(), response.getOptions().getContentFormat());
		status.response = response;
		status.exchange = exchange;
		if (response.getPayload() != null) {
			status.buf.put(response.getPayload());
			((Buffer)status.buf).flip();
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
	public static Block2BlockwiseStatus forInboundResponse(final Exchange exchange, final Response block, final int maxBodySize) {
		int contentFormat = block.getOptions().getContentFormat();
		int bufferSize = maxBodySize;
		if (block.getOptions().hasSize2()) {
			bufferSize = block.getOptions().getSize2();
		}
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(bufferSize, contentFormat);
		status.setFirst(block);
		status.exchange = exchange;
		Integer observeCount = block.getOptions().getObserve();
		if (observeCount != null && OptionSet.isValidObserveOption(observeCount)) {
			// mark this tracker with the observe no of the block it has been created for
			status.orderer = new ObserveNotificationOrderer(observeCount);
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
	 * @return The tracker.
	 * @throws IllegalArgumentException if the request does not contain a block2 option.
	 */
	public static Block2BlockwiseStatus forRandomAccessRequest(final Exchange exchange, final Request request) {

		BlockOption block2 = request.getOptions().getBlock2();
		if (block2 == null) {
			throw new IllegalArgumentException("request must contain block2 option");
		}
		int contentFormat = request.getOptions().getContentFormat();
		Block2BlockwiseStatus status = new Block2BlockwiseStatus(0, contentFormat);
		status.randomAccess = true;
		status.exchange = exchange;
		status.setCurrentNum(block2.getNum());
		status.setCurrentSzx(block2.getSzx());
		return status;
	}

	private static int determineResponseBlock2Szx(final Exchange exchange, final int preferredBlockSize) {
		if (exchange.getRequest() != null) {
			BlockOption block2 = exchange.getRequest().getOptions().getBlock2();
			if (block2 != null) {
				LOGGER.debug("using block2 szx from early negotiation in request: {}", block2.getSize());
				return block2.getSzx();
			}
		}
		LOGGER.debug("using default preferred block size for response: {}", preferredBlockSize);
		return BlockOption.size2Szx(preferredBlockSize);
	}

	/**
	 * Checks if this tracker tracks a notification.
	 * 
	 * @return {@code true} if this tracker has been created for a transferring
	 *                      the body of a notification.
	 */
	public final synchronized boolean isNotification() {
		return orderer != null;
	}

	/**
	 * Gets the observe option value.
	 * 
	 * @return The value.
	 */
	final synchronized Integer getObserve() {
		return orderer == null ? null : orderer.getCurrent();
	}

	/**
	 * Check, if the provided response is newer than the current transfer.
	 * 
	 * Use {@link #orderer} to check according RFC7641, 4.4.
	 * 
	 * @param response response to check.
	 * @return {@code true}, if response is newer than the current transfer,
	 *         {@code false}, otherwise.
	 */
	public final synchronized boolean isNew(final Response response) {
		if (response == null) {
			throw new NullPointerException("response block must not be null");
		} else {
			if (!response.getOptions().hasObserve()) {
				// none observe exchanges are cleared on sending request
				return false;
			}
			return orderer == null || orderer.isNew(response);
		}
	}

	/**
	 * Check, if the provided exchange matches this transfer.
	 * 
	 * @param exchange exchange to check.
	 * @return {@code true}, if exchange matches this transfer, {@code false},
	 *         otherwise.
	 */
	public final synchronized boolean matchTransfer(Exchange exchange) {
		Integer notification = exchange.getNotificationNumber();
		if (notification != null && orderer != null) {
			return orderer.getCurrent() == notification;
		}
		else {
			return notification == null && orderer == null;
		}
	}

	/**
	 * Adds the payload of an incoming response to the buffer.
	 * 
	 * @param responseBlock The incoming response.
	 * @return {@code true} if the payload could be added.
	 * @throws NullPointerException if response block is {@code null}.
	 * @throws IllegalArgumentException if the response block has no block2 option.
	 */
	public synchronized boolean addBlock(final Response responseBlock) {

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
						LOGGER.debug("response does not contain a single ETag");
						return false;
					} else if (!Arrays.equals(etag, responseBlock.getOptions().getETags().get(0))) {
						LOGGER.debug("response does not contain expected ETag");
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
	public synchronized Response getNextResponseBlock(final BlockOption block2) {

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

		final Response block = new Response(response.getCode());
		block.setDestinationContext(response.getDestinationContext());
		block.setOptions(new OptionSet(response.getOptions()));
		block.addMessageObservers(response.getMessageObservers());
		if (getCurrentNum() != 0) {
			// observe option must only be included in first block
			block.getOptions().removeObserve();
		} else {
			block.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onReadyToSend() {
					// when the request for transferring the first block
					// has been sent out, we copy the token to the
					// original request so that at the end of the
					// blockwise transfer the Matcher can correctly
					// close the overall exchange
					if (response.getToken() == null) {
						response.setToken(block.getToken());
					}
					if (!response.hasMID()) {
						response.setMID(block.getMID());
					}
				}
			});
			block.setType(response.getType());
			if (response.getOptions().getSize2() == null) {
				// indicate overall size to peer
				block.getOptions().setSize2(response.getPayloadSize());
			}
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
			((Buffer)buf).position(from);
			buf.get(blockPayload, 0, length);
			block.setPayload(blockPayload);
		}
		setComplete(!m);

		block.getOptions().setBlock2(getCurrentSzx(), m, getCurrentNum());
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
		Exchange oldExchange;
		synchronized (this) {
			oldExchange = this.exchange;
			// stop old cleanup task
			setBlockCleanupHandle(null);
			this.exchange = null;
		}
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
	 * Complete given new exchange only if this is not the one using by this current block status
	 */
	public final void completeNewTranfer(Exchange newExchange) {
		Exchange oldExchange;
		synchronized (this) {
			oldExchange = this.exchange;
		}
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
		Response response;
		synchronized (this) {
			response = this.response;
		}
		if (response != null) {
			setComplete(true);
			response.onComplete();
			return true;
		}
		return false;
	}

	@Override
	public synchronized String toString() {
		String result = super.toString();
		if (orderer != null || response != null) {
			StringBuilder builder = new StringBuilder(result);
			if (orderer != null) {
				builder.setLength(result.length() - 1);
				builder.append(", observe=").append(orderer.getCurrent()).append("]");
			}
			if (response != null) {
				builder.append(", ").append(response);
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
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 * @throws IllegalArgumentException if the response does not contain the block. Clients
	 *            can check whether a message contains a particular block using the
	 *            {@link Response#hasBlock(BlockOption)} method.
	 */
	public static final void crop(final Response responseToCrop, final BlockOption requestedBlock) {

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

			LOGGER.debug("cropping response body [size={}] to block {}", bodySize, requestedBlock);

			byte[] blockPayload = new byte[length];
			boolean m = to < bodySize;
			responseToCrop.getOptions().setBlock2(requestedBlock.getSzx(), m, requestedBlock.getNum());

			// crop payload -- do after calculation of m in case block==response
			System.arraycopy(responseToCrop.getPayload(), from, blockPayload, 0, length);
			responseToCrop.setPayload(blockPayload);
		}
	}
}
