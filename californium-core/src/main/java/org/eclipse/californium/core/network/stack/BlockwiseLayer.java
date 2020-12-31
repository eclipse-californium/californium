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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use exchange.calculateRTT
 *    Achim Kraus (Bosch Software Innovations GmbH) - use new introduced failed() 
 *                                                    instead of onReject() and
 *                                                    onTimeout(). Add onSendError()
 *    Achim Kraus (Bosch Software Innovations GmbH) - use onReadyToSend() to copy token
 *                                                    to fix rare race condition in
 *                                                    block1wise, when the generated
 *                                                    token was copied too late 
 *                                                    (after sending). 
 *    Achim Kraus (Bosch Software Innovations GmbH) - cancel a pending blockwise notify,
 *                                                    if a new request is send.
 *                                                    Please see comment below
 *                                                    sendRequest() for more details.
 *                                                    cancel also the pending requests
 *                                                    of the stale transfer.
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce stop transfer on
 *                                                    received responses generally.
 *                                                    cleanup stale functions.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - keep original response, if
 *                                                    current request is the original
 *    Achim Kraus (Bosch Software Innovations GmbH) - use uniformly the response 
 *                                                    source endpoint context
 *                                                    for next block requests
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - copy token and mid for error responses
 *                                                    copy scheme to assembled blockwise 
 *                                                    payload.
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't cleanup on send response failures.
 *                                                    remove "is last", not longer meaningful
 *                                                    remove addBlock2CleanUpObserver in
 *                                                    sendResponse
 *                                                    add health status logging
 *                                                    for blockwise transfers
 *    Achim Kraus (Bosch Software Innovations GmbH) - use ExecutorsUtil.getScheduledExecutor()
 *                                                    for health status instead of own executor.
 *    Achim Kraus (Bosch Software Innovations GmbH) - disable transparent blockwise for multicast.
 *    Achim Kraus (Bosch Software Innovations GmbH) - extract requestNextBlock from 
 *                                                    tcp_experimental_features branch
 *                                                    for easier merging in the future.
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Iterator;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaults;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides transparent handling of the blockwise transfer of a large <em>resource body</em>.
 * <p>
 * There are four cases in which such <em>transparent</em> blockwise transfers occur:
 * <ul>
 * <li>An outbound request carrying a large body that is too large to be sent in the payload
 * of a single message, is transparently replaced by a sequence of requests transferring individual
 * blocks of the body to the server.</li>
 * <li>An outbound response carrying a large body that is too large to be sent in the payload
 * of a single message, is transparently replaced by a response containing only the first block
 * of the body. The body will be <em>buffered</em> in-memory so that the peer can retrieve the
 * whole body using multiple requests for individual blocks.</li>
 * <li>When an inbound request containing a single block of a large body is received, the payload
 * will be buffered and acknowledged so that the peer can send the rest of the body using a blockwise
 * transfer. Once all blocks have been received, the overall body is re-assembled and forwarded
 * to the {@code Resource} handling the request.</li>
 * <li>When a response is received from a peer containing a single block of a large body is received,
 * the payload will be buffered and a blockwise transfer is started for retrieving the rest of the body.
 * Once all blocks have been received, the overall body is re-assembled and forwarded
 * to the client that has issued the original request.</li>
 * </ul>
 * <p>
 * Block-wise transfer does not support concurrent transfer for the same
 * resource. So using <em>transparent</em> block-wise transfer with CoAP observe
 * is not really advised. When concurrent transfer is detected we always
 * privilege the most recent transfers. This is the most resilient way, as new
 * transfer will never be blocked by old incomplete transfer.
 */
public class BlockwiseLayer extends AbstractLayer {

	// TODO: Random access for Cf servers: The draft still needs to specify a reaction to "overshoot"
	// TODO: Blockwise with separate response or NONs. Not yet mentioned in draft.
	// TODO: Forward cancellation and timeouts of a request to its blocks.

	/*
	 * What if a request contains a Block2 option with size 128 but the response
	 * is only 10 bytes long? A configuration property allow the server between two choices :
	 * <ul>
	 * 	<li>Include block2 option with m flag set to false to indicate that there is no more block to request.</li>
	 * 	<li>Do not include the block2 option at all (allowed by the RFC, it should be up to the client to handle this use case : https://tools.ietf.org/html/rfc7959#section-2.2)</li>
	 * </ul>
	 * <p>
	 * The draft needs to specify whether it is allowed to use separate
	 * responses or NONs. Otherwise, I do not know whether I should allow (or
	 * prevent) the resource to use it. Currently, we do not prevent it but I am
	 * not sure what would happen if a resource used accept() or NONs.
	 * <p>
	 * What is the client supposed to do when it asks the server for block x but
	 * receives a wrong block? The client cannot send a 4.08 (Request Entity
	 * Incomplete). Should it reject it? Currently, we reject it and cancel the
	 * request.
	 * <p>
	 * In a blockwise transfer of a response to a POST request, the draft should
	 * mention whether the client should always include all options in each
	 * request for the next block or not. The response is already produced at
	 * the server, thus, there is no point in receiving them again. The draft
	 * only states that the payload should be empty. Currently we always send
	 * all options in each request (just in case) (except observe which is not
	 * allowed).
	 * <p>
	 * When an observe notification is being sent blockwise, it is not clear
	 * whether we are allowed to include the observe option in each response
	 * block. In the draft, the observe option is left out but it would be
	 * easier for us if we were allowed to include it. The policy which options
	 * should be included in which block is not clear to me anyway. ETag is
	 * always included, observe only in the first block, what about the others?
	 * Currently, I send observe only in the first block so that it exactly
	 * matches the example in the draft.
	 */

	// Minimal block size : 2^4 bytes
	// (see https://tools.ietf.org/html/rfc7959#section-2.2)
	private static final int MINIMAL_BLOCK_SIZE = 16;

	private static final Logger LOGGER = LoggerFactory.getLogger(BlockwiseLayer.class);
	private static final Logger HEALTH_LOGGER = LoggerFactory.getLogger(LOGGER.getName() + ".health");
	private final LeastRecentlyUsedCache<KeyUri, Block1BlockwiseStatus> block1Transfers;
	private final LeastRecentlyUsedCache<KeyUri, Block2BlockwiseStatus> block2Transfers;
	private final AtomicInteger ignoredBlock2 = new AtomicInteger();
	private volatile boolean enableStatus;
	private ScheduledFuture<?> statusLogger;
	private int maxMessageSize;
	private int preferredBlockSize;
	private int preferredBlockSzx;
	private int blockTimeout;
	private int maxResourceBodySize;
	private boolean strictBlock2Option;
	private int healthStatusInterval;
	/* @since 2.4 */
	private boolean enableAutoFailoverOn413;

	/**
	 * Creates a new blockwise layer for a configuration.
	 * <p>
	 * The following configuration properties are used:
	 * <ul>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MAX_MESSAGE_SIZE} -
	 * This value is used as the threshold for determining
	 * whether an inbound or outbound message's body needs to be transferred blockwise.
	 * If not set, a default value of 4096 bytes is used.</li>
	 * 
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#PREFERRED_BLOCK_SIZE} -
	 * This value is used as the value proposed to a peer when doing a transparent blockwise transfer.
	 * The value indicates the number of bytes, not the szx code.
	 * If not set, a default value of 1024 bytes is used.</li>
	 * 
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MAX_RESOURCE_BODY_SIZE} -
	 * This value (in bytes) is used as the upper limit for the size of the buffer used for assembling
	 * blocks of a transparent blockwise transfer. Resource bodies larger than this value can only be
	 * transferred in a manually managed blockwise transfer. Setting this value to 0 disables transparent
	 * blockwise handling altogether, i.e. all messages will simply be forwarded directly up and down to
	 * the next layer.
	 * If not set, a default value of 8192 bytes is used.</li>
	 * 
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#BLOCKWISE_STATUS_LIFETIME} -
	 * The maximum amount of time (in milliseconds) allowed between transfers of individual blocks before
	 * the blockwise transfer state is discarded.
	 * If not set, a default value of 30 seconds is used.</li>
	 * 
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#BLOCKWISE_STRICT_BLOCK2_OPTION} -
	 * This value is used to indicate if the response should always include the Block2 option when client request early blockwise negociation but the response can be sent on one packet.
	 * If not set, the default value is {@link org.eclipse.californium.core.network.config.NetworkConfigDefaults#DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION}</li>
	 * </ul>

	 * @param config The configuration values to use.
	 */
	public BlockwiseLayer(final NetworkConfig config) {

		maxMessageSize = config.getInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, NetworkConfigDefaults.DEFAULT_MAX_MESSAGE_SIZE);
		preferredBlockSize = config.getInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, NetworkConfigDefaults.DEFAULT_PREFERRED_BLOCK_SIZE);
		preferredBlockSzx = BlockOption.size2Szx(preferredBlockSize);
		blockTimeout = config.getInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME,
				NetworkConfigDefaults.DEFAULT_BLOCKWISE_STATUS_LIFETIME);
		maxResourceBodySize = config.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE,
				NetworkConfigDefaults.DEFAULT_MAX_RESOURCE_BODY_SIZE);
		int maxActivePeers = config.getInt(NetworkConfig.Keys.MAX_ACTIVE_PEERS,
				NetworkConfigDefaults.DEFAULT_MAX_ACTIVE_PEERS);
		block1Transfers = new LeastRecentlyUsedCache<>(maxActivePeers, TimeUnit.MILLISECONDS.toSeconds(blockTimeout));
		block1Transfers.setEvictingOnReadAccess(false);
		block2Transfers = new LeastRecentlyUsedCache<>(maxActivePeers, TimeUnit.MILLISECONDS.toSeconds(blockTimeout));
		block2Transfers.setEvictingOnReadAccess(false);
		strictBlock2Option = config.getBoolean(NetworkConfig.Keys.BLOCKWISE_STRICT_BLOCK2_OPTION, NetworkConfigDefaults.DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION);

		healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 60); // seconds

		enableAutoFailoverOn413 = config.getBoolean(NetworkConfig.Keys.BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER,
				NetworkConfigDefaults.DEFAULT_BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER);

		LOGGER.info(
				"BlockwiseLayer uses MAX_MESSAGE_SIZE={}, PREFERRED_BLOCK_SIZE={}, BLOCKWISE_STATUS_LIFETIME={}, MAX_RESOURCE_BODY_SIZE={}, BLOCKWISE_STRICT_BLOCK2_OPTION={}",
				 maxMessageSize, preferredBlockSize, blockTimeout, maxResourceBodySize, strictBlock2Option);
	}

	@Override
	public void start() {
		if (healthStatusInterval > 0 && HEALTH_LOGGER.isDebugEnabled() && statusLogger == null) {
			statusLogger = secondaryExecutor.scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					if (enableStatus) {
						{
							HEALTH_LOGGER.debug("{} block1 transfers", block1Transfers.size());
							Iterator<Block1BlockwiseStatus> iterator = block1Transfers.valuesIterator();
							int max = 5;
							while (iterator.hasNext()) {
								HEALTH_LOGGER.debug("   block1 {}", iterator.next());
								--max;
								if (max == 0) {
									break;
								}
							}
						}
						{
							HEALTH_LOGGER.debug("{} block2 transfers", block2Transfers.size());
							Iterator<Block2BlockwiseStatus> iterator = block2Transfers.valuesIterator();
							int max = 5;
							while (iterator.hasNext()) {
								HEALTH_LOGGER.debug("   block2 {}", iterator.next());
								--max;
								if (max == 0) {
									break;
								}
							}
						}
						HEALTH_LOGGER.debug("{} block2 responses ignored", ignoredBlock2.get());
					}
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
	}

	@Override
	public void destroy() {
		if (statusLogger != null) {
			statusLogger.cancel(false);
			statusLogger = null;
		}
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		Request requestToSend = request;

		if (isTransparentBlockwiseHandlingEnabled() && !request.isMulticast()) {

			BlockOption block2 = request.getOptions().getBlock2();
			if (block2 != null && block2.getNum() > 0) {
				// This is the case if the user has explicitly added a block option
				// for random access.
				// Note: We do not regard it as random access when the block number is 0.
				// This is because the user might just want to do early block
				// size negotiation but actually want to retrieve the whole body by means of
				// a transparent blockwise transfer.
				LOGGER.debug("outbound request contains block2 option, creating random-access blockwise status");
				addRandomAccessBlock2Status(exchange, request);
			} else {
				KeyUri key = getKey(exchange, request);
				Block2BlockwiseStatus status = getBlock2Status(key);
				if (status != null) {
					// Receiving a blockwise response in transparent mode
					// is done by in an "internal request" for the left payload.
					// Therefore the client is not aware of that ongoing request
					// and may send an additional request for the same resource.
					// If that happens, two blockwise request may pend for the 
					// same resource. RFC7959, section 2.4, page 13, 
					// "The Block2 Option provides no way for a single endpoint
					//  to perform multiple concurrently proceeding block-wise
					//  response payload transfer (e.g., GET) operations to the
					//  same resource."
					// So one transfer must be abandoned. This chose the transfer
					// of the notify to be abandoned so that the client receives
					// the requested response but lose the notify. 
					clearBlock2Status(key, status);
					status.completeOldTransfer(null);
				}
				
				if (requiresBlockwise(request)) {
					// This must be a large POST or PUT request
					requestToSend = startBlockwiseUpload(exchange, request, preferredBlockSize);
				}
			}
		}

		exchange.setCurrentRequest(requestToSend);
		lower().sendRequest(exchange, requestToSend);
	}

	private Request startBlockwiseUpload(final Exchange exchange, final Request request, int blocksize) {

		final KeyUri key = getKey(exchange, request);

		synchronized (block1Transfers) {

			Block1BlockwiseStatus status = getBlock1Status(key);
			if (status != null) {
				// there already is a block1 transfer going on to the resource
				// cancel the original request and start over with a new tracker
				status.cancelRequest();
				clearBlock1Status(key, status);
			}
			status = getOutboundBlock1Status(key, exchange, request, blocksize);

			final Request block = status.getNextRequestBlock();
			block.setDestinationContext(request.getDestinationContext());
			Token token = request.getToken();
			if (token != null) {
				block.setToken(token);
			}
			block.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onReadyToSend() {
					// when the request for transferring the first block
					// has been sent out, we copy the token to the
					// original request so that at the end of the
					// blockwise transfer the Matcher can correctly
					// close the overall exchange
					if (request.getToken() == null) {
						request.setToken(block.getToken());
					}
					if (!request.hasMID()) {
						request.setMID(block.getMID());
					}
				}
			});

			addBlock1CleanUpObserver(block, key, status);
			prepareBlock1Cleanup(status, key);
			return block;
		}
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {

		if (isTransparentBlockwiseHandlingEnabled()) {

			BlockOption block2 = request.getOptions().getBlock2();

			if (request.getOptions().hasBlock1()) {

				// This is a large POST or PUT request
				handleInboundBlockwiseUpload(exchange, request);

			} else if (block2 != null && block2.getNum() > 0) {

				KeyUri key = getKey(exchange, request);
				Block2BlockwiseStatus status = getBlock2Status(key);
				if (status == null) {

					LOGGER.debug(
							"peer wants to retrieve individual block2 {} of {}, delivering request to application layer",
							block2, key);
					exchange.setRequest(request);
					upper().receiveRequest(exchange, request);

				} else {
					// The peer wants to retrieve the next block of a blockwise transfer
					handleInboundRequestForNextBlock(exchange, request, key, status);
				}

			} else {

				exchange.setRequest(request);
				upper().receiveRequest(exchange, request);
			}

		} else {

			exchange.setRequest(request);
			upper().receiveRequest(exchange, request);
		}
	}

	private void handleInboundBlockwiseUpload(final Exchange exchange, final Request request) {

		if (requestExceedsMaxBodySize(request)) {
			int maxResourceBodySize = getMaxResourceBodySize(request);
			Response error = Response.createResponse(request, ResponseCode.REQUEST_ENTITY_TOO_LARGE);
			error.setPayload(String.format("body too large, can process %d bytes max", maxResourceBodySize));
			error.getOptions().setSize1(maxResourceBodySize);
			exchange.setCurrentResponse(error);
			lower().sendResponse(exchange, error);

		} else {

			BlockOption block1 = request.getOptions().getBlock1();
			LOGGER.debug("inbound request contains block1 option {}", block1);
			KeyUri key = getKey(exchange, request);
			Block1BlockwiseStatus status = getInboundBlock1Status(key, exchange, request);

			if (block1.getNum() == 0 && status.getCurrentNum() > 0) {
				status = resetInboundBlock1Status(key, exchange, request);
			}

			if (block1.getNum() != status.getCurrentNum()) {
				// ERROR, wrong number, Incomplete
				LOGGER.warn(
						"peer sent wrong block, expected no. {} but got {}. Responding with 4.08 (Request Entity Incomplete)",
						status.getCurrentNum(), block1.getNum());

				sendBlock1ErrorResponse(key, status, exchange, request, ResponseCode.REQUEST_ENTITY_INCOMPLETE,
						"wrong block number");

			} else if (!status.hasContentFormat(request.getOptions().getContentFormat())) {

				sendBlock1ErrorResponse(key, status, exchange, request, ResponseCode.REQUEST_ENTITY_INCOMPLETE,
						"unexpected Content-Format");

			} else if (!status.addBlock(request.getPayload())) {

				sendBlock1ErrorResponse(key, status, exchange, request, ResponseCode.REQUEST_ENTITY_TOO_LARGE,
						"body exceeded expected size " + status.getBufferSize());

			} else {

				status.setCurrentNum(status.getCurrentNum() + 1);
				if ( block1.isM() ) {

					// do not assemble and deliver the request yet

					LOGGER.debug("acknowledging incoming block1 [num={}], expecting more blocks to come", block1.getNum());

					Response piggybacked = Response.createResponse(request, ResponseCode.CONTINUE);
					piggybacked.getOptions().setBlock1(block1.getSzx(), true, block1.getNum());

					exchange.setCurrentResponse(piggybacked);
					lower().sendResponse(exchange, piggybacked);

				} else {

					LOGGER.debug("peer has sent last block1 [num={}], delivering request to application layer", block1.getNum());

					// Remember block to acknowledge. TODO: We might make this a boolean flag in status.
					exchange.setBlock1ToAck(block1); 

					// Assemble and deliver
					Request assembled = new Request(request.getCode());
					status.assembleReceivedMessage(assembled);

					// make sure we deliver the request using the MID and token of the latest request
					// so that the response created by the application layer can reply to his 
					// token and MID
					assembled.setMID(request.getMID());
					assembled.setToken(request.getToken());
					// copy scheme
					assembled.setScheme(request.getScheme());
					
					// make sure peer's early negotiation of block2 size gets included
					assembled.getOptions().setBlock2(request.getOptions().getBlock2());

					clearBlock1Status(key, status);

					exchange.setRequest(assembled);
					upper().receiveRequest(exchange, assembled);
				}
			}
		}
	}

	private void sendBlock1ErrorResponse(KeyUri key, Block1BlockwiseStatus status, Exchange exchange, Request request,
			ResponseCode errorCode, String message) {

		BlockOption block1 = request.getOptions().getBlock1();
		Response error = Response.createResponse(request, errorCode);
		error.getOptions().setBlock1(block1.getSzx(), block1.isM(), block1.getNum());
		error.setPayload(message);
		clearBlock1Status(key, status);
		exchange.setCurrentResponse(error);
		lower().sendResponse(exchange, error);
	}

	private void handleInboundRequestForNextBlock(final Exchange exchange, final Request request,
			final KeyUri key, final Block2BlockwiseStatus status) {

		Response block;
		boolean complete;
		synchronized (status) {

			BlockOption block2 = request.getOptions().getBlock2();
			block = status.getNextResponseBlock(block2);
			complete = status.isComplete();
			if (!complete) {
				prepareBlock2Cleanup(status, key);
				LOGGER.debug("peer has requested intermediary block of blockwise transfer: {}", status);
			}
		}

		if (complete) {
			// clean up blockwise status
			LOGGER.debug("peer has requested last block of blockwise transfer: {}", status);
			clearBlock2Status(key, status);
		}

		exchange.setCurrentResponse(block);
		lower().sendResponse(exchange, block);
	}

	/**
	 * Invoked when a response is sent to a peer.
	 * <p>
	 * This method initiates a blockwise transfer if the response's payload
	 * exceeds {@code MAX_MESSAGE_SIZE}.
	 * 
	 * @param exchange The exchange the response is part of.
	 * @param response The response to send to the peer.
	 */
	@Override
	public void sendResponse(final Exchange exchange, final Response response) {

		Response responseToSend = response;

		if (isTransparentBlockwiseHandlingEnabled()) {

			BlockOption requestBlock2 = exchange.getRequest().getOptions().getBlock2();
			BlockOption responseBlock2 = response.getOptions().getBlock2();

			if (requestBlock2 != null && requestBlock2.getNum() > 0) {

				// peer has issued a random block access request

				if (responseBlock2 != null) {

					// the resource implementation supports blockwise retrieval (indicated by the
					// presence of the block2 option in the response)

					if (requestBlock2.getNum() != responseBlock2.getNum()) {
						LOGGER.warn(
								"resource [{}] implementation error, peer requested block {} but resource returned block {}",
								exchange.getRequest().getURI(), requestBlock2.getNum(), responseBlock2.getNum());
						responseToSend = Response.createResponse(exchange.getRequest(), ResponseCode.INTERNAL_SERVER_ERROR);
						responseToSend.setType(response.getType());
						responseToSend.setMID(response.getMID());
						responseToSend.addMessageObservers(response.getMessageObservers());
					}

				} else if (response.hasBlock(requestBlock2)) {

					// the resource implementation does not support blockwise retrieval
					// but instead has responded with the full response body
					// crop the response down to the requested block
					Block2BlockwiseStatus.crop(responseToSend, requestBlock2);

				} else {

					// peer has requested a non existing block
					responseToSend = Response.createResponse(exchange.getRequest(), ResponseCode.BAD_OPTION);
					responseToSend.setType(response.getType());
					responseToSend.setMID(response.getMID());
					responseToSend.getOptions().setBlock2(requestBlock2);
					responseToSend.addMessageObservers(response.getMessageObservers());
				}

			} else if (requiresBlockwise(exchange, response, requestBlock2)) {

				// the client either has not included a block2 option at all or has
				// included a block2 option with num = 0 (early negotiation of block size)

				KeyUri key = getKey(exchange, response);
				// We can not handle several block2 transfer for the same client/resource.
				// So we clean previous transfer (priority to the new one)
				Block2BlockwiseStatus status = resetOutboundBlock2Status(key, exchange, response);
				BlockOption block2 = requestBlock2 != null ? requestBlock2
						: new BlockOption(preferredBlockSzx, false, 0);
				responseToSend = status.getNextResponseBlock(block2);
			}

			BlockOption block1 = exchange.getBlock1ToAck();
			if (block1 != null) {
				exchange.setBlock1ToAck(null);
				responseToSend.getOptions().setBlock1(block1);
			}
		}

		exchange.setCurrentResponse(responseToSend);
		lower().sendResponse(exchange, responseToSend);
	}

	/**
	 * Invoked when a response has been received from a peer.
	 * <p>
	 * Checks whether the response
	 * <ul>
	 * <li>contains a block of an already ongoing blockwise transfer or
	 * contains the first block of a large body and requires the start of a
	 * blockwise transfer to retrieve the remaining blocks of the body or</li>
	 * <li>acknowledges a block sent to the peer as part of a block1 transfer
	 * and either sends the next block or handles a potential error situation.</li>
	 * </ul>
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 */
	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {

		if (isTransparentBlockwiseHandlingEnabled() && !exchange.getRequest().isMulticast()) {
			if (response.isError()) {
				// handle blockwise specific error codes
				switch(response.getCode()) {
				case REQUEST_ENTITY_INCOMPLETE: // 4.08
					// we seem to have uploaded blocks not in expected order
				case REQUEST_ENTITY_TOO_LARGE: // 4.13
					if (handleEntityTooLarge(exchange, response)) {
						return;
					}

					// server is not able to process the payload we included
					KeyUri key = getKey(exchange, exchange.getCurrentRequest());
					Block1BlockwiseStatus status = getBlock1Status(key);
					if (status != null) {
						clearBlock1Status(key, status);
					}
				default:
				}

				// check, if response is for original request
				if (exchange.getRequest() != exchange.getCurrentRequest()) {
					// prepare the response as response to the original request
					Response resp = new Response(response.getCode());
					// adjust the token using the original request
					resp.setToken(exchange.getRequest().getToken());
					if (exchange.getRequest().getType() == Type.CON) {
						resp.setType(Type.ACK);
						// adjust MID also
						resp.setMID(exchange.getRequest().getMID());
					} else {
						resp.setType(Type.NON);
					}
					resp.setSourceContext(response.getSourceContext());
					resp.setPayload(response.getPayload());
					resp.setOptions(response.getOptions());
					resp.setRTT(exchange.calculateRTT());
					exchange.setResponse(resp);
					upper().receiveResponse(exchange, resp);
				} else {
					upper().receiveResponse(exchange, response);
				}
				return;
			}

			if (response.getMaxResourceBodySize() == 0) {
				response.setMaxResourceBodySize(exchange.getRequest().getMaxResourceBodySize());
			}
			KeyUri key = getKey(exchange, response);
			Block2BlockwiseStatus status = getBlock2Status(key);
			if (discardBlock2(key, status, exchange, response)) {
				return;
			}

			if (!response.hasBlockOption()) {

				// This is a normal response, no special treatment necessary
				exchange.setResponse(response);
				upper().receiveResponse(exchange, response);

			} else {

				if (response.getOptions().hasBlock1()) {
					handleBlock1Response(exchange, response);
				}

				if (response.getOptions().hasBlock2()) {
					handleBlock2Response(exchange, response);
				}
			}

		} else {
			exchange.setResponse(response);
			upper().receiveResponse(exchange, response);
		}
	}

	/**
	 * Handle 4.13 Entity Too Large error.
	 * 
	 * @param exchange current exchange
	 * @param response the Entity Too Larger response.
	 * @return {@code true} if the response is handled by auto failover
	 */
	private boolean handleEntityTooLarge(Exchange exchange, Response response) {
		if (enableAutoFailoverOn413) {
			if (response.getOptions().hasBlock1()) {

				BlockOption block1 = response.getOptions().getBlock1();
				final KeyUri key = getKey(exchange, exchange.getRequest());

				Block1BlockwiseStatus status;
				Request blockRequest = null;
				synchronized (block1Transfers) {
					status = getBlock1Status(key);
					if (status == null) {
						// We sent a request without using block1 and
						// server give us hint it want it with block1
						Request request = exchange.getRequest();
						if (!exchange.getRequest().isCanceled() && block1.getNum() == 0
								&& block1.getSize() < request.getPayloadSize()) {
							// Start block1 transfer
							blockRequest = startBlockwiseUpload(exchange, request,
									Math.min(block1.getSize(), preferredBlockSize));
						}
					}
				}
				if (status == null) {
					if (blockRequest != null) {
						exchange.setCurrentRequest(blockRequest);
						lower().sendRequest(exchange, blockRequest);
						return true;
					}
				} else if (!status.hasMatchingToken(response)) {
					// a concurrent block1 transfer has been started in
					// the meantime which has "overwritten" the status
					// object with the new (concurrent) request to we simply
					// discard the response
					LOGGER.debug("discarding obsolete block1 response: {}", response);
					return true;
				} else if (exchange.getRequest().isCanceled()) {
					clearBlock1Status(key, status);
					return true;
				} else {
					// we handle only Entity Too Large
					// at begin of the transfer and
					// if blocksize requested is smaller
					if (status.getCurrentNum() == 0 && block1.getSize() < status.getCurrentSize()) {
						// re-send first block with smaller size
						sendBlock(exchange, response, key, status, 0, block1.getSzx());
						return true;
					}
				}
			} else if (!exchange.getRequest().isCanceled()) {
				Request requestToSend = null;
				synchronized (block1Transfers) {
					if (getBlock1Status(getKey(exchange, exchange.getRequest())) == null) {
						// We sent a request without using block1 and
						// server give us hint it want it with block1
						Request request = exchange.getRequest();
						// Try to guess the a block size to use
						Integer maxSize = null;
						if (response.getOptions().hasSize1() && response.getOptions().getSize1() >= MINIMAL_BLOCK_SIZE
								&& response.getOptions().getSize1() < request.getPayloadSize()) {
							maxSize = response.getOptions().getSize1();
						} else if (request.getPayloadSize() > MINIMAL_BLOCK_SIZE) {
							maxSize = request.getPayloadSize() - 1;
						}

						// Start blockwise if we guess a correct size
						if (maxSize != null) {
							int blocksize = Integer.highestOneBit(maxSize);
							 requestToSend = startBlockwiseUpload(exchange, request,
									Math.min(blocksize, preferredBlockSize));
						}
					}
				}
				if (requestToSend != null) {
					exchange.setCurrentRequest(requestToSend);
					lower().sendRequest(exchange, requestToSend);
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Checks if a response acknowledges a block sent in a POST/PUT request and
	 * sends the next block if applicable.
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 */
	private void handleBlock1Response(final Exchange exchange, final Response response) {

		BlockOption block1 = response.getOptions().getBlock1();
		LOGGER.debug("received response acknowledging block1 {}", block1);

		// Block1 transfer has been originally created for an outbound request
		final KeyUri key = getKey(exchange, exchange.getRequest());

		Block1BlockwiseStatus status = getBlock1Status(key);

		if (status == null) {

			// request has not been sent blockwise
			LOGGER.debug("discarding unexpected block1 response: {}", response);

		} else if (!status.hasMatchingToken(response)) {

			// a concurrent block1 transfer has been started in the meantime
			// which has "overwritten" the status object with the new (concurrent) request
			// so we simply discard the response
			LOGGER.debug("discarding obsolete block1 response: {}", response);

		} else if (exchange.getRequest().isCanceled()) {

			clearBlock1Status(key, status);

		} else if (!status.isComplete()) {

			// this means that our last request's M-bit was set

			if (block1.isM()) {
				if (response.getCode() == ResponseCode.CONTINUE) {
					// server wants us to send the remaining blocks before returning
					// its response
					sendNextBlock(exchange, response, key, status);
				} else {
					// the server has responded in a way that is not compliant with RFC 7959
					clearBlock1Status(key, status);
					exchange.getRequest().setRejected(true);
				}

			} else {
				// this means that the response already contains the server's final
				// response to the request. However, the server is still expecting us
				// to continue to send the remaining blocks as specified in
				// https://tools.ietf.org/html/rfc7959#section-2.3

				// the current implementation does not allow us to forward the response
				// to the application layer, though, because it would "complete"
				// the exchange and thus remove the blockwise status necessary
				// to keep track of this POST/PUT request
				// we therefore go on sending all pending blocks and then return the
				// response received for the last block
				sendNextBlock(exchange, response, key, status);
			}

		} else {

			// all blocks of block1 transfer have been sent
			clearBlock1Status(key, status);

			if (response.getOptions().hasBlock2()) {
				LOGGER.debug("Block1 followed by Block2 transfer");
			} else {
				// All request blocks have been acknowledged and we have received a
				// response that does not need blockwise transfer. Thus, deliver it.
				exchange.setResponse(response);
				upper().receiveResponse(exchange, response);
			}
		}
	}

	private void sendNextBlock(final Exchange exchange, final Response response, final KeyUri key,
			final Block1BlockwiseStatus status) {

		BlockOption block1 = response.getOptions().getBlock1();
		int currentSize = status.getCurrentSize();
		// adjust block size to peer's preference
		int newSize, newSzx;
		if (block1.getSize() < currentSize) {
			newSize = block1.getSize();
			newSzx = block1.getSzx();
		} else {
			newSize = currentSize;
			newSzx = status.getCurrentSzx();
		}
		int nextNum = (status.getCurrentNum() + 1) * status.getCurrentSize() / newSize;
		sendBlock(exchange, response, key, status, nextNum, newSzx);
	}

	private void sendBlock(final Exchange exchange, final Response response, final KeyUri key,
			final Block1BlockwiseStatus status, int num, int szx) {
		Request nextBlock = null;
		LOGGER.trace("sending Block1 num={}", num);
		try {
			if (status.isComplete()) {
				LOGGER.debug("stopped block1 transfer, droping request.");
			} else {
				nextBlock = status.getNextRequestBlock(num, szx);
				// we use the same token to ease traceability
				nextBlock.setToken(response.getToken());
				nextBlock.setDestinationContext(status.getFollowUpEndpointContext(response.getSourceContext()));
				addBlock1CleanUpObserver(nextBlock, key, status);

				LOGGER.debug("sending (next) Block1 [num={}]: {}", num, nextBlock);
				exchange.setCurrentRequest(nextBlock);
				prepareBlock1Cleanup(status, key);
				lower().sendRequest(exchange, nextBlock);
			}
		} catch (RuntimeException ex) {
			LOGGER.warn("cannot process next block request, aborting request!", ex);
			if (nextBlock != null) {
				nextBlock.setSendError(ex);
			} else {
				exchange.getRequest().setSendError(ex);
			}
		}
	}

	/**
	 * Check, if response is to be discarded caused by the block2 status. Clears
	 * also the block status for new block transfers
	 * 
	 * @param key uri key for blocktransfer
	 * @param status status of blocktransfer
	 * @param exchange exchange of blocktransfer
	 * @param response current response
	 * @return {@code true}, if reponse is to be ignored, {@code false},
	 *         otherwise
	 */
	private boolean discardBlock2(KeyUri key, Block2BlockwiseStatus status, Exchange exchange, Response response) {
		BlockOption block = response.getOptions().getBlock2();
		if (status != null) {
			// ongoing blockwise transfer
			boolean starting = (block == null) || (block.getNum() == 0);
			if (starting) {
				if (status.isNew(response)) {
					LOGGER.debug("discarding outdated block2 transfer {}, current is [{}]", status.getObserve(),
							response);
					clearBlock2Status(key, status);
					status.completeOldTransfer(exchange);
				} else {
					LOGGER.debug("discarding old block2 transfer [{}], received during ongoing block2 transfer {}",
							response, status.getObserve());
					status.completeNewTranfer(exchange);
					return true;
				}
			} else if (!status.matchTransfer(exchange)) {
				LOGGER.debug("discarding outdate block2 response [{}, {}] received during ongoing block2 transfer {}",
						exchange.getNotificationNumber(), response, status.getObserve());
				status.completeNewTranfer(exchange);
				return true;
			}
		} else if (block != null && block.getNum() != 0) {
			LOGGER.debug("discarding stale block2 response [{}, {}] received without ongoing block2 transfer for {}",
					exchange.getNotificationNumber(), response, key);
			exchange.setComplete();
			return true;
		}

		return false;
	}

	/**
	 * Checks if a response contains a single block of a large payload only and
	 * retrieves the remaining blocks if applicable.
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 */
	private void handleBlock2Response(final Exchange exchange, final Response response) {

		BlockOption block2 = response.getOptions().getBlock2();
		KeyUri key = getKey(exchange, response);

		if (exchange.getRequest().isCanceled()) {

			// We have received a block of the resource body in response to a request that
			// has been canceled by the application layer. There is no need to retrieve the
			// remaining blocks.
			Block2BlockwiseStatus status = getBlock2Status(key);
			if (status != null) {
				clearBlock2Status(key, status);
			}

			if (response.isNotification()) {
				// We have received a notification for an observed resource that the
				// application layer is no longer interested in.
				// Let upper layers decide what to do with the notification.
				upper().receiveResponse(exchange, response);
			}

		} else if (responseExceedsMaxBodySize(response)) {

			String msg = String.format(
					"requested resource body [%d bytes] exceeds max buffer size [%d bytes], aborting request",
					response.getOptions().getSize2(), getMaxResourceBodySize(response));
			LOGGER.debug(msg);
			exchange.getRequest().setOnResponseError(new IllegalStateException(msg));
			// TODO we keep the cancel event for backward compatibility but this
			// should be removed in 3.x
			exchange.getRequest().cancel();

		} else {
			Block2BlockwiseStatus status;
			synchronized (block2Transfers) {
				status = getBlock2Status(key);
				if (discardBlock2(key, status, exchange, response)) {
					return;
				}
				status = getInboundBlock2Status(key, exchange, response);
			}
			if (block2.getNum() == status.getCurrentNum()) {

				// We got the block we expected :-)
				LOGGER.debug("processing incoming block2 response [num={}]: {}", block2.getNum(), response);

				if (status.isRandomAccess()) {

					// The client has requested this specific block and we deliver it
					exchange.setResponse(response);
					clearBlock2Status(key, status);
					upper().receiveResponse(exchange, response);

				} else if (!status.addBlock(response)) {

					String msg = "cannot process payload of block2 response, aborting request";
					LOGGER.debug(msg);
					exchange.getRequest().setOnResponseError(new IllegalStateException(msg));
					// TODO we keep the cancel event for backward compatibility
					// but this should be removed in 3.x
					exchange.getRequest().cancel();
					return;

				} else if (block2.isM()) {
					// request next block
					requestNextBlock(exchange, response, key, status);

				} else {

					// we have received the last block of the block2 transfer

					LOGGER.debug(
							"all {} blocks have been retrieved, assembling response and delivering to application layer",
							status.getBlockCount());
					Response assembled = new Response(response.getCode());
					status.assembleReceivedMessage(assembled);

					// set overall transfer RTT
					assembled.setRTT(exchange.calculateRTT());

					clearBlock2Status(key, status);
					LOGGER.debug("assembled response: {}", assembled);
					// Set the original request as current request so that
					// the Matcher can clean up its state based on the latest
					// ("current") request's MID and token
					exchange.setCurrentRequest(exchange.getRequest());
					// Set the assembled response as current response
					exchange.setResponse(assembled);
					upper().receiveResponse(exchange, assembled);
				}

			} else {
				// ERROR, wrong block number (server error)
				// Canceling the request would interfere with Observe,
				// so just ignore it
				ignoredBlock2.incrementAndGet();
				LOGGER.warn("ignoring block2 response with wrong block number {} (expected {}) - {}: {}",
						block2.getNum(), status.getCurrentNum(), exchange.getCurrentRequest().getToken(), response);
			}
		}
	}

	/**
	 * Sends request for the next response block.
	 */
	private void requestNextBlock(final Exchange exchange, final Response response, final KeyUri key, final Block2BlockwiseStatus status) {
		int currentSize = status.getCurrentSize();
		// do late block size negotiation
		int newSize, newSzx;
		BlockOption block2 = response.getOptions().getBlock2();
		if (block2.getSzx() > preferredBlockSzx) {
			newSize = preferredBlockSize;
			newSzx = preferredBlockSzx;
		} else {
			newSize = currentSize;
			newSzx = status.getCurrentSzx();
		}
		int nextNum = status.getCurrentNum() + currentSize / newSize;

		Request request = exchange.getRequest();

		Request block = new Request(request.getCode());
		try {
			// do not enforce CON, since NON could make sense over SMS or similar transports
			block.setType(request.getType());
			block.setDestinationContext(status.getFollowUpEndpointContext(response.getSourceContext()));

			/*
			 * WARNING:
			 * 
			 * For Observe, the Matcher then will store the same
			 * exchange under a different KeyToken in exchangesByToken,
			 * which is cleaned up in the else case below.
			 */
			if (!response.isNotification()) {
				block.setToken(response.getToken());
			} else if (exchange.isNotification()) {
				// Recreate cleanup message observer 
				request.addMessageObserver(new CleanupMessageObserver(exchange));
			}

			// copy options
			block.setOptions(new OptionSet(request.getOptions()));
			block.getOptions().setBlock2(newSzx, false, nextNum);

			// make sure NOT to use Observe for block retrieval
			block.getOptions().removeObserve();

			// copy message observers from original request so that they will be notified
			// if something goes wrong with this blockwise request, e.g. if it times out
			block.addMessageObservers(request.getMessageObservers());
			// add an observer that cleans up the block2 transfer tracker if the
			// block request fails
			addBlock2CleanUpObserver(block, key, status);

			status.setCurrentNum(nextNum);

			if (status.isComplete()) {
				LOGGER.debug("stopped block2 transfer, droping response.");
			} else {
				LOGGER.debug("requesting next Block2 [num={}]: {}", nextNum, block);
				exchange.setCurrentRequest(block);
				prepareBlock2Cleanup(status, key);
				lower().sendRequest(exchange, block);
			}
		} catch (RuntimeException ex) {
			LOGGER.warn("cannot process next block request, aborting request!", ex);
			block.setSendError(ex);
		}
	}

	/////////// HELPER METHODS //////////

	private static KeyUri getKey(final Exchange exchange, final Request request) {

		if (exchange.isOfLocalOrigin()) {
			return KeyUri.fromOutboundRequest(request);
		} else {
			return KeyUri.fromInboundRequest(request);
		}
	}

	private static KeyUri getKey(final Exchange exchange, final Response response) {

		if (exchange.isOfLocalOrigin()) {
			return KeyUri.fromInboundResponse(exchange.getRequest(), response);
		} else {
			return KeyUri.fromOutboundResponse(exchange.getRequest(), response);
		}
	}

	private Block1BlockwiseStatus getOutboundBlock1Status(final KeyUri key, final Exchange exchange, final Request request, int blocksize) {

		synchronized (block1Transfers) {
			Block1BlockwiseStatus status = block1Transfers.get(key);
			if (status == null) {
				status = Block1BlockwiseStatus.forOutboundRequest(exchange, request, blocksize);
				block1Transfers.put(key, status);
				enableStatus = true;
				LOGGER.debug("created tracker for outbound block1 transfer {}, transfers in progress: {}", status,
						block1Transfers.size());
			}
			return status;
		}
	}

	private Block1BlockwiseStatus getInboundBlock1Status(final KeyUri key, final Exchange exchange, final Request request) {
		Block1BlockwiseStatus status;
		int maxPayloadSize = getMaxResourceBodySize(request);
		synchronized (block1Transfers) {
			status = block1Transfers.get(key);
			if (status == null) {
				status = Block1BlockwiseStatus.forInboundRequest(exchange, request, maxPayloadSize);
				block1Transfers.put(key, status);
				enableStatus = true;
				LOGGER.debug("created tracker for inbound block1 transfer {}, transfers in progress: {}", status,
						block1Transfers.size());
			}
		}
		// register a task for cleaning up if the peer does not send all blocks
		prepareBlock1Cleanup(status, key);
		return status;
	}

	private Block1BlockwiseStatus resetInboundBlock1Status(final KeyUri key, final Exchange exchange, final Request request) {
		Block1BlockwiseStatus removedStatus;
		Block1BlockwiseStatus newStatus;
		synchronized (block1Transfers) {
			removedStatus = block1Transfers.remove(key);
			LOGGER.debug("inbound block1 transfer reset at {} by peer: {}", removedStatus, request);
			// remove old status ensures, that getInboundBlock1Status could be
			// called in synchronized (block1Transfers)
			newStatus = getInboundBlock1Status(key, exchange, request);
		}
		if (removedStatus != null) {
			removedStatus.setComplete(true);
		}
		return newStatus;
	}

	private Block2BlockwiseStatus getOutboundBlock2Status(final KeyUri key, final Exchange exchange, final Response response) {

		Block2BlockwiseStatus status;
		synchronized (block2Transfers) {
			status = block2Transfers.get(key);
			if (status == null) {
				status = Block2BlockwiseStatus.forOutboundResponse(exchange, response, preferredBlockSize);
				block2Transfers.put(key, status);
				enableStatus = true;
				LOGGER.debug("created tracker for outbound block2 transfer {}, transfers in progress: {}", status,
						block2Transfers.size());
			}
		}
		// we register a clean up task in case the peer does not retrieve all blocks
		prepareBlock2Cleanup(status, key);
		return status;
	}

	private Block2BlockwiseStatus getInboundBlock2Status(final KeyUri key, final Exchange exchange, final Response response) {
		int maxPayloadSize = getMaxResourceBodySize(response);
		synchronized (block2Transfers) {
			Block2BlockwiseStatus status = block2Transfers.get(key);
			if (status == null) {
				status = Block2BlockwiseStatus.forInboundResponse(exchange, response, maxPayloadSize);
				block2Transfers.put(key, status);
				enableStatus = true;
				LOGGER.debug("created tracker for {} inbound block2 transfer {}, transfers in progress: {}, {}", key,
						status, block2Transfers.size(), response);
			}
			return status;
		}
	}

	private KeyUri addRandomAccessBlock2Status(final Exchange exchange, final Request request) {

		KeyUri key = getKey(exchange, request);
		int size;
		Block2BlockwiseStatus status = Block2BlockwiseStatus.forRandomAccessRequest(exchange, request);
		synchronized (block2Transfers) {
			block2Transfers.put(key, status);
			size = block1Transfers.size();
		}
		enableStatus = true;
		addBlock2CleanUpObserver(request, key, status);
		LOGGER.debug("created tracker for random access block2 retrieval {}, transfers in progress: {}", status, size);
		return key;
	}

	private Block2BlockwiseStatus resetOutboundBlock2Status(KeyUri key, Exchange exchange, Response response) {
		Block2BlockwiseStatus previousStatus;
		Block2BlockwiseStatus newStatus;
		synchronized (block2Transfers) {
			previousStatus = block2Transfers.remove(key);
			newStatus = getOutboundBlock2Status(key, exchange, response);
		}
		if (previousStatus != null && !previousStatus.isComplete()) {
			LOGGER.debug("stop previous block transfer {} {} for new {}", key, previousStatus, response);
			previousStatus.completeResponse();
		} else {
			LOGGER.debug("block transfer {} for {}", key, response);
		}
		return newStatus;
	}

	private Block1BlockwiseStatus getBlock1Status(final KeyUri key) {

		synchronized (block1Transfers) {
			return block1Transfers.get(key);
		}
	}

	private Block2BlockwiseStatus getBlock2Status(final KeyUri key) {

		synchronized (block2Transfers) {
			return block2Transfers.get(key);
		}
	}

	private Block1BlockwiseStatus clearBlock1Status(KeyUri key, Block1BlockwiseStatus status) {
		int size;
		Block1BlockwiseStatus removedTracker;
		synchronized (block1Transfers) {
			removedTracker = block1Transfers.remove(key, status);
			size = block1Transfers.size();
		}
		if (removedTracker != null) {
			LOGGER.debug("removing block1 tracker [{}], block1 transfers still in progress: {}", key, size);
			removedTracker.setComplete(true);
		}
		return removedTracker;
	}

	private Block2BlockwiseStatus clearBlock2Status(KeyUri key, Block2BlockwiseStatus status) {
		int size;
		Block2BlockwiseStatus removedTracker;
		synchronized (block2Transfers) {
			removedTracker = block2Transfers.remove(key, status);
			size = block2Transfers.size();
		}
		if (removedTracker != null) {
			LOGGER.debug("removing block2 tracker [{}], block2 transfers still in progress: {}", key, size);
			removedTracker.setComplete(true);
		}
		return removedTracker;
	}

	private boolean requiresBlockwise(final Request request) {
		boolean blockwiseRequired = request.getPayloadSize() > maxMessageSize;
		if (blockwiseRequired) {
			LOGGER.debug("request body [{}/{}] requires blockwise transfer", request.getPayloadSize(), maxMessageSize);
		}
		return blockwiseRequired;
	}

	private boolean requiresBlockwise(final Exchange exchange, final Response response, final BlockOption requestBlock2) {

		boolean blockwiseRequired = response.getPayloadSize() > maxMessageSize;
		if (requestBlock2 != null) {
			// client might have included early negotiation block2 option
			// If the block2 strict mode has been enabled we must respond with a block2 option even if the payload fits in one block
			blockwiseRequired = blockwiseRequired || strictBlock2Option || response.getPayloadSize() > requestBlock2.getSize();
		}
		if (blockwiseRequired) {
			LOGGER.debug("response body [{}/{}] requires blockwise transfer", response.getPayloadSize(),
					maxMessageSize);
		}
		return blockwiseRequired;
	}

	private boolean isTransparentBlockwiseHandlingEnabled() {
		return maxResourceBodySize > 0;
	}

	private boolean responseExceedsMaxBodySize(final Response response) {
		return response.getOptions().hasSize2() && response.getOptions().getSize2() > getMaxResourceBodySize(response);
	}

	private boolean requestExceedsMaxBodySize(final Request request) {
		return request.getOptions().hasSize1() && request.getOptions().getSize1() > getMaxResourceBodySize(request);
	}

	private int getMaxResourceBodySize(final Message message) {
		int maxPayloadSize = message.getMaxResourceBodySize();
		if (maxPayloadSize == 0) {
			maxPayloadSize = maxResourceBodySize; 
		}
		return maxPayloadSize;
	}

	/**
	 * Schedules a task for cleaning up state when a block1 transfer times out.
	 * 
	 * @param status The tracker for the block1 transfer to clean up for.
	 * @param key The key of the tracker.
	 */
	protected void prepareBlock1Cleanup(final Block1BlockwiseStatus status, final KeyUri key) {

		LOGGER.debug("scheduling clean up task for block1 transfer {}", key);
		ScheduledFuture<?> taskHandle = scheduleBlockCleanupTask(new Runnable() {

			@Override
			public void run() {
				try {
					if (!status.isComplete()) {
						LOGGER.debug("block1 transfer timed out: {}", key);
						status.timeoutCurrentTranfer();
					}
					clearBlock1Status(key, status);
				} catch (Exception e) {
					LOGGER.debug("Unexcepted error while block1 cleaning", e);
				}
			}
		});
		status.setBlockCleanupHandle(taskHandle);
	}

	private MessageObserver addBlock1CleanUpObserver(final Request message, final KeyUri key,
			final Block1BlockwiseStatus status) {

		MessageObserver observer = new MessageObserverAdapter() {

			@Override
			public void onCancel() {
				clearBlock1Status(key, status);
			}

			@Override
			protected void failed() {
				clearBlock1Status(key, status);
			}
		};
		message.addMessageObserver(observer);
		return observer;
	}

	private MessageObserver addBlock2CleanUpObserver(final Request message, final KeyUri key,
			final Block2BlockwiseStatus status) {

		MessageObserver observer = new MessageObserverAdapter() {

			@Override
			public void onCancel() {
				clearBlock2Status(key, status);
			}

			@Override
			protected void failed() {
				clearBlock2Status(key, status);
			}
		};
		message.addMessageObserver(observer);
		return observer;
	}

	/**
	 * Schedules a task for cleaning up state when a block2 transfer times out.
	 * 
	 * @param status The tracker for the block2 transfer to clean up for.
	 * @param key The key of the tracker.
	 */
	protected void prepareBlock2Cleanup(final Block2BlockwiseStatus status, final KeyUri key) {

		LOGGER.debug("scheduling clean up task for block2 transfer {}", key);
		ScheduledFuture<?> taskHandle = scheduleBlockCleanupTask(new Runnable() {

			@Override
			public void run() {
				try {
					if (!status.isComplete()) {
						LOGGER.debug("block2 transfer timed out: {}", key);
						status.timeoutCurrentTranfer();
					}
					clearBlock2Status(key, status);
				} catch (Exception e) {
					LOGGER.debug("Unexcepted error while block2 cleaning", e);
				}
			}
		});
		status.setBlockCleanupHandle(taskHandle);
	}

	private ScheduledFuture<?> scheduleBlockCleanupTask(final Runnable task) {

		// prevent RejectedExecutionException
		if (executor.isShutdown()) {
			LOGGER.info("Endpoint is being destroyed: skipping block clean-up");
			return null;

		} else {
			return executor.schedule(task , blockTimeout, TimeUnit.MILLISECONDS);
		}
	}

	public boolean isEmpty() {
		return block1Transfers.size() == 0 && block2Transfers.size() == 0;
	}
}
