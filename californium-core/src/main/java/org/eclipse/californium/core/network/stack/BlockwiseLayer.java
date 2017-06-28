/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Pratheek Rai - changes for BERT 
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Arrays;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;

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
 */
public class BlockwiseLayer extends AbstractLayer {

	// TODO: Random access for Cf servers: The draft still needs to specify a reaction to "overshoot"
	// TODO: Blockwise with separate response or NONs. Not yet mentioned in draft.
	// TODO: Forward cancellation and timeouts of a request to its blocks.

	/*
	 * What if a request contains a Block2 option with size 128 but the response
	 * is only 10 bytes long? Should we still add the block2 option to the
	 * response? Currently, we do.
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

	private static final Logger LOGGER = Logger.getLogger(BlockwiseLayer.class.getName());
	private final LeastRecentlyUsedCache<KeyUri, Block1BlockwiseStatus> block1Transfers;
	private final LeastRecentlyUsedCache<KeyUri, Block2BlockwiseStatus> block2Transfers;
	private int maxMessageSize;
	private int preferredBlockSize;
	private int preferredBlockSzx;
	private int blockTimeout;
	private int maxResourceBodySize;

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
	 * </ul>

	 * @param config The configuration values to use.
	 */
	public BlockwiseLayer(final NetworkConfig config) {

		maxMessageSize = config.getInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 4096);
		preferredBlockSize = config.getInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 1024);
		preferredBlockSzx = BlockOption.size2Szx(preferredBlockSize);
		blockTimeout = config.getInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME, 30 * 1000); // 30 secs
		maxResourceBodySize = config.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, 8192);
		int maxActivePeers = config.getInt(NetworkConfig.Keys.MAX_ACTIVE_PEERS);
		block1Transfers = new LeastRecentlyUsedCache<>(maxActivePeers, blockTimeout / 1000);
		block2Transfers = new LeastRecentlyUsedCache<>(maxActivePeers, blockTimeout / 1000);

		LOGGER.log(Level.CONFIG,
			"BlockwiseLayer uses MAX_MESSAGE_SIZE={0}, PREFERRED_BLOCK_SIZE={1}, BLOCKWISE_STATUS_LIFETIME={2} and MAX_RESOURCE_BODY_SIZE={3}",
			new Object[]{maxMessageSize, preferredBlockSize, blockTimeout, maxResourceBodySize});
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		Request requestToSend = request;

		if (isTransparentBlockwiseHandlingEnabled()) {

			BlockOption block2 = request.getOptions().getBlock2();
			if (block2 != null && block2.getNum() > 0) {
				// This is the case if the user has explicitly added a block option
				// for random access.
				// Note: We do not regard it as random access when the block number is 0.
				// This is because the user might just want to do early block
				// size negotiation but actually want to retrieve the whole body by means of
				// a transparent blockwise transfer.
				LOGGER.fine("outbound request contains block2 option, creating random-access blockwise status");
				addRandomAccessBlock2Status(exchange, request);

			} else if (requiresBlockwise(request)) {
				// This must be a large POST or PUT request
				requestToSend = startBlockwiseUpload(exchange, request);

			}
		}

		exchange.setCurrentRequest(requestToSend);
		lower().sendRequest(exchange, requestToSend);
	}

	protected Request startBlockwiseUpload(final Exchange exchange, final Request request) {

		final KeyUri key = getKey(exchange, request);

		synchronized (block1Transfers) {

			Block1BlockwiseStatus status = getBlock1Status(key);
			if (status != null) {
				// there already is a block1 transfer going on to the resource
				// cancel the original request and start over with a new tracker
				status.cancelRequest();
				clearBlock1Status(key);
			}
			status = getOutboundBlock1Status(key, exchange, request);

			final Request block = status.getNextRequestBlock();

			block.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onReadyToSend() {
					// when the request for transferring the first block
					// has been sent out, we copy the token to the
					// original request so that at the end of the
					// blockwise transfer the Matcher can correctly
					// close the overall exchange
					request.setToken(block.getToken());
				}

				@Override
				public void onCancel() {
					failed();
				}

				@Override
				public void failed() {
					clearBlock1Status(key);
				}
			});

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

			} else if (block2 != null) {

				KeyUri key = getKey(exchange, request);
				Block2BlockwiseStatus status = getBlock2Status(key);
				if (status == null) {

					LOGGER.log(
							Level.FINE,
							"peer wants to retrieve individual block2 {0}, delivering request to application layer",
							block2);
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

	protected void handleInboundBlockwiseUpload(final Exchange exchange, final Request request) {

		if (requestExceedsMaxBodySize(request)) {

			Response error = Response.createResponse(request, ResponseCode.REQUEST_ENTITY_TOO_LARGE);
			error.setPayload(String.format("body too large, can process %d bytes max", maxResourceBodySize));
			error.getOptions().setSize1(maxResourceBodySize);
			exchange.setCurrentResponse(error);
			lower().sendResponse(exchange, error);

		} else {

			BlockOption block1 = request.getOptions().getBlock1();
			LOGGER.log(Level.FINE, "inbound request contains block1 option {0}", block1);
			KeyUri key = getKey(exchange, request);
			Block1BlockwiseStatus status = getInboundBlock1Status(key, exchange, request);

			if (block1.getNum() == 0 && status.getCurrentNum() > 0) {
				status = resetInboundBlock1Status(key, exchange, request);
			}

			if (block1.getNum() != status.getCurrentNum()) {
				// ERROR, wrong number, Incomplete
				LOGGER.log(Level.WARNING,
						"peer sent wrong block, expected no. {0} but got {1}. Responding with 4.08 (Request Entity Incomplete)",
						new Object[]{status.getCurrentNum(), block1.getNum()});

				sendBlock1ErrorResponse(key, exchange, request, ResponseCode.REQUEST_ENTITY_INCOMPLETE, "wrong block number");

			} else if (!status.hasContentFormat(request.getOptions().getContentFormat())) {

				sendBlock1ErrorResponse(key, exchange, request, ResponseCode.REQUEST_ENTITY_INCOMPLETE, "unexpected Content-Format");

			} else if (!status.addBlock(request.getPayload())) {

				sendBlock1ErrorResponse(key, exchange, request, ResponseCode.REQUEST_ENTITY_TOO_LARGE,
						"body exceeded expected size " + status.getBufferSize());

			} else {

				status.setCurrentNum(status.getCurrentNum() + 1);
				if ( block1.isM() ) {

					// do not assemble and deliver the request yet

					LOGGER.log(Level.FINE, "acknowledging incoming block1 [num={0}], expecting more blocks to come", block1.getNum());

					Response piggybacked = Response.createResponse(request, ResponseCode.CONTINUE);
					piggybacked.getOptions().setBlock1(block1.getSzx(), true, block1.getNum());
					piggybacked.setLast(false);

					exchange.setCurrentResponse(piggybacked);
					lower().sendResponse(exchange, piggybacked);

				} else {

					LOGGER.log(Level.FINE, "peer has sent last block1 [num={0}], delivering request to application layer", block1.getNum());

					// Remember block to acknowledge. TODO: We might make this a boolean flag in status.
					exchange.setBlock1ToAck(block1); 

					// Assemble and deliver
					Request assembled = new Request(request.getCode());
					assembled.setSenderIdentity(request.getSenderIdentity());
					status.assembleMessage(assembled);

					// make sure we deliver the request using the MID and token of the latest request
					// so that the response created by the application layer can reply to his token and
					// MID
					assembled.setMID(request.getMID());
					assembled.setToken(request.getToken());

					// make sure peer's early negotiation of block2 size gets included
					assembled.getOptions().setBlock2(request.getOptions().getBlock2());

					clearBlock1Status(key);

					exchange.setRequest(assembled);
					upper().receiveRequest(exchange, assembled);
				}
			}
		}
	}

	protected void sendBlock1ErrorResponse(final KeyUri key, final Exchange exchange, final Request request,
			final ResponseCode errorCode, final String message) {

		BlockOption block1 = request.getOptions().getBlock1();
		Response error = Response.createResponse(request, errorCode);
		error.getOptions().setBlock1(block1.getSzx(), block1.isM(), block1.getNum());
		error.setPayload(message);
		clearBlock1Status(key);
		exchange.setCurrentResponse(error);
		lower().sendResponse(exchange, error);
	}

	protected void handleInboundRequestForNextBlock(final Exchange exchange, final Request request,
			final KeyUri key, final Block2BlockwiseStatus status) {

		synchronized (status) {

			BlockOption block2 = request.getOptions().getBlock2();
			Response block = status.getNextResponseBlock(block2);
			if (status.isComplete()) {
				// clean up blockwise status
				LOGGER.log(Level.FINE, "peer has requested last block of blockwise transfer: {0}", status);
				clearBlock2Status(key);
			} else {
				LOGGER.log(Level.FINE, "peer has requested intermediary block of blockwise transfer: {0}", status);
			}

			exchange.setCurrentResponse(block);
			lower().sendResponse(exchange, block);
		}
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
						LOGGER.log(
							Level.WARNING,
							"resource [{0}] implementation error, peer requested block {1} but resource returned block {2}",
							new Object[]{exchange.getRequest().getURI(), requestBlock2.getNum(), responseBlock2.getNum()});
						responseToSend = Response.createResponse(exchange.getRequest(), ResponseCode.INTERNAL_SERVER_ERROR);
						responseToSend.setType(response.getType());
						responseToSend.setMID(response.getMID());
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

				}

			} else if (requiresBlockwise(exchange, response, requestBlock2)) {

				// the client either has not included a block2 option at all or has
				// included a block2 option with num = 0 (early negotiation of block size)

				KeyUri key = getKey(exchange, response);
				// There are potentially multiple blockwise transfers of the same
				// resource representation going on with the same client.
				// We cannot distinguish these because the status is scoped to the
				// client's endpoint address only (which is the same in this case)
				// thus these transfers all "share" the same status object on the
				// server (this) side.
				// This shared status will be cleaned up as soon as the last block
				// is transferred for the first time. Any subsequent block2 requests
				// with num > 0 will then be processed as "random block access" requests.
				Block2BlockwiseStatus status = getOutboundBlock2Status(key, exchange, response);

				// Subsequent requests for the same resource from the same client for
				// either block 0 or without a block2 option at all will result in
				// the existing status being "re-used". We therefore need to make
				// sure that we return the first block of the payload.
				BlockOption block2 = requestBlock2 != null ? requestBlock2 : new BlockOption(preferredBlockSzx, false, 0);
				responseToSend = status.getNextResponseBlock(block2);

				if (status.isComplete()) {
					// clean up blockwise status
					LOGGER.log(Level.FINE, "block2 transfer of response finished after first block: {0}", status);
					clearBlock2Status(key);
				} else {
					LOGGER.log(Level.FINE, "block2 transfer of response started: {0}", status);
					addBlock2CleanUpObserver(responseToSend, key);
				}

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

		if (isTransparentBlockwiseHandlingEnabled()) {

			if (response.isError()) {
				// handle blockwise specific error codes
				switch(response.getCode()) {
				case REQUEST_ENTITY_INCOMPLETE: // 4.08
					// we seem to have uploaded blocks not in expected order
				case REQUEST_ENTITY_TOO_LARGE: // 4.13
					// server is not able to process the payload we included
					KeyUri key = getKey(exchange, exchange.getCurrentRequest());
					clearBlock1Status(key);
				default:
					Response resp = new Response(response.getCode());
					resp.setToken(exchange.getRequest().getToken());
					if (exchange.getRequest().getType() == Type.CON) {
						resp.setType(Type.ACK);
						resp.setMID(exchange.getRequest().getMID());
					} else {
						resp.setType(Type.NON);
					}
					resp.setSource(response.getSource());
					resp.setSourcePort(response.getSourcePort());
					resp.setPayload(response.getPayload());
					resp.setOptions(response.getOptions());
					exchange.setResponse(resp);
					upper().receiveResponse(exchange, resp);
				}
			} else if (!response.hasBlockOption()) {

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
	 * Checks if a response acknowledges a block sent in a POST/PUT request and
	 * sends the next block if applicable.
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 */
	private void handleBlock1Response(final Exchange exchange, final Response response) {

		BlockOption block1 = response.getOptions().getBlock1();
		LOGGER.log(Level.FINER, "received response acknowledging block1 {0}", block1);

		// Block1 transfer has been originally created for an outbound request
		final KeyUri key = getKey(exchange, exchange.getRequest());

		synchronized (block1Transfers) {

			Block1BlockwiseStatus status = getBlock1Status(key);

			if (status == null) {

				// request has not been sent blockwise
				LOGGER.log(Level.FINE, "discarding unexpected block1 response: {0}", response);

			} else if (!status.hasMatchingToken(response)) {

				// a concurrent block1 transfer has been started in the meantime
				// which has "overwritten" the status object with the new (concurrent) request
				// so we simply discard the response
				LOGGER.log(Level.FINE, "discarding obsolete block1 response: {0}", response);

			} else if (exchange.getRequest().isCanceled()) {

				clearBlock1Status(key);

			} else if (!status.isComplete()) {

				// this means that our last request's M-bit was set

				if (block1.isM()) {
					if (response.getCode() == ResponseCode.CONTINUE) {
						// server wants us to send the remaining blocks before returning
						// its response
						sendNextBlock(exchange, response, key, status);
					} else {
						// the server has responded in a way that is not compliant with RFC 7959
						clearBlock1Status(key);
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
				clearBlock1Status(key);

				if (response.getOptions().hasBlock2()) {
					LOGGER.finer("Block1 followed by Block2 transfer");
				} else {
					// All request blocks have been acknowledged and we have received a
					// response that does not need blockwise transfer. Thus, deliver it.
					exchange.setResponse(response);
					upper().receiveResponse(exchange, response);
				}
			}
		}
	}

	protected void sendNextBlock(final Exchange exchange, final Response response, final KeyUri key, final Block1BlockwiseStatus status) {

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
		int nextNum = status.getCurrentNum() + currentSize / newSize;
		LOGGER.log(Level.FINE, "sending next Block1 num={0}", nextNum);
		Request nextBlock = status.getNextRequestBlock(nextNum, newSzx);
		// we use the same token to ease traceability
		nextBlock.setToken(response.getToken());
		addBlock1CleanUpObserver(nextBlock, key);

		exchange.setCurrentRequest(nextBlock);
		lower().sendRequest(exchange, nextBlock);
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
			clearBlock2Status(key);

			if (response.isNotification()) {
				// We have received a notification for an observed resource that the
				// application layer is no longer interested in.
				// Let upper layers decide what to do with the notification.
				upper().receiveResponse(exchange, response);
			}

		} else if (responseExceedsMaxBodySize(response)) {

			LOGGER.log(Level.FINE, "requested resource body exceeds max buffer size [{0}], aborting request", maxResourceBodySize);
			exchange.getRequest().cancel();

		} else {

			synchronized (exchange) {

				Block2BlockwiseStatus status = getInboundBlock2Status(key, exchange, response);

				if (status.isInterferingNotification(response)) {

					// a new notification has arrived

					if (response.getOptions().getObserve() > status.getObserve()) {
						status = resetInboundBlock2Status(key, exchange, response);
					} else {
						LOGGER.log(
								Level.FINER,
								"discarding old notification [{0}] received during ongoing blockwise transfer: {1}",
								new Object[]{ response.getOptions().getObserve(), response });
						return;
					}
				}

				// We now need to make sure that we are not processing a block from a blockwise transfer
				// for a previous (outdated) notification.
				// When a response to a block2 request is received from a peer, the Matcher will look up
				// the corresponding Exchange and pass the response up the stack to the BlockwiseLayer.
				// The problem we are facing is that the key used to look up the Block2BlockwiseStatus
				// will always be the same if no ETag is contained in the notification (the key then only
				// depends on the request's URI and source endpoint). So there is no way to distinguish a
				// response to an outdated block2 request from a response that is part of the most recent
				// block2 transfer.
				// In order to be able to distinguish between a block of an old vs a new notification,
				// the Exchange used to initially create the Block2BlockwiseStatus is
				// marked with the notification's observe option (see Block2BlockwiseStatus.forInboundResponse()).
				// We can then compare the observe option value from the Exchange that has been looked up
				// for the incoming response with the value of the most recently received notification from the
				// Block2BlockwiseStatus that has been looked up for the key.

				if (exchange.getNotificationNumber() != null && exchange.getNotificationNumber() != status.getObserve()) {

					// we are processing a "delayed" response to a block2 request issued for a previous notification
					// this may happen if the peer sends a new notification before the blockwise transfer has finished
					LOGGER.log(
							Level.FINER,
							"discarding outdated block2 transfer response for old notification {0}, current is {1}: {2}",
							new Object[]{ exchange.getNotificationNumber(), status.getObserve(), response });

				} else if (block2.getNum() == status.getCurrentNum() && (block2.getNum() == 0 || Arrays.equals(response.getToken(), exchange.getCurrentRequest().getToken()))) {

					// check token to avoid mixed blockwise transfers (possible with observe) 

					// We got the block we expected :-)
					LOGGER.log(Level.FINER, "processing incoming block2 response [num={0}]: {1}", new Object[]{ block2.getNum(), response });

					if (status.isRandomAccess()) {

						// The client has requested this specific block and we deliver it
						exchange.setResponse(response);
						clearBlock2Status(key);
						upper().receiveResponse(exchange, response);

					} else if (!status.addBlock(response)) {

						LOGGER.log(Level.FINE, "cannot process payload of block2 response, aborting request");
						exchange.getRequest().cancel();
						return;

					} else if (block2.isM()) {

						// request next block
						requestNextBlock(exchange, response, key, status);
					} else {

						// we have received the last block of the block2 transfer

						LOGGER.log(
								Level.FINER,
								"all {0} blocks have been retrieved, assembling response and delivering to application layer",
								status.getBlockCount());
						Response assembled = new Response(response.getCode());
						status.assembleMessage(assembled);

						// set overall transfer RTT
						assembled.setRTT(exchange.calculateRTT());

						if (status.isNotification()) {

							/*
							 * When retrieving the rest of a blockwise notification
							 * with a different token, the additional Matcher state
							 * must be cleaned up through the call below.
							 */
							if (!response.getOptions().hasObserve()) {
								// call the clean-up mechanism for the additional Matcher entry in exchangesByToken
								exchange.completeCurrentRequest();
							}
						}

						clearBlock2Status(key);
						LOGGER.log(Level.FINE, "assembled response: {0}", assembled);
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
					// Canceling the request would interfere with Observe, so just ignore it
					LOGGER.log(Level.WARNING,
							"ignoring block2 response with wrong block number {1} (expected {0}): {2}",
							new Object[]{status.getCurrentNum(), block2.getNum(), response});
				}
			}
		}
	}
	
	/**
	 * Sends request for the next response block.
	 */
	protected void requestNextBlock(final Exchange exchange, final Response response, final KeyUri key, final Block2BlockwiseStatus status) {
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
		// do not enforce CON, since NON could make sense over SMS or similar transports
		block.setType(request.getType());
		block.setDestination(request.getDestination());
		block.setDestinationPort(request.getDestinationPort());

		/*
		 * WARNING:
		 * 
		 * For Observe, the Matcher then will store the same
		 * exchange under a different KeyToken in exchangesByToken,
		 * which is cleaned up in the else case below.
		 */
		if (!response.getOptions().hasObserve()) {
			block.setToken(response.getToken());
		}

		// copy options
		block.setOptions(new OptionSet(request.getOptions()));
		block.getOptions().setBlock2(newSzx, false, nextNum);
		if (response.getOptions().getETagCount() > 0) {
			// use ETag provided by peer
			block.getOptions().addETag(response.getOptions().getETags().get(0));
		}

		// make sure NOT to use Observe for block retrieval
		block.getOptions().removeObserve();

		// copy message observers from original request so that they will be notified
		// if something goes wrong with this blockwise request, e.g. if it times out
		block.addMessageObservers(request.getMessageObservers());
		// add an observer that cleans up the block2 transfer tracker if the
		// block request fails
		addBlock2CleanUpObserver(block, key);

		status.setCurrentNum(nextNum);

		LOGGER.log(Level.FINER, "requesting next Block2 [num={0}]: {1}", new Object[]{ nextNum, block });
		exchange.setCurrentRequest(block);
		lower().sendRequest(exchange, block);

	}

	/////////// HELPER METHODS //////////

	protected static KeyUri getKey(final Exchange exchange, final Request request) {

		if (exchange.isOfLocalOrigin()) {
			return KeyUri.fromOutboundRequest(request);
		} else {
			return KeyUri.fromInboundRequest(request);
		}
	}

	protected static KeyUri getKey(final Exchange exchange, final Response response) {

		if (exchange.isOfLocalOrigin()) {
			return KeyUri.fromInboundResponse(exchange.getRequest().getURI(), response);
		} else {
			return KeyUri.fromOutboundResponse(exchange.getRequest().getURI(), response);
		}
	}

	private Block1BlockwiseStatus getOutboundBlock1Status(final KeyUri key, final Exchange exchange, final Request request) {

		synchronized (block1Transfers) {
			Block1BlockwiseStatus status = block1Transfers.get(key);
			if (status == null) {
				status = Block1BlockwiseStatus.forOutboundRequest(exchange, request, preferredBlockSize);
				block1Transfers.put(key, status);
				LOGGER.log(Level.FINE, "created tracker for outbound block1 transfer {0}, transfers in progress: {1}",
						new Object[]{ status, block1Transfers.size() });
			}
			return status;
		}
	}

	protected Block1BlockwiseStatus getInboundBlock1Status(final KeyUri key, final Exchange exchange, final Request request) {

		synchronized (block1Transfers) {
			Block1BlockwiseStatus status = block1Transfers.get(key);
			if (status == null) {
				status = Block1BlockwiseStatus.forInboundRequest(exchange, request, maxResourceBodySize);
				block1Transfers.put(key, status);
				LOGGER.log(Level.FINE, "created tracker for inbound block1 transfer {0}, transfers in progress: {1}",
						new Object[]{ status, block1Transfers.size() });
			}
			// register a task for cleaning up if the peer does not send all blocks
			prepareBlock1Cleanup(status, key);
			return status;
		}
	}

	protected Block1BlockwiseStatus resetInboundBlock1Status(final KeyUri key, final Exchange exchange, final Request request) {

		synchronized (block1Transfers) {
			Block1BlockwiseStatus removedStatus = block1Transfers.remove(key);
			LOGGER.log(Level.WARNING, "inbound block1 transfer reset at {0} by peer: {1}", new Object[]{ removedStatus, request });
			return getInboundBlock1Status(key, exchange, request);
		}
	}

	protected Block2BlockwiseStatus getOutboundBlock2Status(final KeyUri key, final Exchange exchange, final Response response) {

		synchronized (block2Transfers) {
			Block2BlockwiseStatus status = block2Transfers.get(key);
			if (status == null) {
				status = Block2BlockwiseStatus.forOutboundResponse(exchange, response, preferredBlockSize);
				block2Transfers.put(key, status);
				LOGGER.log(Level.FINE, "created tracker for outbound block2 transfer {0}, transfers in progress: {1}",
						new Object[]{ status, block2Transfers.size() });
			}
			// we register a clean up task in case the peer does not retrieve all blocks
			prepareBlock2Cleanup(status, key);
			return status;
		}
	}

	private Block2BlockwiseStatus getInboundBlock2Status(final KeyUri key, final Exchange exchange, final Response response) {

		synchronized (block2Transfers) {
			Block2BlockwiseStatus status = block2Transfers.get(key);
			if (status == null) {
				status = Block2BlockwiseStatus.forInboundResponse(exchange, response, maxResourceBodySize);
				block2Transfers.put(key, status);
				LOGGER.log(Level.FINE, "created tracker for inbound block2 transfer {0}, transfers in progress: {1}",
						new Object[]{ status, block2Transfers.size() });
			}
			return status;
		}
	}

	private Block2BlockwiseStatus resetInboundBlock2Status(final KeyUri key, final Exchange exchange, final Response response) {

		synchronized (block2Transfers) {

			Block2BlockwiseStatus removedStatus = clearBlock2Status(key);

			// log a warning, since this might cause a loop where no notification is ever assembled (when the server sends notifications faster than the blocks can be transmitted)
			LOGGER.log(Level.WARNING, "inbound block2 transfer reset at {0} by new notification: {1}", new Object[]{ removedStatus, response });

			return getInboundBlock2Status(key, exchange, response);
		}
	}

	protected KeyUri addRandomAccessBlock2Status(final Exchange exchange, final Request request) {

		KeyUri key = getKey(exchange, request);
		synchronized (block2Transfers) {
			Block2BlockwiseStatus status = Block2BlockwiseStatus.forRandomAccessRequest(exchange, request);
			block2Transfers.put(key, status);
			addBlock2CleanUpObserver(request, key);
			LOGGER.log(Level.FINE, "created tracker for random access block2 retrieval {0}, transfers in progress: {1}",
					new Object[]{ status, block2Transfers.size() });
			return key;
		}
	}

	protected Block1BlockwiseStatus getBlock1Status(final KeyUri key) {

		synchronized (block1Transfers) {
			return block1Transfers.get(key);
		}
	}

	private Block2BlockwiseStatus getBlock2Status(final KeyUri key) {

		synchronized (block2Transfers) {
			return block2Transfers.get(key);
		}
	}

	protected Block1BlockwiseStatus clearBlock1Status(final KeyUri key) {
		synchronized (block1Transfers) {
			Block1BlockwiseStatus removedTracker = block1Transfers.remove(key);
			LOGGER.log(Level.FINE, "removing block1 tracker [{0}], block1 transfers still in progress: {1}",
					new Object[]{ key, block1Transfers.size() });
			return removedTracker;
		}
	}

	protected Block2BlockwiseStatus clearBlock2Status(final KeyUri key) {
		synchronized (block2Transfers) {
			Block2BlockwiseStatus removedTracker = block2Transfers.remove(key);
			LOGGER.log(Level.FINE, "removing block2 tracker [{0}], block2 transfers still in progress: {1}",
					new Object[]{ key, block2Transfers.size() });
			return removedTracker;
		}
	}

	protected boolean requiresBlockwise(final Request request) {
		boolean blockwiseRequired = false;
		if (request.getCode() == Code.PUT || request.getCode() == Code.POST) {
			blockwiseRequired = request.getPayloadSize() > maxMessageSize;
		}
		if (blockwiseRequired) {
			LOGGER.log(Level.FINE, "request body [{0}/{1}] requires blockwise transfer",
					new Object[]{request.getPayloadSize(), maxMessageSize});
		}
		return blockwiseRequired;
	}

	protected boolean requiresBlockwise(final Exchange exchange, final Response response, final BlockOption requestBlock2) {

		boolean blockwiseRequired = response.getPayloadSize() > maxMessageSize;
		if (requestBlock2 != null) {
			// client might have included early negotiation block2 option
			blockwiseRequired = blockwiseRequired || response.getPayloadSize() > requestBlock2.getSize();
		}
		if (blockwiseRequired) {
			LOGGER.log(Level.FINE, "response body [{0}/{1}] requires blockwise transfer",
					new Object[]{response.getPayloadSize(), maxMessageSize});
		}
		return blockwiseRequired;
	}

	protected boolean isTransparentBlockwiseHandlingEnabled() {
		return maxResourceBodySize > 0;
	}

	private boolean responseExceedsMaxBodySize(final Response response) {
		return response.getOptions().hasSize2() && response.getOptions().getSize2() > maxResourceBodySize;
	}

	protected boolean requestExceedsMaxBodySize(final Request request) {
		return request.getOptions().hasSize1() && request.getOptions().getSize1() > maxResourceBodySize;
	}

	/**
	 * Schedules a task for cleaning up state when a block1 transfer times out.
	 * 
	 * @param status The tracker for the block1 transfer to clean up for.
	 * @param key The key of the tracker.
	 */
	protected void prepareBlock1Cleanup(final Block1BlockwiseStatus status, final KeyUri key) {

		LOGGER.log(Level.FINE, "scheduling clean up task for block1 transfer {0}", key);
		ScheduledFuture<?> taskHandle = scheduleBlockCleanupTask(new Runnable() {

			@Override
			public void run() {
				if (!status.isComplete()) {
					LOGGER.log(Level.FINE, "block1 transfer timed out: {0}", key);
				}
				clearBlock1Status(key);
			}
		});
		status.setBlockCleanupHandle(taskHandle);
	}

	protected MessageObserver addBlock1CleanUpObserver(final Message message, final KeyUri key) {

		MessageObserver observer = new MessageObserverAdapter() {

			@Override
			public void onCancel() {
				clearBlock1Status(key);
			}

			@Override
			protected void failed() {
				clearBlock1Status(key);
			}
		};
		message.addMessageObserver(observer);
		return observer;
	}

	protected MessageObserver addBlock2CleanUpObserver(final Message message, final KeyUri key) {

		MessageObserver observer = new MessageObserverAdapter() {

			@Override
			public void onCancel() {
				clearBlock2Status(key);
			}

			@Override
			protected void failed() {
				clearBlock2Status(key);
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

		LOGGER.log(Level.FINE, "scheduling clean up task for block2 transfer {0}", key);
		ScheduledFuture<?> taskHandle = scheduleBlockCleanupTask(new Runnable() {

			@Override
			public void run() {
				if (!status.isComplete()) {
					LOGGER.log(Level.FINE, "block2 transfer timed out: {0}", key);
				}
				clearBlock2Status(key);
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
}
