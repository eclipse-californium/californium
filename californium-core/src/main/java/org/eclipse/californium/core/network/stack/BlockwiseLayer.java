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
 *    Achim Kraus (Bosch Software Innovations GmbH) - check, if exchange is already
 *                                                    completed before report timeout.
 *                                                    Issue #103
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
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * Provides transparent handling of blockwise transfer of a large <em>resource body</em>.
 * <p>
 * Outbound requests containing a large resource body that is too large to be sent in the payload
 * of a single message are transparently replaced by a sequence of message exchanges doing a
 * blockwise transfer of the body to the server.
 * <p>
 * If a response received from a server contains a payload that represents a single block of
 * a resource body then a blockwise transfer for retrieving the individual blocks of the resource
 * body is started. Once all blocks are retrieved, they are assembled into a single {@code Response}
 * object containing the full body which is then delivered to the application layer.
 * 
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
	private int maxMessageSize;
	private int preferredBlockSize;
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
	 * If not set, a default value of 1024 bytes is used.</li>
	 * 
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#PREFERRED_BLOCK_SIZE} -
	 * This value is used as the value proposed to a peer when doing a transparent blockwise transfer.
	 * The value indicates the number of bytes, not the szx code.
	 * If not set, a default value of 512 bytes is used.</li>
	 * 
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MAX_RESOURCE_BODY_SIZE} -
	 * This value (in bytes) is used as the upper limit for the size of the buffer used for assembling
	 * blocks of a transparent blockwise transfer. Resource bodies larger than this value can only be
	 * transferred in a manually managed blockwise transfer. Setting this value to 0 disables transparent
	 * blockwise handling altogether, i.e. all messages will simply be forwarded directly up and down to
	 * the next layer.
	 * If not set, a default value of 2048 bytes is used.</li>
	 * 
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#BLOCKWISE_STATUS_LIFETIME} -
	 * The maximum amount of time (in milliseconds) allowed between transfers of individual blocks before
	 * the blockwise transfer state is discarded.
	 * If not set, a default value of 30 seconds is used.</li>
	 * </ul>

	 * @param config The configuration values to use.
	 */
	public BlockwiseLayer(final NetworkConfig config) {

		maxMessageSize = config.getInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 1024);
		preferredBlockSize = config.getInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 512);
		blockTimeout = config.getInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME);
		maxResourceBodySize = config.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, 2048);

		LOGGER.log(Level.CONFIG,
			"BlockwiseLayer uses MAX_MESSAGE_SIZE={0}, PREFERRED_BLOCK_SIZE={1}, BLOCKWISE_STATUS_LIFETIME={2} and MAX_RESOURCE_BODY_SIZE={3}",
			new Object[]{maxMessageSize, preferredBlockSize, blockTimeout, maxResourceBodySize});
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		BlockOption block2 = request.getOptions().getBlock2();
		if (block2 != null && block2.getNum() > 0) {
			// This is the case if the user has explicitly added a block option
			// for random access.
			// Note: We do not regard it as random access when the block num is
			// 0. This is because the user might just want to do early block
			// size negotiation but actually wants to receive all blocks.
			LOGGER.fine("request contains block2 option, creating random-access blockwise status");
			BlockwiseStatus status = new BlockwiseStatus(getSizeForSzx(block2.getSzx()), request.getOptions().getContentFormat());
			status.setCurrentSzx(block2.getSzx());
			status.setCurrentNum(block2.getNum());
			status.setRandomAccess(true);
			exchange.setResponseBlockStatus(status);
			lower().sendRequest(exchange, request);

		} else if (requiresBlockwise(request)) {
			// This must be a large POST or PUT request
			startBlockwiseUpload(exchange, request);

		} else {
			// no blockwise transfer required
			exchange.setCurrentRequest(request);
			lower().sendRequest(exchange, request);
		}
	}

	private void startBlockwiseUpload(final Exchange exchange, final Request request) {

		BlockwiseStatus status = findRequestBlockStatus(exchange, request);

		final Request block = getNextRequestBlock(request, status);
		// indicate overall body size to peer
		block.getOptions().setSize1(request.getPayloadSize());

		exchange.setRequestBlockStatus(status);
		exchange.setCurrentRequest(block);
		lower().sendRequest(exchange, block);
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {

		BlockOption block1 = request.getOptions().getBlock1();
		if (block1 != null) {

			// This is a large POST or PUT request
			LOGGER.log(Level.FINE, "inbound request contains block1 option {0}", block1);

			if (isTransparentBlockwiseHandlingEnabled()) {

				handleInboundBlockwiseUpload(block1, exchange, request);

			} else {

				LOGGER.fine("transparent blockwise handling is disabled, delivering request to application layer");
				upper().receiveRequest(exchange, request);

			}

		} else if (exchange.getResponse() != null && request.getOptions().hasBlock2()) {
			// The response has already been generated and the client just wants its next block

			BlockOption block2 = request.getOptions().getBlock2();
			Response response = exchange.getResponse();
			BlockwiseStatus status = findResponseBlockStatus(exchange, response);
			status.setCurrentNum(block2.getNum());
			status.setCurrentSzx(block2.getSzx());

			Response block = getNextResponseBlock(response, status);
			// indicate overall body size to peer
			block.getOptions().setSize2(response.getPayloadSize());
			if (status.isComplete()) {
				// clean up blockwise status
				LOGGER.log(Level.FINE, "peer has requested last block of blockwise transfer: {0}", status);
				exchange.setResponseBlockStatus(null);
				exchange.setBlockCleanupHandle(null);
			} else {
				LOGGER.log(Level.FINE, "peer has requested intermediary block of blockwise transfer: {0}", status);
			}

			exchange.setCurrentResponse(block);
			lower().sendResponse(exchange, block);

		} else {
			earlyBlock2Negotiation(exchange, request);

			exchange.setRequest(request);
			upper().receiveRequest(exchange, request);
		}
	}

	private void handleInboundBlockwiseUpload(final BlockOption block1, final Exchange exchange, final Request request) {

		if (requestExceedsMaxBodySize(request)) {

			Response error = Response.createResponse(request, ResponseCode.REQUEST_ENTITY_TOO_LARGE);
			error.setPayload(String.format("body too large, can process %d bytes max", maxResourceBodySize));
			error.getOptions().setSize1(maxResourceBodySize);
			lower().sendResponse(exchange, error);

		} else {

			BlockwiseStatus status = findRequestBlockStatus(exchange, request);

			if (block1.getNum() == 0 && status.getCurrentNum() > 0) {
				// reset the blockwise transfer
				LOGGER.finer("Block1 num is 0, the client has restarted the blockwise transfer. Reset status.");
				// reset current status
				exchange.setRequestBlockStatus(null);
				// and create new status for fresher notification
				status = findRequestBlockStatus(exchange, request);
			}

			if (block1.getNum() == status.getCurrentNum()) {

				if (status.hasContentFormat(request.getOptions().getContentFormat())) {

					status.addBlock(request.getPayload());
					status.setCurrentNum(status.getCurrentNum() + 1);
					if ( block1.isM() ) {
						LOGGER.finest("There are more blocks to come. Acknowledge this block.");
						
						Response piggybacked = Response.createResponse(request, ResponseCode.CONTINUE);
						piggybacked.getOptions().setBlock1(block1.getSzx(), true, block1.getNum());
						piggybacked.setLast(false);

						exchange.setCurrentResponse(piggybacked);
						lower().sendResponse(exchange, piggybacked);

						// do not assemble and deliver the request yet

					} else {
						LOGGER.finer("This was the last block. Deliver request");

						// Remember block to acknowledge. TODO: We might make this a boolean flag in status.
						exchange.setBlock1ToAck(block1); 

						// Block2 early negotiation
						earlyBlock2Negotiation(exchange, request);

						// Assemble and deliver
						Request assembled = new Request(request.getCode());
						assembled.setSenderIdentity(request.getSenderIdentity());
						assembleMessage(status, assembled);

						exchange.setRequest(assembled);
						upper().receiveRequest(exchange, assembled);
					}

				} else {
					Response error = Response.createResponse(request, ResponseCode.REQUEST_ENTITY_INCOMPLETE);
					error.getOptions().setBlock1(block1.getSzx(), block1.isM(), block1.getNum());
					error.setPayload("unexpected Content-Format");

					exchange.setCurrentResponse(error);
					lower().sendResponse(exchange, error);
					return;
				}

			} else {
				// ERROR, wrong number, Incomplete
				LOGGER.log(Level.WARNING,
						"Wrong block number. Expected {0} but received {1}. Respond with 4.08 (Request Entity Incomplete)",
						new Object[]{status.getCurrentNum(), block1.getNum()});
				Response error = Response.createResponse(request, ResponseCode.REQUEST_ENTITY_INCOMPLETE);
				error.getOptions().setBlock1(block1.getSzx(), block1.isM(), block1.getNum());
				error.setPayload("Wrong block number");
				exchange.setCurrentResponse(error);

				lower().sendResponse(exchange, error);
			}
		}
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {

		BlockOption block1 = exchange.getBlock1ToAck();

		if (block1 != null) {
			exchange.setBlock1ToAck(null);
		}

		if (requiresBlockwise(exchange, response)) {

			BlockwiseStatus status = findResponseBlockStatus(exchange, response);
			int bodySize = response.getPayloadSize();
			Response block = getNextResponseBlock(response, status);
			// indicate overall body size to peer
			block.getOptions().setSize2(bodySize);

			if (block1 != null) { // in case we still have to ack the last block1
				block.getOptions().setBlock1(block1);
			}
			if (status.isComplete()) {
				// clean up blockwise status
				LOGGER.log(Level.FINE, "Ongoing finished on first block {0}", status);
				exchange.setResponseBlockStatus(null);
				exchange.setBlockCleanupHandle(null);
			} else {
				LOGGER.log(Level.FINE, "Ongoing started {0}", status);
			}

			exchange.setCurrentResponse(block);
			lower().sendResponse(exchange, block);

		} else {
			if (block1 != null) {
				response.getOptions().setBlock1(block1);
			}
			exchange.setCurrentResponse(response);
			// Block1 transfer completed
			exchange.setBlockCleanupHandle(null);
			lower().sendResponse(exchange, response);
		}
	}

	/**
	 * Invoked when a response has been received from a peer.
	 * <p>
	 * Checks whether the response either contains a block of an already ongoing
	 * blockwise transfer or contains the first block of a large body and
	 * requires the start of a blockwise transfer to retrieve the remaining blocks
	 * of the body.
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 */
	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {

		if (exchange.getRequest().isCanceled()) {
			// do not continue fetching blocks if canceled
			// reject (in particular for Block+Observe)
			if (response.getType()!=Type.ACK) {
				LOGGER.finer("rejecting blockwise transfer for canceled Exchange");
				EmptyMessage rst = EmptyMessage.newRST(response);
				sendEmptyMessage(exchange, rst);
				// Matcher sets exchange as complete when RST is sent
			}

		} else if (!response.hasBlockOption()) {

			// This is a normal response, no special treatment necessary
			exchange.setResponse(response);
			upper().receiveResponse(exchange, response);

		} else {

			BlockOption block = response.getOptions().getBlock1();
			if (block != null) {
				handleBlock1Response(exchange, response, block);
			}

			block = response.getOptions().getBlock2();
			if (block != null) {
				handleBlock2Response(exchange, response, block);
			}
		}

	}

	/**
	 * Checks if a response acknowledges a block sent in a POST/PUT request and
	 * sends the next block if applicable.
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 * @param block1 The block1 option from the response.
	 */
	private void handleBlock1Response(final Exchange exchange, final Response response, final BlockOption block1) {

		LOGGER.log(Level.FINER, "received response acknowledging block {0}", block1);

		BlockwiseStatus status = exchange.getRequestBlockStatus();
		if (status == null) {

			// request has not been sent blockwise
			LOGGER.log(Level.FINE, "discarding response containing unexpected block1 option: {0}", response);

		} else if (!status.isComplete()) {

			if (block1.isM()) {
				// server wants us to send the remaining blocks before returning
				// its response
				sendNextBlock(exchange, response, block1, status);

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
				sendNextBlock(exchange, response, block1, status);
			}

		} else if (!response.getOptions().hasBlock2()) {

			// All request block have been acknowledged and we receive a piggy-backed
			// response that needs no blockwise transfer. Thus, deliver it.
			upper().receiveResponse(exchange, response);

		} else {

			LOGGER.finer("Block1 followed by Block2 transfer");

		}
	}

	private void sendNextBlock(final Exchange exchange, final Response response, final BlockOption block1, final BlockwiseStatus requestStatus) {

		// Send next block
		int currentSize = 1 << (4 + requestStatus.getCurrentSzx());
		// Define new size of the block depending of preferred size block
		int newSize, newSzx;
		if (block1.getSize() < currentSize) {
			newSize = block1.getSize();
			newSzx = block1.getSzx();
		} else {
			newSize = currentSize;
			newSzx = requestStatus.getCurrentSzx();
		}
		int nextNum = requestStatus.getCurrentNum() + currentSize / newSize;
		LOGGER.log(Level.FINER, "Sending next Block1 num={0}", nextNum);
		requestStatus.setCurrentNum(nextNum);
		requestStatus.setCurrentSzx(newSzx);
		Request nextBlock = getNextRequestBlock(exchange.getRequest(), requestStatus);

		// indicate overall body size to peer
		nextBlock.getOptions().setSize1(exchange.getRequest().getPayloadSize());

		// we use the same token to ease traceability
		nextBlock.setToken(response.getToken());

		exchange.setCurrentRequest(nextBlock);
		lower().sendRequest(exchange, nextBlock);
		// do not deliver response
	}

	/**
	 * Checks if a response contains a single block of a large payload only and
	 * retrieves the remaining blocks if applicable.
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 * @param block2 The block2 option from the response.
	 */
	private void handleBlock2Response(final Exchange exchange, final Response response, final BlockOption block2) {

		if (responseExceedsMaxBodySize(response)) {
			LOGGER.log(Level.FINE, "requested resource body exceeds max buffer size [{0}], aborting request", maxResourceBodySize);
			exchange.getRequest().cancel();
			return;
		}

		BlockwiseStatus responseStatus = findResponseBlockStatus(exchange, response);

		// a new notification might arrive during a blockwise transfer
		if (response.isNotification() && block2.getNum() == 0 && responseStatus.getCurrentNum() != 0) {

			if (response.getOptions().getObserve() > responseStatus.getObserve()) {
				// log a warning, since this might cause a loop where no notification is ever assembled (when the server sends notifications faster than the blocks can be transmitted)
				LOGGER.log(Level.WARNING, "ongoing blockwise transfer reset at num = {0} by new notification: {1}", new Object[]{responseStatus.getCurrentNum(), response});
				// reset current status
				exchange.setResponseBlockStatus(null);
				// and create new status for fresher notification
				responseStatus = findResponseBlockStatus(exchange, response);
			} else {
				LOGGER.log(Level.FINE, "discarding old notification received during ongoing blockwise transfer: {0}", response);
				return;
			}
		}

		// check token to avoid mixed blockwise transfers (possible with observe) 
		if (block2.getNum() == responseStatus.getCurrentNum() && (block2.getNum() == 0 || Arrays.equals(response.getToken(), exchange.getCurrentRequest().getToken()))) {

			// We got the block we expected :-)

			if (!responseStatus.addBlock(response.getPayload())) {
				LOGGER.log(Level.FINE, "requested resource body exceeds max buffer size [{0}], aborting request", maxResourceBodySize);
				exchange.getRequest().cancel();
				return;
			}

			// store the observe sequence number to set it in the assembled response
			if (response.getOptions().hasObserve()) {
				responseStatus.setObserve(response.getOptions().getObserve());
			}

			if (responseStatus.isRandomAccess()) {
				// The client has requested this specific block and we deliver it
				exchange.setResponse(response);
				upper().receiveResponse(exchange, response);
			
			} else if (block2.isM()) {

				Request request = exchange.getRequest();
				int num = block2.getNum() + 1;
				int szx = block2.getSzx();
				boolean m = false;

				LOGGER.log(Level.FINER, "Requesting next Block2 num={0}", num);

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
				if (!response.getOptions().hasObserve()) block.setToken(response.getToken());

				// copy options
				block.setOptions(new OptionSet(request.getOptions()));
				// make sure NOT to use Observe for block retrieval
				block.getOptions().removeObserve();

				block.getOptions().setBlock2(szx, m, num);

				// copy message observers from original request so that they will be notified
				// if something goes wrong with this blockwise request, e.g. if it times out
				block.addMessageObservers(request.getMessageObservers());

				responseStatus.setCurrentNum(num);

				exchange.setCurrentRequest(block);
				lower().sendRequest(exchange, block);

			} else {
				LOGGER.log(Level.FINER, "We have received all {0} blocks of the response. Assemble and deliver", responseStatus.getBlockCount());
				Response assembled = new Response(response.getCode());

				assembleMessage(responseStatus, assembled);

				// set overall transfer RTT
				assembled.setRTT(System.currentTimeMillis() - exchange.getTimestamp());

				// Check if this response is a notification
				int observe = responseStatus.getObserve();
				if (observe != BlockwiseStatus.NO_OBSERVE) {

					/*
					 * When retrieving the rest of a blockwise notification
					 * with a different token, the additional Matcher state
					 * must be cleaned up through the call below.
					 */
					if (!response.getOptions().hasObserve()) {
						// call the clean-up mechanism for the additional Matcher entry in exchangesByToken
						exchange.completeCurrentRequest();
					}

					assembled.getOptions().setObserve(observe);
					// This is necessary for notifications that are sent blockwise:
					// Reset block number AND container with all blocks
					exchange.setResponseBlockStatus(null);
				}

				LOGGER.log(Level.FINE, "Assembled response: {0}", assembled);
				// Set the assembled response as current response
				exchange.setResponse(assembled);
				upper().receiveResponse(exchange, assembled);
			}

		} else {
			// ERROR, wrong block number (server error)
			// TODO: This scenario is not specified in the draft.
			// Canceling the request would interfere with Observe, so just ignore it
			LOGGER.log(Level.WARNING,
					"Wrong block number. Expected {0} but received {1}: {2}",
					new Object[]{responseStatus.getCurrentNum(), block2.getNum(), response});
			if (response.getType()==Type.CON) {
				EmptyMessage rst = EmptyMessage.newRST(response);
				lower().sendEmptyMessage(exchange, rst);
			}
		}
	}

	/////////// HELPER METHODS //////////

	private static void earlyBlock2Negotiation(final Exchange exchange, final Request request) {
		// Call this method when a request has completely arrived (might have
		// been sent in one piece without blockwise).
		BlockOption block2 = request.getOptions().getBlock2();
		if (block2 != null) {
			BlockwiseStatus status2 = new BlockwiseStatus(request.getOptions().getContentFormat(), block2.getNum(), block2.getSzx());
			LOGGER.log(Level.FINE, "Request with early block negotiation {0}. Create and set new Block2 status: {1}", new Object[]{block2, status2});
			exchange.setResponseBlockStatus(status2);
		}
	}

	/*
	 * NOTICE:
	 * This method is used by sendRequest and receiveRequest.
	 * Be careful, making changes to the status in here.
	 */
	private BlockwiseStatus findRequestBlockStatus(final Exchange exchange, final Request request) {
		BlockwiseStatus status = exchange.getRequestBlockStatus();
		if (status == null) {
			if (exchange.isOfLocalOrigin()) {
				// we are sending a large body out in a POST/GET to a peer
				// we only need to buffer one block each
				status = new BlockwiseStatus(preferredBlockSize, request.getOptions().getContentFormat());
			} else {
				// we are receiving a large body in a POST/GET from a peer
				// we need to be prepared to buffer up to MAX_RESOURCE_BODY_SIZE bytes
				int bufferSize = maxResourceBodySize;
				if (request.getOptions().hasBlock1() && request.getOptions().hasSize1()) {
					// use size indication for allocating buffer
					bufferSize = request.getOptions().getSize1();
				}
				status = new BlockwiseStatus(bufferSize, request.getOptions().getContentFormat());
			}
			status.setFirst(request);
			status.setCurrentSzx(computeSZX(preferredBlockSize));
			exchange.setRequestBlockStatus(status);
			LOGGER.log(Level.FINER, "There is no assembler status yet. Create and set new Block1 status: {0}", status);
		} else {
			LOGGER.log(Level.FINER, "Current Block1 status: {0}", status);
		}
		// sets a timeout to complete exchange
		prepareBlockCleanup(exchange);
		return status;
	}

	/*
	 * NOTICE:
	 * This method is used by sendResponse and receiveResponse.
	 * Be careful, making changes to the status in here.
	 */
	private BlockwiseStatus findResponseBlockStatus(final Exchange exchange, final Response response) {
		BlockwiseStatus status = exchange.getResponseBlockStatus();
		if (status == null) {
			if (exchange.isOfLocalOrigin()) {
				// we are receiving a large body in response to a request originating locally
				// we need to be prepared to buffer up to MAX_RESOURCE_BODY_SIZE bytes
				int bufferSize = maxResourceBodySize;
				if (response.getOptions().hasBlock2() && response.getOptions().hasSize2()) {
					// use size indication for allocating buffer
					bufferSize = response.getOptions().getSize2();
				}
				status = new BlockwiseStatus(bufferSize, response.getOptions().getContentFormat());
			} else {
				// we are sending out a large body in response to a request from a peer
				// we do not need to buffer and assemble anything
				status = new BlockwiseStatus(0, response.getOptions().getContentFormat());
			}
			status.setCurrentSzx(computeSZX(preferredBlockSize));
			status.setFirst(response);
			exchange.setResponseBlockStatus(status);
			LOGGER.log(Level.FINER, "There is no blockwise status yet. Create and set new Block2 status: {0}", status);
		} else {
			LOGGER.log(Level.FINER, "Current Block2 status: {0}", status);
		}
		// sets a timeout to complete exchange
		prepareBlockCleanup(exchange);
		return status;
	}

	private static Request getNextRequestBlock(final Request request, final BlockwiseStatus status) {
		int num = status.getCurrentNum();
		int szx = status.getCurrentSzx();
		Request block = new Request(request.getCode());
		// do not enforce CON, since NON could make sense over SMS or similar transports
		block.setType(request.getType());
		block.setDestination(request.getDestination());
		block.setDestinationPort(request.getDestinationPort());
		// copy options
		block.setOptions(new OptionSet(request.getOptions()));
		// copy message observers so that a failing blockwise request also notifies observers registered with
		// the original request
		block.addMessageObservers(request.getMessageObservers());

		int currentSize = 1 << (4 + szx);
		int from = num * currentSize;
		int to = Math.min((num + 1) * currentSize, request.getPayloadSize());
		int length = to - from;
		byte[] blockPayload = new byte[length];
		System.arraycopy(request.getPayload(), from, blockPayload, 0, length);
		block.setPayload(blockPayload);

		boolean m = (to < request.getPayloadSize());
		block.getOptions().setBlock1(szx, m, num);

		status.setComplete(!m);
		return block;
	}

	private static Response getNextResponseBlock(final Response response, final BlockwiseStatus status) {

		Response block;
		int szx = status.getCurrentSzx();
		int num = status.getCurrentNum();

		if (response.getOptions().hasObserve()) {
			// a blockwise notification transmits the first block only
			block = response;
		} else {
			block = new Response(response.getCode());
			block.setDestination(response.getDestination());
			block.setDestinationPort(response.getDestinationPort());
			block.setOptions(new OptionSet(response.getOptions()));

			block.addMessageObserver(new TimeoutForwarder(response));
		}

		int payloadsize = response.getPayloadSize();
		int currentSize = 1 << (4 + szx);
		int from = num * currentSize;

		if (0 < payloadsize && from < payloadsize) {
			int to = Math.min((num + 1) * currentSize, response.getPayloadSize());
			int length = to - from;
			byte[] blockPayload = new byte[length];
			boolean m = (to < response.getPayloadSize());
			block.getOptions().setBlock2(szx, m, num);

			// crop payload -- do after calculation of m in case block==response
			System.arraycopy(response.getPayload(), from, blockPayload, 0, length);
			block.setPayload(blockPayload);

			// do not complete notifications
			block.setLast(!m && !response.getOptions().hasObserve());

			status.setComplete(!m);
		} else {
			block.getOptions().setBlock2(szx, false, num);
			block.setLast(true);
			status.setComplete(true);
		}
		return block;
	}

	private static void assembleMessage(final BlockwiseStatus status, final Message message) {
		// The assembled request will contain the options of the first block
		message.setSource(status.getFirst().getSource());
		message.setSourcePort(status.getFirst().getSourcePort());
		message.setType(status.getFirst().getType());
		message.setMID(status.getFirst().getMID());
		message.setToken(status.getFirst().getToken());
		message.setOptions(new OptionSet(status.getFirst().getOptions()));
		message.setPayload(status.getBody());
	}

	private boolean requiresBlockwise(final Request request) {
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

	private boolean requiresBlockwise(final Exchange exchange, final Response response) {
		boolean blockwiseRequired = response.getPayloadSize() > maxMessageSize || exchange.getResponseBlockStatus() != null;
		if (blockwiseRequired) {
			LOGGER.log(Level.FINE, "response body [{0}/{1}] requires blockwise transfer",
					new Object[]{response.getPayloadSize(), maxMessageSize});
		}
		return blockwiseRequired;
	}

	private boolean isTransparentBlockwiseHandlingEnabled() {
		return maxResourceBodySize > 0;
	}

	private boolean responseExceedsMaxBodySize(final Response response) {
		return response.getOptions().hasSize2() && response.getOptions().getSize2() > maxResourceBodySize;
	}

	private boolean requestExceedsMaxBodySize(final Request request) {
		return request.getOptions().hasSize1() && request.getOptions().getSize1() > maxResourceBodySize;
	}

	/*
	 * Encodes a block size into a 3-bit SZX value as specified by
	 * draft-ietf-core-block-14, Section-2.2:
	 * 
	 * 16 bytes = 2^4 --> 0
	 * ... 
	 * 1024 bytes = 2^10 -> 6
	 */
	static int computeSZX(final int blockSize) {
		if (blockSize > 1024) {
			return 6;
		} else if (blockSize <= 16) {
			return 0;
		} else {
			int maxOneBit = Integer.highestOneBit(blockSize);
			return Integer.numberOfTrailingZeros(maxOneBit) - 4;
		}
	}

	static int getSizeForSzx(final int szx) {
		if (szx <= 0) {
			return 16;
		} else if (szx >= 6) {
			return 1024;
		} else {
			return 1 << (szx + 4);
		}
	}

	/**
	 * Schedules a clean-up task. Use the BLOCKWISE_STATUS_LIFETIME config
	 * property to set the timeout.
	 * 
	 * @param exchange
	 *            the exchange
	 */
	protected void prepareBlockCleanup(final Exchange exchange) {

		// prevent RejectedExecutionException
		if (executor.isShutdown()) {
			LOGGER.info("Endpoint is being destroyed: skipping block clean-up");
			return;
		}

		BlockCleanupTask task = new BlockCleanupTask(exchange);

		ScheduledFuture<?> f = executor.schedule(task , blockTimeout, TimeUnit.MILLISECONDS);
		exchange.setBlockCleanupHandle(f);
	}

	protected class BlockCleanupTask implements Runnable {

		private final Exchange exchange;

		public BlockCleanupTask(final Exchange exchange) {
			this.exchange = exchange;
		}

		@Override
		public void run() {
			if (!exchange.isComplete()) {
				if (exchange.getRequest() == null) {
					LOGGER.log(Level.INFO, "Block1 transfer timed out: {0}", exchange.getCurrentRequest());
				} else {
					LOGGER.log(Level.INFO, "Block2 transfer timed out: {0}", exchange.getRequest());
				}
				exchange.setComplete();
			}
		}
	}

	/*
	 * When a timeout occurs for a block it has to be forwarded to the origin response.
	 */
	public static class TimeoutForwarder extends MessageObserverAdapter {

		private final Message message;

		public TimeoutForwarder(final Message message) {
			this.message = message;
		}

		@Override
		public void onTimeout() {
			message.setTimedOut(true);
		}
	}
}
