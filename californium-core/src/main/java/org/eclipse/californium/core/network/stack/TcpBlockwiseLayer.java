/*******************************************************************************
 * Copyright (c) 2017 Pratheek Rai and others.
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
 *    Pratheek Rai - initial creation
 ******************************************************************************/

package org.eclipse.californium.core.network.stack;

import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;

/**
 * Blockwise layer for TCP. Extended mainly for BERT option. Capable of handling
 * incoming blocks with SZX = 7.
 * 
 * @author Pratheek Rai.
 *
 */
public class TcpBlockwiseLayer extends BlockwiseLayer {

	/**
	 * logger.
	 */
	private static final Logger LOGGER = Logger.getLogger(TcpBlockwiseLayer.class.getName());

	/**
	 * BERT SZX constant.
	 */
	private final static int BERT_SZX = 7;
	
	/**
	 * Internal block size for BERT. i.e internally BERT is handled similar to
	 * SZX = 6.
	 */
	private final static int BERT_INT_BLOCK_SIZE = 1024;

	/**
	 * The number of 1024 Bytes packets to be sent as a block. Size of 1 BERT
	 * block = bertStepSize * 1024 Bytes
	 */
	private int bertStepSize;

	/**
	 * Flag for BERT option.This flag is only for sending messages with BERT.
	 * This class can handle incoming BERT messages irrespective of this flag.
	 */
	private boolean isBertEnabled;

	/**
	 * Constructor 
	 * @param config - network configuration.
	 */
	public TcpBlockwiseLayer(NetworkConfig config) {
		super(config);
		bertStepSize = config.getInt(Keys.TCP_NUMBER_OF_BULK_BLOCKS, 1);
		if (bertStepSize > 1) {
			isBertEnabled = true;
		}
	}

	/**
	 * Handles inbound blockwise upload from peer. Handling is done here only
	 * for SZX = 7 all other handling is done in the BlockwikseLayer.
	 */
	protected void handleInboundBlockwiseUpload(final Exchange exchange, final Request request) {

		if (requestExceedsMaxBodySize(request)) {
			// allow super class to handle this error.
			super.handleInboundBlockwiseUpload(exchange, request);
		} else {

			BlockOption block1 = request.getOptions().getBlock1();

			if ((block1 != null) && (block1.getSzx() == BERT_SZX)) {
				KeyUri key = getKey(exchange, request);
				Block1BlockwiseStatus status = getInboundBlock1Status(key, exchange, request);
				
				if (block1.getNum() == 0 && status.getCurrentNum() > 0) {
					status = resetInboundBlock1Status(key, exchange, request);
				}

				if (block1.getNum() != status.getCurrentNum()) {
					// ERROR, wrong number, Incomplete
					LOGGER.log(Level.WARNING,
							"peer sent wrong block, expected no. {0} but got {1}. Responding with 4.08 (Request Entity Incomplete)",
							new Object[] { status.getCurrentNum(), block1.getNum() });

					sendBlock1ErrorResponse(key, exchange, request, ResponseCode.REQUEST_ENTITY_INCOMPLETE,
							"wrong block number");

				} else if (!status.hasContentFormat(request.getOptions().getContentFormat())) {

					sendBlock1ErrorResponse(key, exchange, request, ResponseCode.REQUEST_ENTITY_INCOMPLETE,
							"unexpected Content-Format");

				} else if (!status.addBlock(request.getPayload())) {
					sendBlock1ErrorResponse(key, exchange, request, ResponseCode.REQUEST_ENTITY_TOO_LARGE,
							"body exceeded expected size " + status.getBufferSize());
				}

				status.setCurrentNum(status.getCurrentNum() + (request.getPayloadSize() / BERT_INT_BLOCK_SIZE));
				if (block1.isM()) {

					// Message has more blocks.

					LOGGER.log(Level.FINE, "acknowledging incoming block1 [num={0}], expecting more blocks to come",
							block1.getNum());

					Response piggybacked = Response.createResponse(request, ResponseCode.CONTINUE);
					piggybacked.getOptions().setBlock1(block1.getSzx(), true, block1.getNum());
					piggybacked.setLast(false);

					exchange.setCurrentResponse(piggybacked);
					lower().sendResponse(exchange, piggybacked);

				} else {

					LOGGER.log(Level.FINE,
							"peer has sent last block1 [num={0}], delivering request to application layer",
							block1.getNum());

					// Remember block to acknowledge. TODO: We might make
					// this a
					// boolean flag in status.
					exchange.setBlock1ToAck(block1);

					// Assemble and deliver
					Request assembled = new Request(request.getCode());
					assembled.setSenderIdentity(request.getSenderIdentity());
					status.assembleMessage(assembled);

					assembled.setMID(request.getMID());
					assembled.setToken(request.getToken());

					assembled.getOptions().setBlock2(request.getOptions().getBlock2());

					clearBlock1Status(key);

					exchange.setRequest(assembled);
					upper().receiveRequest(exchange, assembled);
				}
			} else {
				super.handleInboundBlockwiseUpload(exchange, request);
			}
		}

	}

	/**
	 * Handles the request for next block from the peer. Handling is done here
	 * only for SZX = 7 all other handling is done in the BlockwikseLayer.
	 */
	protected void handleInboundRequestForNextBlock(final Exchange exchange, final Request request, final KeyUri key,
			final Block2BlockwiseStatus status) {

		BlockOption block2 = request.getOptions().getBlock2();
		if ((block2 != null) && (block2.getSzx() == BERT_SZX)) {

			synchronized (status) {

				ByteBuffer responseBlockBuilder = ByteBuffer.allocate(bertStepSize * BERT_INT_BLOCK_SIZE);
				int blockNum = block2.getNum();
				int currentNum = blockNum;
				boolean hasNextBlock = true;
				Response block = null;

				for (int i = 0; ((i < bertStepSize) && (hasNextBlock)); i++) {
					block = status.getNextResponseBlock(block2);
					hasNextBlock = block.getOptions().getBlock2().isM();
					currentNum = currentNum + 1;
					block2 = new BlockOption(BERT_SZX, hasNextBlock, currentNum);
					responseBlockBuilder.put(block.getPayload());
				}

				if (status.isComplete()) {
					// clean up blockwise status
					LOGGER.log(Level.FINE, "peer has requested last block of blockwise transfer: {0}", status);
					clearBlock2Status(key);
				} else {
					LOGGER.log(Level.FINE, "peer has requested intermediary block of blockwise transfer: {0}", status);
				}

				block.setPayload(getBody(responseBlockBuilder));
				boolean m = block.getOptions().getBlock2().isM();
				block.getOptions().setBlock2(BERT_SZX, m, blockNum);
				exchange.setCurrentResponse(block);
				lower().sendResponse(exchange, block);
			}
		} else {
			super.handleInboundRequestForNextBlock(exchange, request, key, status);
		}
	}

	/**
	 * Send request to peers.Handling is done here only when BERT option is
	 * enabled otherwise handling is done in the BlockwikseLayer.
	 */
	public void sendRequest(final Exchange exchange, final Request request) {

		Request requestToSend = request;
		if (isBertEnabled) {
			if (isTransparentBlockwiseHandlingEnabled()) {

				BlockOption block2 = request.getOptions().getBlock2();
				if (block2 != null && block2.getNum() > 0) {
					// This is the case if the user has explicitly added a block
					// option
					// for random access.
					// Note: We do not regard it as random access when the block
					// number is 0.
					// This is because the user might just want to do early
					// block
					// size negotiation but actually want to retrieve the whole
					// body by means of
					// a transparent blockwise transfer.
					LOGGER.fine("outbound request contains block2 option, creating random-access blockwise status");
					addRandomAccessBlock2Status(exchange, request);
					handleRandomBlockAccess(exchange, request, block2.getNum());
				} else if (requiresBlockwise(request)) {
					// This must be a large POST or PUT request with BERT
					// option.
					ByteBuffer requestBuilder = ByteBuffer.allocate(bertStepSize * BERT_INT_BLOCK_SIZE);
					boolean hasNextBlock = true;
					KeyUri key = getKey(exchange, request);
					Request firstRequest = startBlockwiseUpload(exchange, request);
					requestBuilder.put(firstRequest.getPayload());

					Block1BlockwiseStatus status = getBlock1Status(key);
					for (int i = 1; ((i < bertStepSize) && (hasNextBlock)); i++) {
						status.setCurrentNum(i);
						requestToSend = status.getNextRequestBlock();
						requestBuilder.put(requestToSend.getPayload());
						hasNextBlock = requestToSend.getOptions().getBlock1().isM();
					}
					firstRequest.setPayload(getBody(requestBuilder));
					firstRequest.getOptions().setBlock1(BERT_SZX, hasNextBlock, 0);
					exchange.setCurrentRequest(firstRequest);
					lower().sendRequest(exchange, firstRequest);
				} else {
					exchange.setCurrentRequest(requestToSend);
					lower().sendRequest(exchange, requestToSend);
				}
			} else {
				exchange.setCurrentRequest(requestToSend);
				lower().sendRequest(exchange, requestToSend);
			}
		} else {
			super.sendRequest(exchange, requestToSend);
		}
	}

	

	/**
	 * Send response to peers. Handling is done here only when BERT option is
	 * enabled otherwise handling is done in the BlockwikseLayer.
	 */
	public void sendResponse(final Exchange exchange, final Response response) {
		Response responseToSend = response;
		if (isBertEnabled) {
			if (isTransparentBlockwiseHandlingEnabled()) {
				Response firstResponse = response;
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
						// crop the response down to the requested block.
						BlockOption nextBlockOption = requestBlock2;
						boolean hasNextBlock = true;
						ByteBuffer responseBuilder = ByteBuffer.allocate(bertStepSize * BERT_INT_BLOCK_SIZE);
						for (int i = 0; ((i < bertStepSize) && (hasNextBlock)); i++) {
							Response nextBlock = responseToSend;
							Block2BlockwiseStatus.crop(nextBlock, nextBlockOption);
							responseBuilder.put(nextBlock.getPayload());
							hasNextBlock = nextBlock.getOptions().getBlock1().isM();
							nextBlockOption = new BlockOption(nextBlockOption.getSzx(), hasNextBlock,
									(nextBlockOption.getNum() + 1));
						}
						responseToSend.setPayload(getBody(responseBuilder));
						responseToSend.getOptions().setBlock2(BERT_SZX, responseToSend.getOptions().getBlock2().isM(),
								requestBlock2.getNum());
					} else {

						// peer has requested a non existing block
						responseToSend = Response.createResponse(exchange.getRequest(), ResponseCode.BAD_OPTION);
						responseToSend.setType(response.getType());
						responseToSend.setMID(response.getMID());
						responseToSend.getOptions().setBlock2(requestBlock2);

					}

				} else if (requiresBlockwise(exchange, response, requestBlock2)) {

					// the client either has not included a block2 option at all
					// or
					// has
					// included a block2 option with num = 0 (early negotiation
					// of
					// block size)

					KeyUri key = getKey(exchange, response);
					Block2BlockwiseStatus status = getOutboundBlock2Status(key, exchange, response);
					BlockOption block2 = requestBlock2 != null ? requestBlock2 : new BlockOption(BERT_SZX, false, 0);
					firstResponse = status.getNextResponseBlock(block2);
					boolean hasNextBlock = true;
					ByteBuffer responseBuilder = ByteBuffer.allocate(bertStepSize * BERT_INT_BLOCK_SIZE);
					responseBuilder.put(firstResponse.getPayload());

					for (int i = 1; ((i < bertStepSize) && (hasNextBlock)); i++) {
						status.setCurrentNum(i);
						block2 = new BlockOption(BERT_SZX, false, i);
						responseToSend = status.getNextResponseBlock(block2);
						responseBuilder.put(responseToSend.getPayload());
						hasNextBlock = responseToSend.getOptions().getBlock2().isM();
					}
					firstResponse.setPayload(getBody(responseBuilder));
					firstResponse.getOptions().setBlock2(BERT_SZX, responseToSend.getOptions().getBlock2().isM(), 0);
					if (status.isComplete()) {
						// clean up blockwise status
						LOGGER.log(Level.FINE, "block2 transfer of response finished after first block: {0}", status);
						clearBlock2Status(key);
					} else {
						LOGGER.log(Level.FINE, "block2 transfer of response started: {0}", status);
						addBlock2CleanUpObserver(responseToSend, key);
					}
					responseToSend = firstResponse;
				}

				BlockOption block1 = exchange.getBlock1ToAck();
				if (block1 != null) {
					exchange.setBlock1ToAck(null);
					responseToSend.getOptions().setBlock1(block1);
				}

				exchange.setCurrentResponse(responseToSend);
				lower().sendResponse(exchange, responseToSend);

			} else {
				super.sendResponse(exchange, responseToSend);
			}
		} else {
			exchange.setCurrentResponse(responseToSend);
			lower().sendResponse(exchange, responseToSend);
		}

	}

	/**
	 * Send the next request block. Handling is done here only when BERT option
	 * is enabled otherwise handling is done in the BlockwikseLayer.
	 */
	protected void sendNextBlock(final Exchange exchange, final Response response, final KeyUri key,
			final Block1BlockwiseStatus status) {
		if (isBertEnabled) {
			int blockNum = status.getCurrentNum() + 1;
			int nextNum = blockNum;
			LOGGER.log(Level.FINE, "sending next Block1 num={0}", nextNum);

			Request nextBlock = null;
			ByteBuffer nextRequestBuilder = ByteBuffer.allocate(bertStepSize * BERT_INT_BLOCK_SIZE);

			boolean hasNextBlock = true;
			for (int i = 0; ((i < bertStepSize) && (hasNextBlock)); i++) {
				status.setCurrentNum(nextNum);
				nextBlock = status.getNextRequestBlock(nextNum, BERT_SZX);
				nextRequestBuilder.put(nextBlock.getPayload());
				hasNextBlock = nextBlock.getOptions().getBlock1().isM();
				nextNum = nextNum + 1;

			}
			nextBlock.setPayload(getBody(nextRequestBuilder));
			// we use the same token to ease traceability
			nextBlock.setToken(response.getToken());
			addBlock1CleanUpObserver(nextBlock, key);

			BlockOption blockOption1 = nextBlock.getOptions().getBlock1();
			boolean currentm = blockOption1.isM();
			nextBlock.getOptions().setBlock1(BERT_SZX, currentm, blockNum);

			exchange.setCurrentRequest(nextBlock);
			lower().sendRequest(exchange, nextBlock);

		} else {
			super.sendNextBlock(exchange, response, key, status);
		}

	}

	/**
	 * Request the next response block.Handling is done here only for SZX = 7
	 * all other handling is done in the BlockwikseLayer.
	 */
	protected void requestNextBlock(final Exchange exchange, final Response response, final KeyUri key,
			final Block2BlockwiseStatus status) {

		if (response.getOptions().getBlock2().getSzx() == BERT_SZX) {
			int blockNum = status.getCurrentNum() + (response.getPayloadSize() / BERT_INT_BLOCK_SIZE);
			Request request = exchange.getRequest();
			Request block = new Request(request.getCode());
			// do not enforce CON, since NON could make sense over SMS or
			// similar transports
			block.setType(request.getType());
			block.setDestination(request.getDestination());
			block.setDestinationPort(request.getDestinationPort());

			/*
			 * WARNING:
			 * 
			 * For Observe, the Matcher then will store the same exchange under
			 * a different KeyToken in exchangesByToken, which is cleaned up in
			 * the else case below.
			 */
			if (!response.getOptions().hasObserve()) {
				block.setToken(response.getToken());
			}

			// copy options
			block.setOptions(new OptionSet(request.getOptions()));
			block.getOptions().setBlock2(BERT_SZX, false, blockNum);
			if (response.getOptions().getETagCount() > 0) {
				// use ETag provided by peer
				block.getOptions().addETag(response.getOptions().getETags().get(0));
			}

			// make sure NOT to use Observe for block retrieval
			block.getOptions().removeObserve();

			// copy message observers from original request so that they will be
			// notified
			// if something goes wrong with this blockwise request, e.g. if it
			// times out
			block.addMessageObservers(request.getMessageObservers());
			// add an observer that cleans up the block2 transfer tracker if the
			// block request fails
			addBlock2CleanUpObserver(block, key);

			status.setCurrentNum(blockNum);

			LOGGER.log(Level.FINER, "requesting next Block2 [num={0}]: {1}", new Object[] { blockNum, block });
			exchange.setCurrentRequest(block);
			lower().sendRequest(exchange, block);

		} else {
			super.requestNextBlock(exchange, response, key, status);
		}

	}
	
	/**
	 * Handle random access of blocks while sending request.
	 * @param exchange - exchange state.
	 * @param request - request message.
	 * @param blockNum - Block number to be accessed.
	 */
	private void handleRandomBlockAccess(Exchange exchange, final Request request, final int blockNum) {

		Request requestToSend = request;
		KeyUri key = getKey(exchange, request);
		Block1BlockwiseStatus status = getBlock1Status(key);
		if (status == null) {
			// request has not been sent blockwise
			LOGGER.log(Level.FINE,
					"request is not initiated with blockwise transfer. Hence random block access is not possible",
					request);
		} else {
			ByteBuffer requestBuilder = ByteBuffer.allocate(bertStepSize * BERT_INT_BLOCK_SIZE);
			boolean hasNextBlock = true;
			int nextBlockNum = blockNum;
			for (int i = 0; ((i < bertStepSize) && (hasNextBlock)); i++) {
				status.setCurrentNum(nextBlockNum);
				Request nextBlock = status.getNextRequestBlock();
				requestBuilder.put(nextBlock.getPayload());
				hasNextBlock = nextBlock.getOptions().getBlock1().isM();
				nextBlockNum = nextBlockNum + 1;
			}
			requestToSend.setPayload(getBody(requestBuilder));
			requestToSend.getOptions().setBlock1(BERT_SZX, hasNextBlock, 0);
			exchange.setCurrentRequest(requestToSend);
			lower().sendRequest(exchange, requestToSend);
		}
	}

	/**
	 * Truncates the buffer and returns only the filled part. Call this
	 * method only when all the data is added to the buffer.
	 * 
	 * @param buf
	 * @return Returns only the filled part of the buffer.
	 */
	private byte[] getBody(ByteBuffer buf) {
		buf.flip();
		byte[] body = new byte[buf.remaining()];
		buf.get(body).clear();
		return body;
	}
}
