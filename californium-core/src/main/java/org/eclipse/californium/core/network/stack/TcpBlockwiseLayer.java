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
 * Blockwise layer for TCP. Extended mainly for BERT option. Capable of handling
 * incoming blocks with SZX = 7.
 * 
 *
 */
public class TcpBlockwiseLayer extends BlockwiseLayer {

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
	 * @param config
	 *            The configuration values to use.
	 */
	public TcpBlockwiseLayer(final NetworkConfig config) {
		super(config);
		bertStepSize = config.getInt(NetworkConfig.Keys.TCP_NUMBER_OF_BULK_BLOCKS, 1);
		if (bertStepSize > 1) {
			// When BERT option is enabled each block is of size 1024.
			preferredBlockSize = BERT_INT_BLOCK_SIZE * bertStepSize;
			// When BERT option is enabled the maxMessageSize is set to the
			// value of szx = 6.i.e 1024.
			maxMessageSize = 1024;
		}
	}

	protected void startBlockwiseUpload(final Exchange exchange, final Request request) {

		BlockwiseStatus status = findRequestBlockStatus(exchange, request);
		final Request block;
		if (status.getCurrentSzx() == BERT_SZX) {
			// BERT option
			block = getNextBertRequestBlock(request, status, preferredBlockSize);
		} else {
			block = getNextRequestBlock(request, status);
		}
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
			// The response has already been generated and the client just wants
			// its next block

			BlockOption block2 = request.getOptions().getBlock2();
			Response response = exchange.getResponse();
			BlockwiseStatus status = findResponseBlockStatus(exchange, response);
			status.setCurrentNum(block2.getNum());
			status.setCurrentSzx(block2.getSzx());
			Response block;
			if (status.getCurrentSzx() == BERT_SZX) {
				// BERT option.
				block = getNextBertResponseBlock(response, status, preferredBlockSize);
			} else {
				block = getNextResponseBlock(response, status);
			}
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

	protected void handleInboundBlockwiseUpload(final BlockOption block1, final Exchange exchange,
			final Request request) {

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

					if (status.getCurrentSzx() == BERT_SZX) {
						// For BERT option.
						status.setCurrentNum(status.getCurrentNum() + (request.getPayloadSize() / BERT_INT_BLOCK_SIZE));
					} else {
						status.setCurrentNum(status.getCurrentNum() + 1);
					}
					if (block1.isM()) {
						LOGGER.finest("There are more blocks to come. Acknowledge this block.");

						Response piggybacked = Response.createResponse(request, ResponseCode.CONTINUE);
						piggybacked.getOptions().setBlock1(block1.getSzx(), true, block1.getNum());
						piggybacked.setLast(false);

						exchange.setCurrentResponse(piggybacked);
						lower().sendResponse(exchange, piggybacked);

						// do not assemble and deliver the request yet

					} else {
						LOGGER.finer("This was the last block. Deliver request");

						// Remember block to acknowledge. TODO: We might make
						// this a boolean flag in status.
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
						new Object[] { status.getCurrentNum(), block1.getNum() });
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
			Response block;
			if (status.getCurrentSzx() == BERT_SZX) {
				// For BERT option
				block = getNextBertResponseBlock(response, status, preferredBlockSize);
			} else {
				block = getNextResponseBlock(response, status);
			}
			// indicate overall body size to peer
			block.getOptions().setSize2(bodySize);

			if (block1 != null) { // in case we still have to ack the last
									// block1
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

	protected void sendNextBlock(final Exchange exchange, final Response response, final BlockOption block1,
			final BlockwiseStatus requestStatus) {

		if (requestStatus.getCurrentSzx() <= 6) {
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
		} else if (requestStatus.getCurrentSzx() == BERT_SZX) {
			// handling BERT option. This is only used when the connector is
			// either TCP or Websocket.

			int nextNum = (preferredBlockSize / BERT_INT_BLOCK_SIZE) + requestStatus.getCurrentNum();
			requestStatus.setCurrentNum(nextNum);
			requestStatus.setCurrentSzx(BERT_SZX);

			Request nextBlock = getNextBertRequestBlock(exchange.getRequest(), requestStatus, preferredBlockSize);

			// indicate overall body size to peer
			nextBlock.getOptions().setSize1(exchange.getRequest().getPayloadSize());

			// we use the same token to ease traceability
			nextBlock.setToken(response.getToken());

			exchange.setCurrentRequest(nextBlock);
			lower().sendRequest(exchange, nextBlock);

		}
	}

	/**
	 * Sends request for the next response block.
	 */
	protected void requestNextBlock(final Exchange exchange, final Response response, final BlockwiseStatus status) {
		Request request = exchange.getRequest();
		BlockOption block2 = response.getOptions().getBlock2();
		int szx = status.getCurrentSzx();
		int num = 0;
		if (szx == BERT_SZX) {
			// For BERT Option.
			num = block2.getNum() + (response.getPayloadSize() / BERT_INT_BLOCK_SIZE);
		} else {
			num = block2.getNum() + 1;
		}
		boolean m = false;

		LOGGER.log(Level.FINER, "Requesting next Block2 num={0}", num);

		Request block = new Request(request.getCode());
		// do not enforce CON, since NON could make sense over SMS or similar
		// transports
		block.setType(request.getType());
		block.setDestination(request.getDestination());
		block.setDestinationPort(request.getDestinationPort());

		/*
		 * WARNING:
		 * 
		 * For Observe, the Matcher then will store the same exchange under a
		 * different KeyToken in exchangesByToken, which is cleaned up in the
		 * else case below.
		 */
		if (!response.getOptions().hasObserve())
			block.setToken(response.getToken());

		// copy options
		block.setOptions(new OptionSet(request.getOptions()));
		// make sure NOT to use Observe for block retrieval
		block.getOptions().removeObserve();

		block.getOptions().setBlock2(szx, m, num);

		// copy message observers from original request so that they will be
		// notified
		// if something goes wrong with this blockwise request, e.g. if it times
		// out
		block.addMessageObservers(request.getMessageObservers());

		status.setCurrentNum(num);

		exchange.setCurrentRequest(block);
		lower().sendRequest(exchange, block);
	}

	/////////// HELPER METHODS //////////

	/**
	 * Returns the next BERT Request block.
	 * 
	 * @param request
	 * @param status
	 * @param bertSize
	 *            - size of the BERT block.
	 * @return BERT block
	 */
	private static Request getNextBertRequestBlock(final Request request, final BlockwiseStatus status, int bertSize) {
		int num = status.getCurrentNum();
		int szx = BERT_SZX;
		Request block = new Request(request.getCode());
		// do not enforce CON, since NON could make sense over SMS or similar
		// transports
		block.setType(request.getType());
		block.setDestination(request.getDestination());
		block.setDestinationPort(request.getDestinationPort());
		// copy options
		block.setOptions(new OptionSet(request.getOptions()));
		// copy message observers so that a failing blockwise request also
		// notifies observers registered with
		// the original request
		block.addMessageObservers(request.getMessageObservers());
		int from = num * BERT_INT_BLOCK_SIZE;
		int to = Math.min(from + bertSize, request.getPayloadSize());
		int length = to - from;
		byte[] blockPayload = new byte[length];
		System.arraycopy(request.getPayload(), from, blockPayload, 0, length);
		block.setPayload(blockPayload);

		boolean m = (to < request.getPayloadSize());
		block.getOptions().setBlock1(szx, m, num);

		status.setComplete(!m);
		return block;
	}

	/**
	 * Returns the next BERT Response block.
	 * 
	 * @param response
	 * @param status
	 * @param bertsize
	 * @return next BERT block.
	 */
	private static Response getNextBertResponseBlock(final Response response, final BlockwiseStatus status,
			int bertsize) {

		Response block;
		int szx = BERT_SZX;
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
		int from = num * BERT_INT_BLOCK_SIZE;
		if (0 < payloadsize && from < payloadsize) {
			int to = Math.min(from + bertsize, response.getPayloadSize());
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

	/*
	 * Encodes a block size into a 3-bit SZX value as specified by
	 * draft-ietf-core-block-14, Section-2.2:
	 * 
	 * 16 bytes = 2^4 --> 0 ... 1024 bytes = 2^10 -> 6
	 */
	protected int computeSZX(final int blockSize) {
		if (blockSize > BERT_INT_BLOCK_SIZE) {
			return BERT_SZX;
		} else if (blockSize <= 16) {
			return 0;
		} else {
			int maxOneBit = Integer.highestOneBit(blockSize);
			return Integer.numberOfTrailingZeros(maxOneBit) - 4;
		}
	}

	protected int getSizeForSzx(final int szx) {
		if (szx <= 0) {
			return 16;
		} else if (szx == BERT_SZX) {
			return preferredBlockSize;
		} else if (szx >= 6) {
			return BERT_INT_BLOCK_SIZE;
		} else {
			return 1 << (szx + 4);
		}
	}
}
