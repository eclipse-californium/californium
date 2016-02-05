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
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigObserverAdapter;

public class BlockwiseLayer extends AbstractLayer {

	/** The logger. */
	protected final static Logger LOGGER = Logger.getLogger(BlockwiseLayer.class.getCanonicalName());

	// TODO: Size Option. Include only in first block.
	// TODO: DoS: server should have max allowed blocks/bytes/time to allocate.
	// TODO: Random access for Cf servers: The draft still needs to specify a reaction to "overshoot"
	// TODO: Blockwise with separate response or NONs. Not yet mentioned in draft.
	// TODO: How should our client deal with a server that handles blocks non-atomic?
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
	
	private int max_message_size;
	private int preferred_block_size;
	private int block_timeout;
	private final NetworkConfigObserverAdapter observer;
	final private NetworkConfig config;

	/**
	 * Constructs a new blockwise layer.
	 * Changes to the configuration are observed and automatically applied.
	 * @param config the configuration
	 */
	public BlockwiseLayer(NetworkConfig config) {
		this.config = config;
		max_message_size = config.getInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE);
		preferred_block_size = config.getInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE);
		block_timeout = config.getInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME);
		
		LOGGER.log(Level.CONFIG,
			"BlockwiseLayer uses MAX_MESSAGE_SIZE={0}, DEFAULT_BLOCK_SIZE={1} and BLOCKWISE_STATUS_LIFETIME={2}",
			new Object[]{max_message_size, preferred_block_size, block_timeout});

		observer = new NetworkConfigObserverAdapter() {
			@Override
			public void changed(String key, int value) {
				if (NetworkConfig.Keys.MAX_MESSAGE_SIZE.equals(key))
					max_message_size = value;
				if (NetworkConfig.Keys.PREFERRED_BLOCK_SIZE.equals(key))
					preferred_block_size = value;
				if (NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME.equals(key))
					block_timeout = value;
			}
		};
		config.addConfigObserver(observer);
	}
	
	@Override
	public void sendRequest(Exchange exchange, Request request) {
		if (request.getOptions().hasBlock2() && request.getOptions().getBlock2().getNum() > 0) {
			// This is the case if the user has explicitly added a block option
			// for random access.
			// Note: We do not regard it as random access when the block num is
			// 0. This is because the user might just want to do early block
			// size negotiation but actually wants to receive all blocks.
			LOGGER.fine("Request carries explicit defined block2 option: create random access blockwise status");
			BlockwiseStatus status = new BlockwiseStatus(request.getOptions().getContentFormat());
			BlockOption block2 = request.getOptions().getBlock2();
			status.setCurrentSzx(block2.getSzx());
			status.setCurrentNum(block2.getNum());
			status.setRandomAccess(true);
			exchange.setResponseBlockStatus(status);
			super.sendRequest(exchange, request);
			
		} else if (requiresBlockwise(request)) {
			// This must be a large POST or PUT request
			LOGGER.log(Level.FINE, "Request payload {0}/{1} requires Blockwise", new Object[]{request.getPayloadSize(), max_message_size});
			BlockwiseStatus status = findRequestBlockStatus(exchange, request);
			
			Request block = getNextRequestBlock(request, status);
			
			exchange.setRequestBlockStatus(status);
			exchange.setCurrentRequest(block);
			super.sendRequest(exchange, block);
			
		} else {
			exchange.setCurrentRequest(request);
			super.sendRequest(exchange, request);
		}
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {
		if (request.getOptions().hasBlock1()) {
			// This must be a large POST or PUT request
			
			BlockOption block1 = request.getOptions().getBlock1();
			LOGGER.log(Level.FINE, "Request contains block1 option {0}", block1);
			
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
				
				if (request.getOptions().getContentFormat()==status.getContentFormat()) {
					status.addBlock(request.getPayload());
				} else {
					Response error = Response.createResponse(request, ResponseCode.REQUEST_ENTITY_INCOMPLETE);
					error.getOptions().setBlock1(block1.getSzx(), block1.isM(), block1.getNum());
					error.setPayload("Changed Content-Format");
					
					exchange.setCurrentResponse(error);
					super.sendResponse(exchange, error);
					return;
				}
				
				status.setCurrentNum(status.getCurrentNum() + 1);
				if ( block1.isM() ) {
					LOGGER.finest("There are more blocks to come. Acknowledge this block.");
					
					Response piggybacked = Response.createResponse(request, ResponseCode.CONTINUE);
					piggybacked.getOptions().setBlock1(block1.getSzx(), true, block1.getNum());
					piggybacked.setLast(false);
					
					exchange.setCurrentResponse(piggybacked);
					super.sendResponse(exchange, piggybacked);
					
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
					super.receiveRequest(exchange, assembled);
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
				
				super.sendResponse(exchange, error);
			}
			
		} else if (exchange.getResponse()!=null && request.getOptions().hasBlock2()) {
			// The response has already been generated and the client just wants its next block
			
			BlockOption block2 = request.getOptions().getBlock2();
			Response response = exchange.getResponse();
			BlockwiseStatus status = findResponseBlockStatus(exchange, response);
			status.setCurrentNum(block2.getNum());
			status.setCurrentSzx(block2.getSzx());
			
			Response block = getNextResponseBlock(response, status);
			
			if (status.isComplete()) {
				// clean up blockwise status
				LOGGER.log(Level.FINE, "Ongoing is complete {0}", status);
				exchange.setResponseBlockStatus(null);
				exchange.setBlockCleanupHandle(null);
			} else {
				LOGGER.log(Level.FINE, "Ongoing is continuing {0}", status);
			}
			
			exchange.setCurrentResponse(block);
			super.sendResponse(exchange, block);
			
		} else {
			earlyBlock2Negotiation(exchange, request);

			exchange.setRequest(request);
			super.receiveRequest(exchange, request);
		}
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {
		BlockOption block1 = exchange.getBlock1ToAck();
		if (block1 != null)
			exchange.setBlock1ToAck(null);
		
		if (requireBlockwise(exchange, response)) {
			LOGGER.log(Level.FINE, "Response payload {0}/{1} requires Blockwise", new Object[]{response.getPayloadSize(), max_message_size});
			
			BlockwiseStatus status = findResponseBlockStatus(exchange, response);
			
			Response block = getNextResponseBlock(response, status);
			
			if (block1 != null) // in case we still have to ack the last block1
				block.getOptions().setBlock1(block1);
			
			if (status.isComplete()) {
				// clean up blockwise status
				LOGGER.log(Level.FINE, "Ongoing finished on first block {0}", status);
				exchange.setResponseBlockStatus(null);
				exchange.setBlockCleanupHandle(null);
			} else {
				LOGGER.log(Level.FINE, "Ongoing started {0}", status);
			}
			
			exchange.setCurrentResponse(block);
			super.sendResponse(exchange, block);
			
		} else {
			if (block1 != null) response.getOptions().setBlock1(block1);
			exchange.setCurrentResponse(response);
			// Block1 transfer completed
			exchange.setBlockCleanupHandle(null);
			super.sendResponse(exchange, response);
		}
	}
	
	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		
		// do not continue fetching blocks if canceled
		if (exchange.getRequest().isCanceled()) {
			// reject (in particular for Block+Observe)
			if (response.getType()!=Type.ACK) {
				LOGGER.finer("Rejecting blockwise transfer for canceled Exchange");
				EmptyMessage rst = EmptyMessage.newRST(response);
				sendEmptyMessage(exchange, rst);
				// Matcher sets exchange as complete when RST is sent
			}
			return;
		}
		
		if (!response.getOptions().hasBlock1() && !response.getOptions().hasBlock2()) {
			// There is no block1 or block2 option, therefore it is a normal response
			exchange.setResponse(response);
			super.receiveResponse(exchange, response);
			return;
		}
		
		if (response.getOptions().hasBlock1()) {
			// TODO: What if request has not been sent blockwise (server error)
			BlockOption block1 = response.getOptions().getBlock1();
			LOGGER.log(Level.FINER, "Response acknowledges block {0}", block1);
			
			BlockwiseStatus status = exchange.getRequestBlockStatus();
			if (!status.isComplete()) {
				// TODO: the response code should be CONTINUE. Otherwise deliver random access response.
				// Send next block
				int currentSize = 1 << (4 + status.getCurrentSzx());
				int nextNum = status.getCurrentNum() + currentSize / block1.getSize();
				LOGGER.log(Level.FINER, "Sending next Block1 num={0}", nextNum);
				status.setCurrentNum(nextNum);
				status.setCurrentSzx(block1.getSzx());
				Request nextBlock = getNextRequestBlock(exchange.getRequest(), status);
				// we use the same token to ease traceability
				nextBlock.setToken(response.getToken());
				
				exchange.setCurrentRequest(nextBlock);
				super.sendRequest(exchange, nextBlock);
				// do not deliver response
				
			} else if (!response.getOptions().hasBlock2()) {
				// All request block have been acknowledged and we receive a piggy-backed
				// response that needs no blockwise transfer. Thus, deliver it.
				super.receiveResponse(exchange, response);
			} else {
				LOGGER.finer("Block1 followed by Block2 transfer");
			}
		}
		
		if (response.getOptions().hasBlock2()) {
			
			BlockOption block2 = response.getOptions().getBlock2();
			BlockwiseStatus status = findResponseBlockStatus(exchange, response);
			
			// a new notification might arrive during a blockwise transfer
			if (response.getOptions().hasObserve() && block2.getNum()==0 && status.getCurrentNum()!=0) {
				
				if (response.getOptions().getObserve()>status.getObserve()) {
					// log a warning, since this might cause a loop where no notification is ever assembled (when the server sends notifications faster than the blocks can be transmitted)
					LOGGER.log(Level.WARNING, "Ongoing blockwise transfer reseted at num={0} by new notification: {1}", new Object[]{status.getCurrentNum(), response});
					// reset current status
					exchange.setResponseBlockStatus(null);
					// and create new status for fresher notification
					status = findResponseBlockStatus(exchange, response);
				} else {
					LOGGER.log(Level.INFO, "Ignoring old notification during ongoing blockwise transfer: {0}", response);
					return;
				}
			}
			
			// check token to avoid mixed blockwise transfers (possible with observe) 
			if (block2.getNum() == status.getCurrentNum() && (block2.getNum()==0 || Arrays.equals(response.getToken(), exchange.getCurrentRequest().getToken()))) {
				
				// We got the block we expected :-)
				status.addBlock(response.getPayload());
				
				// store the observe sequence number to set it in the assembled response
				if (response.getOptions().hasObserve()) {
					status.setObserve(response.getOptions().getObserve());
				}
				
				if (status.isRandomAccess()) {
					// The client has requested this specifc block and we deliver it
					exchange.setResponse(response);
					super.receiveResponse(exchange, response);
				
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
					
					status.setCurrentNum(num);
					
					exchange.setCurrentRequest(block);
					super.sendRequest(exchange, block);
					
				} else {
					LOGGER.log(Level.FINER, "We have received all {0} blocks of the response. Assemble and deliver", status.getBlockCount());
					Response assembled = new Response(response.getCode());
					
					assembleMessage(status, assembled);
					
					// set overall transfer RTT
					assembled.setRTT(System.currentTimeMillis() - exchange.getTimestamp());
					
					// Check if this response is a notification
					int observe = status.getObserve();
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
					exchange.setResponse(assembled);
					super.receiveResponse(exchange, assembled);
				}
				
			} else {
				// ERROR, wrong block number (server error)
				// TODO: This scenario is not specified in the draft.
				// Canceling the request would interfere with Observe, so just ignore it
				LOGGER.log(Level.WARNING,
						"Wrong block number. Expected {0} but received {1}: {2}",
						new Object[]{status.getCurrentNum(), block2.getNum(), response});
				if (response.getType()==Type.CON) {
					EmptyMessage rst = EmptyMessage.newRST(response);
					super.sendEmptyMessage(exchange, rst);
				}
			}
		}
	}
	
	/////////// HELPER METHODS //////////
	
	private void earlyBlock2Negotiation(Exchange exchange, Request request) {
		// Call this method when a request has completely arrived (might have
		// been sent in one piece without blockwise).
		if (request.getOptions().hasBlock2()) {
			BlockOption block2 = request.getOptions().getBlock2();
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
	private BlockwiseStatus findRequestBlockStatus(Exchange exchange, Request request) {
		BlockwiseStatus status = exchange.getRequestBlockStatus();
		if (status == null) {
			status = new BlockwiseStatus(request.getOptions().getContentFormat());
			status.setFirst(request);
			status.setCurrentSzx( computeSZX(preferred_block_size) );
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
	private BlockwiseStatus findResponseBlockStatus(Exchange exchange, Response response) {
		BlockwiseStatus status = exchange.getResponseBlockStatus();
		if (status == null) {
			status = new BlockwiseStatus(response.getOptions().getContentFormat());
			status.setCurrentSzx( computeSZX(preferred_block_size) );
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
	
	private Request getNextRequestBlock(Request request, BlockwiseStatus status) {
		int num = status.getCurrentNum();
		int szx = status.getCurrentSzx();
		Request block = new Request(request.getCode());
		// do not enforce CON, since NON could make sense over SMS or similar transports
		block.setType(request.getType());
		block.setDestination(request.getDestination());
		block.setDestinationPort(request.getDestinationPort());
		// copy options
		block.setOptions(new OptionSet(request.getOptions()));
		
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
	
	private Response getNextResponseBlock(Response response, BlockwiseStatus status) {
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
	
	private void assembleMessage(BlockwiseStatus status, Message message) {
		// The assembled request will contain the options of the first block
		message.setSource(status.getFirst().getSource());
		message.setSourcePort(status.getFirst().getSourcePort());
		message.setType(status.getFirst().getType());
		message.setMID(status.getFirst().getMID());
		message.setToken(status.getFirst().getToken());
		message.setOptions(new OptionSet(status.getFirst().getOptions()));
		
		int length = 0;
		for (byte[] block:status.getBlocks())
			length += block.length;
		
		byte[] payload = new byte[length];
		int offset = 0;
		for (byte[] block:status.getBlocks()) {
			System.arraycopy(block, 0, payload, offset, block.length);
			offset += block.length;
		}
		
		message.setPayload(payload);
	}
	
	private boolean requiresBlockwise(Request request) {
		if (request.getCode() == Code.PUT || request.getCode() == Code.POST) {
			return request.getPayloadSize() > max_message_size;
		} else return false;
	}
	
	private boolean requireBlockwise(Exchange exchange, Response response) {
		return response.getPayloadSize() > max_message_size
				|| exchange.getResponseBlockStatus() != null;
	}
	
	/*
	 * Encodes a block size into a 3-bit SZX value as specified by
	 * draft-ietf-core-block-14, Section-2.2:
	 * 
	 * 16 bytes = 2^4 --> 0
	 * ... 
	 * 1024 bytes = 2^10 -> 6
	 */
	private int computeSZX(int blockSize) {
		return (int)(Math.log(blockSize)/Math.log(2)) - 4;
	}
	

	/**
	 * Schedules a clean-up task. Use the BLOCKWISE_STATUS_LIFETIME config
	 * property to set the timeout.
	 * 
	 * @param exchange
	 *            the exchange
	 */
	protected void prepareBlockCleanup(Exchange exchange) {
		
		// prevent RejectedExecutionException
		if (executor.isShutdown()) {
			LOGGER.info("Endpoint is being destroyed: skipping block clean-up");
			return;
		}
		
		BlockCleanupTask task = new BlockCleanupTask(exchange);
		
		ScheduledFuture<?> f = executor.schedule(task , block_timeout, TimeUnit.MILLISECONDS);
		exchange.setBlockCleanupHandle(f);
	}
	
	protected class BlockCleanupTask implements Runnable {
		
		private Exchange exchange;
		
		public BlockCleanupTask(Exchange exchange) {
			this.exchange = exchange;
		}
		
		@Override
		public void run() {
			if (exchange.getRequest()==null) {
				LOGGER.log(Level.INFO, "Block1 transfer timed out: {0}", exchange.getCurrentRequest());
			} else {
				LOGGER.log(Level.INFO, "Block2 transfer timed out: {1}", exchange.getRequest());
			}
			exchange.setComplete();
		}
	}

	@Override
	public void destroy() {
		config.removeConfigObserver(observer);
	}

	/*
	 * When a timeout occurs for a block it has to be forwarded to the origin response.
	 */
	public static class TimeoutForwarder extends MessageObserverAdapter {
		
		private Message message;
		
		public TimeoutForwarder(Message message) {
			this.message = message;
		}
		
		@Override
		public void onTimeout() {
			message.setTimedOut(true);
		}
	}
}
