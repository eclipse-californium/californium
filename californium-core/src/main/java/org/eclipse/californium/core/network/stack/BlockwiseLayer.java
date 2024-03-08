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
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides transparent handling of the blockwise transfer of a large
 * <em>resource body</em>.
 * <p>
 * There are four cases in which such <em>transparent</em> blockwise transfers
 * occur:
 * <ul>
 * <li>An outbound request carrying a large body that is too large to be sent in
 * the payload of a single message, is transparently replaced by a sequence of
 * requests transferring individual blocks of the body to the server.</li>
 * <li>An outbound response carrying a large body that is too large to be sent
 * in the payload of a single message, is transparently replaced by a response
 * containing only the first block of the body. The body will be
 * <em>buffered</em> in-memory so that the peer can retrieve the whole body
 * using multiple requests for individual blocks.</li>
 * <li>When an inbound request containing a single block of a large body is
 * received, the payload will be buffered and acknowledged so that the peer can
 * send the rest of the body using a blockwise transfer. Once all blocks have
 * been received, the overall body is re-assembled and forwarded to the
 * {@code Resource} handling the request.</li>
 * <li>When a response is received from a peer containing a single block of a
 * large body is received, the payload will be buffered and a blockwise transfer
 * is started for retrieving the rest of the body. Once all blocks have been
 * received, the overall body is re-assembled and forwarded to the client that
 * has issued the original request.</li>
 * </ul>
 * <p>
 * Block-wise transfer does not support concurrent transfer for the same
 * resource. So using <em>transparent</em> block-wise transfer with CoAP observe
 * is not really advised. When concurrent transfer is detected we always
 * privilege the most recent transfers. This is the most resilient way, as new
 * transfer will never be blocked by old incomplete transfer.
 * <p>
 * The transparent blockwise mode is enabled by using a value larger than
 * {@code 0} for {@link CoapConfig#MAX_RESOURCE_BODY_SIZE}. If the transparent
 * blockwise mode is enabled, the {@link Resource} is intended to provide the
 * full payload. The application should not use any block option, that is filled
 * in by the stack in transparent mode. Only in rare cases the application may
 * use a block option, but that easily ends up in undefined behavior. Usually
 * disabling the transparent blockwise mode setting
 * {@link CoapConfig#MAX_RESOURCE_BODY_SIZE} to {@code 0} is the better option,
 * if application block options are required.
 * <p>
 * Synchronization: Since 3.9 the blockwise-layer uses the read/write lock of
 * the {@link LeastRecentlyUpdatedCache} to prevent from failures caused by
 * race-conditions. All blockwise-status are kept in {@link #block1Transfers} or
 * {@link #block2Transfers}. {@code Add}, {@code update} and {@code remove} a
 * blockwise-status is executed acquiring the read/write lock on these
 * collections.
 * <ul>
 * <li>{@link #getOutboundBlock1Status(KeyUri, Exchange, Request, boolean)}</li>
 * <li>{@link #getInboundBlock1Status(KeyUri, Exchange, Request, boolean)}</li>
 * <li>{@link #getOutboundBlock2Status(KeyUri, Exchange, Response, boolean)}</li>
 * <li>{@link #getInboundBlock2Status(KeyUri, Exchange, Response)}</li>
 * <li>{@link #clearBlock1Status(Block1BlockwiseStatus)}</li>
 * <li>{@link #clearBlock2Status(Block2BlockwiseStatus)}</li>
 * </ul>
 * All operations on a single blockwise-status are executed synchronized to that
 * status. It's important to always first access the transfer-collection and
 * within that the status synchronized section. It's not possible to access the
 * transfer-collection within a synchronized section of a blockwise-status.
 * 
 * Note: since 3.0 the blockwise transfer has been redesigned. It is now based
 * on the {@link BlockOption#getOffset()} rather then previously on the
 * {@link BlockOption#getNum()}. That enables to adapt the blocksize also in the
 * middle of a resource body. The redesign also moved some similar code snippet
 * from the {@link BlockwiseLayer} to the {@link BlockwiseStatus} (or the
 * sub-classes). That resulted also in a easier synchronization, though the most
 * "write and read" access is now done within a synchronized method of that
 * {@link BlockwiseStatus}.
 * 
 * @see <a href=
 *      "https://mailarchive.ietf.org/arch/browse/core/?gbt=1&index=fYy61XmXaaDvu2sk_6hg4aP83Yw">block1
 *      size negotiation with 4.13 Request Entity Too Large</a>
 */
public class BlockwiseLayer extends AbstractLayer {

	/*
	 * What if a request contains a Block2 option with size 128 but the response
	 * is only 10 bytes long? A configuration property allow the server between
	 * two choices :
	 * <ul>
	 * <li>Include block2 option with m flag set to false to
	 * indicate that there is no more block to request.</li>
	 * <li>Do not include
	 * the block2 option at all (allowed by the RFC, it should be up to the
	 * client to handle this use case :
	 * https://tools.ietf.org/html/rfc7959#section-2.2)</li>
	 * </ul>
	 * <p>
	 * The above behavior is configured with 
	 * {@link CoapConfig#BLOCKWISE_STRICT_BLOCK2_OPTION}. 
	 * <p>
	 * A client, which uses the transparent blockwise mode, fails the request
	 * and cancels the complete transfer, if the offsets in the request and
	 * response are different.
	 * A client without that transparent blockwise mode needs to implement it's
	 * own preferred strategy.
	 * <p> 
	 * In a blockwise transfer of a response to a POST request, the draft should
	 * mention whether the client should always include all options in each
	 * request for the next block or not. The response is already produced at
	 * the server, thus, there is no point in receiving them again. The draft
	 * only states that the payload should be empty. Currently we always send
	 * all options in each request (just in case) (except observe which is not
	 * allowed).
	 * <p>
	 * When an observe notification is being sent blockwise, only the first
	 * block contains the observe option. The client decides, if it continues 
	 * to get the rest of the blocks and use a standard blockwise transfer for
	 * that.
	 */

	// Minimal block size : 2^4 bytes
	// (see https://tools.ietf.org/html/rfc7959#section-2.2)
	private static final int MINIMAL_BLOCK_SIZE = 16;

	private static final Logger LOGGER = LoggerFactory.getLogger(BlockwiseLayer.class);
	private static final Logger HEALTH_LOGGER = LoggerFactory.getLogger(LOGGER.getName() + ".health");
	private final BlockwiseStatus.RemoveHandler removeBlock1Handler = new BlockwiseStatus.RemoveHandler() {

		@Override
		public void remove(BlockwiseStatus status) {
			clearBlock1Status((Block1BlockwiseStatus)status);
		}

	};
	private final BlockwiseStatus.RemoveHandler removeBlock2Handler = new BlockwiseStatus.RemoveHandler() {

		@Override
		public void remove(BlockwiseStatus status) {
			clearBlock2Status((Block2BlockwiseStatus)status);
		}

	};
	private final LeastRecentlyUpdatedCache<KeyUri, Block1BlockwiseStatus> block1Transfers;
	private final LeastRecentlyUpdatedCache<KeyUri, Block2BlockwiseStatus> block2Transfers;
	private final AtomicInteger ignoredBlock2 = new AtomicInteger();
	private final String tag;
	private volatile boolean enableStatus;
	private ScheduledFuture<?> statusLogger;
	private ScheduledFuture<?> cleanup;
	private final long healthStatusInterval;
	private final int maxTcpBertBulkBlocks;
	private final int maxMessageSize;
	private final int preferredBlockSzx;
	private final int blockTimeout;
	private final int blockInterval;
	private final int maxResourceBodySize;
	private final boolean strictBlock1Option;
	private final boolean strictBlock2Option;
	/**
	 * Reuse tokens for follow-up requests.
	 * <p>
	 * <b>Note:</b> reusing tokens may introduce a vulnerability, if
	 * requests/response are captured and sent later without protecting the
	 * integrity of the payload by other means.
	 * </p>
	 * 
	 * @see <a href="https://github.com/core-wg/attacks-on-coap" target=
	 *      "_blank">attacks-on-coap</a>
	 * @since 3.8
	 */
	private final boolean reuseToken;
	/* @since 2.4 */
	private final boolean enableAutoFailoverOn413;

	private final EndpointContextMatcher matchingStrategy;

	/**
	 * Creates a new blockwise layer for a configuration.
	 * <p>
	 * The following configuration properties are used:
	 * <ul>
	 * <li>{@link CoapConfig#MAX_MESSAGE_SIZE} - This value is used as the
	 * threshold for determining whether an inbound or outbound message's body
	 * needs to be transferred blockwise. If not set, a default value of 4096
	 * bytes is used.</li>
	 * 
	 * <li>{@link CoapConfig#PREFERRED_BLOCK_SIZE} - This value is used as the
	 * value proposed to a peer when doing a transparent blockwise transfer. The
	 * value indicates the number of bytes, not the szx code. If not set, a
	 * default value of 1024 bytes is used.</li>
	 * 
	 * <li>{@link CoapConfig#MAX_RESOURCE_BODY_SIZE} - This value (in bytes) is
	 * used as the upper limit for the size of the buffer used for assembling
	 * blocks of a transparent blockwise transfer. Resource bodies larger than
	 * this value can only be transferred in a manually managed blockwise
	 * transfer. Setting this value to 0 disables transparent blockwise handling
	 * altogether, i.e. all messages will simply be forwarded directly up and
	 * down to the next layer. If not set, a default value of 8192 bytes is
	 * used.</li>
	 * 
	 * <li>{@link CoapConfig#BLOCKWISE_STATUS_LIFETIME} - The maximum amount of
	 * time (in milliseconds) allowed between transfers of individual blocks
	 * before the blockwise transfer state is discarded. If not set, a default
	 * value of 30 seconds is used.</li>
	 * 
	 * <li>{@link CoapConfig#BLOCKWISE_STRICT_BLOCK2_OPTION} - This value is
	 * used to indicate if the response should always include the Block2 option
	 * when client request early blockwise negociation but the response can be
	 * sent on one packet.</li>
	 * </ul>
	 * 
	 * @param tag logging tag
	 * @param enableBert {@code true}, enable TCP/BERT support, if the
	 *            configured value for
	 *            {@link CoapConfig#TCP_NUMBER_OF_BULK_BLOCKS} is larger than
	 *            {@code 1}. {@code false} disable it.
	 * @param config The configuration values to use.
	 * @deprecated use
	 *             {@link BlockwiseLayer#BlockwiseLayer(String, boolean, Configuration, EndpointContextMatcher)}
	 *             instead
	 * @since 3.0 (logging tag added and changed parameter to Configuration)
	 */
	public BlockwiseLayer(String tag, boolean enableBert, Configuration config) {
		this(tag, enableBert, config, null);
	}

	/**
	 * Creates a new blockwise layer for a configuration.
	 * <p>
	 * The following configuration properties are used:
	 * <ul>
	 * <li>{@link CoapConfig#MAX_MESSAGE_SIZE} - This value is used as the
	 * threshold for determining whether an inbound or outbound message's body
	 * needs to be transferred blockwise. If not set, a default value of 4096
	 * bytes is used.</li>
	 * 
	 * <li>{@link CoapConfig#PREFERRED_BLOCK_SIZE} - This value is used as the
	 * value proposed to a peer when doing a transparent blockwise transfer. The
	 * value indicates the number of bytes, not the szx code. If not set, a
	 * default value of 1024 bytes is used.</li>
	 * 
	 * <li>{@link CoapConfig#MAX_RESOURCE_BODY_SIZE} - This value (in bytes) is
	 * used as the upper limit for the size of the buffer used for assembling
	 * blocks of a transparent blockwise transfer. Resource bodies larger than
	 * this value can only be transferred in a manually managed blockwise
	 * transfer. Setting this value to 0 disables transparent blockwise handling
	 * altogether, i.e. all messages will simply be forwarded directly up and
	 * down to the next layer. If not set, a default value of 8192 bytes is
	 * used.</li>
	 * 
	 * <li>{@link CoapConfig#BLOCKWISE_STATUS_LIFETIME} - The maximum amount of
	 * time (in milliseconds) allowed between transfers of individual blocks
	 * before the blockwise transfer state is discarded. If not set, a default
	 * value of 30 seconds is used.</li>
	 * 
	 * <li>{@link CoapConfig#BLOCKWISE_STRICT_BLOCK2_OPTION} - This value is
	 * used to indicate if the response should always include the Block2 option
	 * when client request early blockwise negociation but the response can be
	 * sent on one packet.</li>
	 * </ul>
	 * 
	 * @param tag logging tag
	 * @param enableBert {@code true}, enable TCP/BERT support, if the
	 *            configured value for
	 *            {@link CoapConfig#TCP_NUMBER_OF_BULK_BLOCKS} is larger than
	 *            {@code 1}. {@code false} disable it.
	 * @param config The configuration values to use.
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @since 3.1
	 */
	public BlockwiseLayer(String tag, boolean enableBert, Configuration config,
			EndpointContextMatcher matchingStrategy) {
		this.tag = tag;
		this.matchingStrategy = matchingStrategy;
		int blockSize = config.get(CoapConfig.PREFERRED_BLOCK_SIZE);
		int szx = BlockOption.size2Szx(blockSize);
		String blockSizeDescription = String.valueOf(blockSize);
		maxTcpBertBulkBlocks = enableBert ? config.get(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS) : 1;
		if (maxTcpBertBulkBlocks > 1) {
			// Change the preferredBlockSize to accommodate BERT.
			szx = BlockOption.BERT_SZX;
			blockSizeDescription = "1024(BERT)";
		}
		maxMessageSize = config.get(CoapConfig.MAX_MESSAGE_SIZE);
		preferredBlockSzx = szx;
		blockTimeout = config.getTimeAsInt(CoapConfig.BLOCKWISE_STATUS_LIFETIME, TimeUnit.MILLISECONDS);
		blockInterval = config.getTimeAsInt(CoapConfig.BLOCKWISE_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		maxResourceBodySize = config.get(CoapConfig.MAX_RESOURCE_BODY_SIZE);
		int maxActivePeers = config.get(CoapConfig.MAX_ACTIVE_PEERS);
		block1Transfers = new LeastRecentlyUpdatedCache<>(maxActivePeers / 10, maxActivePeers, blockTimeout,
				TimeUnit.MILLISECONDS);
		block1Transfers.addEvictionListener(new LeastRecentlyUpdatedCache.EvictionListener<Block1BlockwiseStatus>() {

			@Override
			public void onEviction(Block1BlockwiseStatus status) {
				if (status.complete()) {
					LOGGER.debug("{}block1 transfer timed out!", BlockwiseLayer.this.tag);
					status.timeoutCurrentTranfer();
				}
			}
		});
		block2Transfers = new LeastRecentlyUpdatedCache<>(maxActivePeers / 10, maxActivePeers, blockTimeout,
				TimeUnit.MILLISECONDS);
		block2Transfers.addEvictionListener(new LeastRecentlyUpdatedCache.EvictionListener<Block2BlockwiseStatus>() {

			@Override
			public void onEviction(Block2BlockwiseStatus status) {
				if (status.complete()) {
					LOGGER.debug("{}block2 transfer timed out!", BlockwiseLayer.this.tag);
					status.timeoutCurrentTranfer();
				}
			}
		});
		strictBlock1Option = config.get(CoapConfig.BLOCKWISE_STRICT_BLOCK1_OPTION);
		strictBlock2Option = config.get(CoapConfig.BLOCKWISE_STRICT_BLOCK2_OPTION);
		reuseToken = config.get(CoapConfig.BLOCKWISE_REUSE_TOKEN);
		healthStatusInterval = config.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);

		enableAutoFailoverOn413 = config.get(CoapConfig.BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER);

		LOGGER.info(
				"{}BlockwiseLayer uses MAX_MESSAGE_SIZE={}, PREFERRED_BLOCK_SIZE={}, BLOCKWISE_STATUS_LIFETIME={}, MAX_RESOURCE_BODY_SIZE={}, BLOCKWISE_STRICT_BLOCK2_OPTION={}",
				tag, maxMessageSize, blockSizeDescription, blockTimeout, maxResourceBodySize, strictBlock2Option);
	}

	@Override
	public void start() {
		if (healthStatusInterval > 0 && HEALTH_LOGGER.isDebugEnabled() && statusLogger == null) {
			statusLogger = secondaryExecutor.scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					if (enableStatus) {
						{
							HEALTH_LOGGER.debug("{}{} block1 transfers", tag, block1Transfers.size());
							Iterator<Block1BlockwiseStatus> iterator = block1Transfers.ascendingIterator();
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
							HEALTH_LOGGER.debug("{}{} block2 transfers", tag, block2Transfers.size());
							Iterator<Block2BlockwiseStatus> iterator = block2Transfers.ascendingIterator();
							int max = 5;
							while (iterator.hasNext()) {
								HEALTH_LOGGER.debug("   block2 {}", iterator.next());
								--max;
								if (max == 0) {
									break;
								}
							}
						}
						HEALTH_LOGGER.debug("{}{} block2 responses ignored", tag, ignoredBlock2.get());
						cleanupExpiredBlockStatus(true);
					}
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.MILLISECONDS);
		}
		cleanup = secondaryExecutor.scheduleAtFixedRate(new Runnable() {

			@Override
			public void run() {
				cleanupExpiredBlockStatus(false);
			}
		}, blockInterval, blockInterval, TimeUnit.MILLISECONDS);
	}

	@Override
	public void destroy() {
		if (statusLogger != null) {
			statusLogger.cancel(false);
			statusLogger = null;
		}
		if (cleanup != null) {
			cleanup.cancel(false);
			cleanup = null;
		}
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		Request requestToSend = request;

		if (isTransparentBlockwiseHandlingEnabled() && !request.isMulticast()) {

			if (isRandomAccess(exchange)) {
				// This is the case if the user has explicitly added a block
				// option for random access.
				// Note: We do not regard it as random access when the block
				// number is 0.
				// This is because the user might just want to do early block
				// size negotiation but actually want to retrieve the whole body
				// by means of a transparent blockwise transfer.
			} else {
				KeyUri key = KeyUri.getKey(exchange);
				Block2BlockwiseStatus status = block2Transfers.get(key);
				if (status != null) {
					// Receiving a blockwise response in transparent mode
					// is done by in an "internal request" for the left payload.
					// Therefore the client is not aware of that ongoing request
					// and may send an additional request for the same resource.
					// If that happens, two blockwise request may pend for the
					// same resource. RFC7959, section 2.4, page 13,
					// "The Block2 Option provides no way for a single endpoint
					// to perform multiple concurrently proceeding block-wise
					// response payload transfer (e.g., GET) operations to the
					// same resource."
					// So one transfer must be abandoned. This chose the
					// transfer of the notify to be abandoned so that the client
					// receives the requested response but lose the notify.
					clearBlock2Status(status);
					status.completeOldTransfer(null);
				}

				if (requiresBlock1wise(request)) {
					try {
						// This must be a large POST or PUT request
						requestToSend = startBlockwiseUpload(key, exchange, request, preferredBlockSzx);
					} catch (BlockwiseTransferException ex) {
						LOGGER.debug("{}{} {}", tag, key, ex.getMessage());
						if (!ex.isCompleted()) {
							request.setSendError(ex);
						}
					}
				}
			}
		}

		exchange.setCurrentRequest(requestToSend);
		lower().sendRequest(exchange, requestToSend);
	}

	private Request startBlockwiseUpload(KeyUri key, Exchange exchange, Request request, int blockSzx)
			throws BlockwiseTransferException {
		Block1BlockwiseStatus status = getOutboundBlock1Status(key, exchange, request, true);
		Request block = status.getNextRequestBlock(blockSzx);
		block.setDestinationContext(request.getDestinationContext());
		Token token = request.getToken();
		if (token != null) {
			block.setToken(token);
		}
		return block;
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {

		if (isTransparentBlockwiseHandlingEnabled()) {

			if (request.getOptions().hasBlock1()) {
				// This is a large POST or PUT request
				handleInboundBlockwiseUpload(exchange, request);
				return;
			}

			BlockOption block2 = request.getOptions().getBlock2();
			if (block2 != null && block2.getNum() > 0) {
				// follow up block, respond from status?
				KeyUri key = KeyUri.getKey(exchange);
				Block2BlockwiseStatus status = block2Transfers.get(key);
				if (status == null) {
					LOGGER.debug(
							"{}peer wants to retrieve individual block2 {} of {}, delivering request to application layer",
							tag, block2, key);
				} else {
					// The peer wants to retrieve the next block of a blockwise
					// transfer
					boolean matching = true;
					if (matchingStrategy != null) {
						EndpointContext sourceContext2 = request.getSourceContext();
						// use context of first response
						EndpointContext sourceContext1 = status.firstMessage.getDestinationContext();
						matching = matchingStrategy.isResponseRelatedToRequest(sourceContext1, sourceContext2);
					}
					if (matching) {
						// matching endpoint context, use available response
						handleInboundRequestForNextBlock(exchange, request, status);
						return;
					} else {
						// not matching endpoint context, forward request to
						// application layer
						clearBlock2Status(status);
						LOGGER.debug(
								"{}peer wants to retrieve block2 {} of {} with new security context, delivering request to application layer",
								tag, block2, key);
					}
				}
			}
		}

		upper().receiveRequest(exchange, request);
	}

	private void handleInboundBlockwiseUpload(final Exchange exchange, final Request request) {

		if (requestExceedsMaxBodySize(request)) {
			int maxResourceBodySize = getMaxResourceBodySize(request);
			Response error = new Response(ResponseCode.REQUEST_ENTITY_TOO_LARGE, true);
			error.setDestinationContext(request.getSourceContext());
			error.setPayload(String.format("body too large, max. %d bytes", maxResourceBodySize));
			error.getOptions().setSize1(maxResourceBodySize);
			lower().sendResponse(exchange, error);

		} else {

			BlockOption block1 = request.getOptions().getBlock1();
			LOGGER.debug("{}inbound request contains block1 option {}", tag, block1);
			KeyUri key = KeyUri.getKey(exchange);
			Block1BlockwiseStatus status = getInboundBlock1Status(key, exchange, request, false);
			int blockOffset = block1.getOffset();

			if (blockOffset == 0 && !status.isStarting()) {
				// restart
				status = getInboundBlock1Status(key, exchange, request, true);
			} else if (!status.hasContentFormat(request.getOptions().getContentFormat())) {

				sendBlock1ErrorResponse(status, exchange, request, ResponseCode.REQUEST_ENTITY_INCOMPLETE,
						"unexpected Content-Format");
				return;
			}
			try {
				status.addBlock(request);
				if (block1.isM()) {

					// do not assemble and deliver the request yet
					LOGGER.debug("{}acknowledging incoming block1 [num={}], expecting more blocks to come", tag,
							block1.getNum());

					Response piggybacked = new Response(ResponseCode.CONTINUE);
					piggybacked.setDestinationContext(request.getSourceContext());
					block1 = getLimitedBlockOption(block1);
					piggybacked.getOptions().setBlock1(block1.getSzx(), true, block1.getNum());

					lower().sendResponse(exchange, piggybacked);

				} else {

					LOGGER.debug("{}peer has sent last block1 [num={}], delivering request to application layer", tag,
							block1.getNum());

					// Remember block to acknowledge.
					exchange.setBlock1ToAck(block1);

					// Assemble and deliver
					Request assembled = new Request(request.getCode());
					status.assembleReceivedMessage(assembled);

					// make sure we deliver the request using the MID and token
					// of the latest request so that the response created by the
					// application layer can reply to his token and MID
					assembled.setMID(request.getMID());
					assembled.setToken(request.getToken());
					// copy scheme
					assembled.setScheme(request.getScheme());

					// make sure peer's early negotiation of block2 size gets
					// included
					assembled.getOptions().setBlock2(request.getOptions().getBlock2());

					clearBlock1Status(status);

					exchange.setRequest(assembled);
					upper().receiveRequest(exchange, assembled);
				}

			} catch (BlockwiseTransferException ex) {
				ResponseCode code = ex.getResponseCode();
				LOGGER.debug("{}peer {} {}. Responding with {}", tag, key, ex.getMessage(), code);
				sendBlock1ErrorResponse(status, exchange, request, code, ex.getMessage());
			}
		}
	}

	private void sendBlock1ErrorResponse(Block1BlockwiseStatus status, Exchange exchange, Request request,
			ResponseCode errorCode, String message) {

		Response error = new Response(errorCode, true);
		if (strictBlock1Option) {
			error.getOptions().setBlock1(request.getOptions().getBlock1());
		}
		error.setDestinationContext(request.getSourceContext());
		error.setPayload(message);
		clearBlock1Status(status);
		lower().sendResponse(exchange, error);
	}

	private void handleInboundRequestForNextBlock(Exchange exchange, Request request, Block2BlockwiseStatus status) {

		BlockOption block2 = request.getOptions().getBlock2();
		block2 = getLimitedBlockOption(block2);
		Response nextBlockResponse = status.getNextResponseBlock(block2);
		nextBlockResponse.setDestinationContext(request.getSourceContext());

		if (nextBlockResponse.getOptions().getBlock2().isM()) {
			LOGGER.debug("{}peer has requested intermediary block of blockwise transfer: {}", tag, status);
			block2Transfers.update(status.getKeyUri());
		} else {
			// clean up blockwise status
			LOGGER.debug("{}peer has requested last block of blockwise transfer: {}", tag, status);
			clearBlock2Status(status);
		}

		lower().sendResponse(exchange, nextBlockResponse);
	}

	/**
	 * Invoked when a response is sent to a peer.
	 * <p>
	 * This method initiates a blockwise transfer, if the response's payload
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
			EndpointContext destinationContext = response.getEffectiveDestinationContext();
			if (destinationContext == null) {
				destinationContext = exchange.getRequest().getSourceContext();
			}
			if (isRandomAccess(exchange)) {

				BlockOption responseBlock2 = response.getOptions().getBlock2();

				// peer has issued a random block access request using option
				// block2 in request
				if (responseBlock2 != null) {
					if (requestBlock2.getOffset() != responseBlock2.getOffset()) {
						LOGGER.warn(
								"{}resource [{}] implementation error, peer requested block offset {} but resource returned block offest {}",
								tag, exchange.getRequest().getURI(), requestBlock2.getOffset(),
								responseBlock2.getOffset());
						responseToSend = new Response(ResponseCode.INTERNAL_SERVER_ERROR, true);
						responseToSend.setDestinationContext(destinationContext);
						responseToSend.setType(response.getType());
						responseToSend.setMID(response.getMID());
						responseToSend.addMessageObservers(response.getMessageObservers());
					}
				} else if (response.hasBlock(requestBlock2)) {
					// the resource implementation does not support blockwise
					// retrieval but instead has responded with the full
					// response body crop the response down to the requested
					// block
					BlockOption block2 = getLimitedBlockOption(requestBlock2);
					Block2BlockwiseStatus.crop(responseToSend, block2, maxTcpBertBulkBlocks);
				} else if (!response.isError()) {
					// peer has requested a non existing block
					responseToSend = new Response(ResponseCode.BAD_OPTION, true);
					responseToSend.setDestinationContext(destinationContext);
					responseToSend.setType(response.getType());
					responseToSend.setMID(response.getMID());
					responseToSend.addMessageObservers(response.getMessageObservers());
				}
			} else if (requiresBlock2wise(response, requestBlock2)) {

				// the client either has not included a block2 option at all or
				// has included a block2 option with num = 0 (early negotiation
				// of block size)

				KeyUri key = KeyUri.getKey(exchange);
				// We can not handle several block2 transfer for the same
				// client/resource.
				// So we clean previous transfer (priority to the new one)
				Block2BlockwiseStatus status = getOutboundBlock2Status(key, exchange, response, true);
				BlockOption block2;
				if (requestBlock2 != null) {
					block2 = getLimitedBlockOption(requestBlock2);
				} else {
					block2 = new BlockOption(preferredBlockSzx, false, 0);
				}
				responseToSend = status.getNextResponseBlock(block2);
				responseToSend.setDestinationContext(destinationContext);
				if (!responseToSend.getOptions().getBlock2().isM()) {
					clearBlock2Status(status);
				}
			} else if (requiresBlock2(requestBlock2)) {

				// the client has included a block2 option with num = 0
				// (early negotiation of block size)
				// the response fit into one block

				BlockOption block2 = getLimitedBlockOption(requestBlock2);
				Block2BlockwiseStatus.crop(responseToSend, block2, maxTcpBertBulkBlocks);
			}

			BlockOption block1 = exchange.getBlock1ToAck();
			if (block1 != null) {
				exchange.setBlock1ToAck(null);
				responseToSend.getOptions().setBlock1(block1);
			}
		}

		lower().sendResponse(exchange, responseToSend);
	}

	/**
	 * Get outer response to pass to application.
	 * 
	 * The outer response matches to initial application request.
	 * 
	 * @param exchange exchange
	 * @param response actual response
	 * @return outer application response
	 * @since 3.8
	 */
	private Response getOuterResponse(Exchange exchange, Response response) {
		// check, if response is for original request
		if (exchange.getRequest() != exchange.getCurrentRequest()) {
			// prepare the response as response to the original request
			Response outerResponse = new Response(response.getCode());
			// adjust the token using the original request
			outerResponse.setToken(exchange.getRequest().getToken());
			if (exchange.getRequest().getType() == Type.CON) {
				outerResponse.setType(Type.ACK);
				// adjust MID also
				outerResponse.setMID(exchange.getRequest().getMID());
			} else {
				outerResponse.setType(Type.NON);
			}
			outerResponse.setSourceContext(response.getSourceContext());
			outerResponse.setPayload(response.getPayload());
			outerResponse.setOptions(response.getOptions());
			outerResponse.setApplicationRttNanos(exchange.calculateApplicationRtt());
			Long rtt = response.getTransmissionRttNanos();
			if (rtt != null) {
				outerResponse.setTransmissionRttNanos(rtt);
			}
			exchange.setResponse(outerResponse);
			return outerResponse;
		} else {
			exchange.setResponse(response);
			return response;
		}
	}

	/**
	 * Invoked when a response has been received from a peer.
	 * <p>
	 * Checks whether the response
	 * <ul>
	 * <li>contains a block of an already ongoing blockwise transfer or contains
	 * the first block of a large body and requires the start of a blockwise
	 * transfer to retrieve the remaining blocks of the body or</li>
	 * <li>acknowledges a block sent to the peer as part of a block1 transfer
	 * and either sends the next block or handles a potential error
	 * situation.</li>
	 * </ul>
	 * 
	 * @param exchange The message exchange that the response is part of.
	 * @param response The response received from the peer.
	 */
	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {

		if (isTransparentBlockwiseHandlingEnabled() && !exchange.getRequest().isMulticast()) {
			if (response.isError()) {
				LOGGER.debug("{} received error {}:", tag, response);
				// handle blockwise specific error codes
				switch (response.getCode()) {
				case REQUEST_ENTITY_INCOMPLETE: // 4.08
					// we seem to have uploaded blocks not in expected order
				case REQUEST_ENTITY_TOO_LARGE: // 4.13
					if (handleEntityTooLarge(exchange, response)) {
						return;
					}

					// server is not able to process the payload we included
					KeyUri key = KeyUri.getKey(exchange);
					Block1BlockwiseStatus removedTracker = block1Transfers.remove(key);
					logRemovedBlock1Transfer(removedTracker);
				default:
				}

				upper().receiveResponse(exchange, getOuterResponse(exchange, response));
				return;
			}

			if (response.getMaxResourceBodySize() == 0) {
				response.setMaxResourceBodySize(exchange.getRequest().getMaxResourceBodySize());
			}

			if (!isRandomAccess(exchange)) {
				KeyUri key = KeyUri.getKey(exchange);
				Block2BlockwiseStatus status = block2Transfers.get(key);
				if (discardBlock2(key, status, exchange, response)) {
					return;
				}
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
			final KeyUri key = KeyUri.getKey(exchange);
			try {
				Request initialRequest = exchange.getRequest();
				if (response.getOptions().hasBlock1()) {

					BlockOption block1 = response.getOptions().getBlock1();

					Request blockRequest = null;
					boolean start = !initialRequest.isCanceled() && block1.getNum() == 0
							&& block1.getSize() < initialRequest.getPayloadSize();

					Block1BlockwiseStatus status;
					WriteLock lock = block1Transfers.writeLock();
					lock.lock();
					try {
						status = block1Transfers.update(key);
						if (status == null && start) {
							// We sent a request without using block1 and
							// server give us hint it want it with block1
							// Start block1 transfer
							blockRequest = startBlockwiseUpload(key, exchange, initialRequest,
									Math.min(block1.getSzx(), preferredBlockSzx));
						}
					} finally {
						lock.unlock();
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
						LOGGER.debug("{}discarding obsolete block1 response: {}", tag, response);
						return true;
					} else if (initialRequest.isCanceled()) {
						clearBlock1Status(status);
						return true;
					} else {
						// we handle only Entity Too Large
						// at begin of the transfer and
						// if blocksize requested is smaller
						if (status.isStarting() && block1.getSzx() < preferredBlockSzx) {
							// re-send first block with smaller szx
							status.restart();
							sendNextBlock(exchange, response, status);
							return true;
						}
					}
				} else if (!exchange.getRequest().isCanceled()) {
					Request requestToSend = null;
					// We sent a request without using block1 and
					// server give us hint it want it with block1
					// Try to guess the a block size to use
					Integer maxSize = response.getOptions().getSize1();
					if (maxSize != null) {
						if (maxSize < MINIMAL_BLOCK_SIZE || maxSize >= initialRequest.getPayloadSize()) {
							maxSize = null;
						}
					}
					if (maxSize == null && initialRequest.getPayloadSize() > MINIMAL_BLOCK_SIZE) {
						maxSize = initialRequest.getPayloadSize() - 1;
					}
					if (maxSize != null) {
						WriteLock lock = block1Transfers.writeLock();
						lock.lock();
						try {
							if (block1Transfers.update(key) == null) {
								// Start blockwise if we guess a correct size
								int blockszx = BlockOption.size2Szx(maxSize);
								requestToSend = startBlockwiseUpload(key, exchange, initialRequest,
										Math.min(blockszx, preferredBlockSzx));
							}
						} finally {
							lock.unlock();
						}
					}
					if (requestToSend != null) {
						exchange.setCurrentRequest(requestToSend);
						lower().sendRequest(exchange, requestToSend);
						return true;
					}
				}
			} catch (BlockwiseTransferException ex) {
				LOGGER.debug("{}{} {}", tag, key, ex.getMessage());
				// send original error response.
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
		LOGGER.debug("{}received response acknowledging block1 {}", tag, block1);

		// Block1 transfer has been originally created for an outbound request
		final KeyUri key = KeyUri.getKey(exchange);

		Block1BlockwiseStatus status = block1Transfers.update(key);

		if (status == null) {

			// request has not been sent blockwise
			LOGGER.debug("{}discarding unexpected block1 response: {}", tag, response);

		} else if (!status.hasMatchingToken(response)) {

			// a concurrent block1 transfer has been started in the meantime
			// which has "overwritten" the status object with the new
			// (concurrent) request so we simply discard the response
			LOGGER.debug("{}discarding obsolete block1 response: {}", tag, response);

		} else if (exchange.getRequest().isCanceled()) {

			clearBlock1Status(status);

		} else if (!status.isComplete()) {

			// this means that our last request's M-bit was set

			if (block1.isM()) {
				if (response.getCode() == ResponseCode.CONTINUE) {
					// server wants us to send the remaining blocks before
					// returning its response
					sendNextBlock(exchange, response, status);
				} else {
					// the server has responded in a way that is not compliant
					// with RFC 7959
					clearBlock1Status(status);
					exchange.getRequest().setRejected(true);
				}

			} else {
				// this means that the response already contains the server's
				// final response to the request. However, the server is still
				// expecting us to continue to send the remaining blocks as
				// specified in https://tools.ietf.org/html/rfc7959#section-2.3

				// the current implementation does not allow us to forward the
				// response to the application layer, though, because it would
				// "complete" the exchange and thus remove the blockwise status
				// necessary to keep track of this POST/PUT request we therefore
				// go on sending all pending blocks and then return the
				// response received for the last block
				sendNextBlock(exchange, response, status);
			}

		} else {

			// all blocks of block1 transfer have been sent
			clearBlock1Status(status);

			if (response.getOptions().hasBlock2()) {
				LOGGER.debug("{}Block1 followed by Block2 transfer", tag);
			} else {
				// All request blocks have been acknowledged and we have
				// received a response that does not need blockwise transfer.
				// Thus, deliver it.
				upper().receiveResponse(exchange, getOuterResponse(exchange, response));
			}
		}
	}

	private void sendNextBlock(Exchange exchange, Response response, Block1BlockwiseStatus status) {
		Request nextBlock = null;
		try {
			if (status.isComplete()) {
				LOGGER.debug("{}stopped block1 transfer, droping request.", tag);
			} else {
				// adjust block size to peer's preference
				int blockSzx = Math.min(response.getOptions().getBlock1().getSzx(), preferredBlockSzx);
				nextBlock = status.getNextRequestBlock(blockSzx);

				if (reuseToken) {
					// we use the same token to ease traceability
					nextBlock.setToken(response.getToken());
				}
				nextBlock.setDestinationContext(status.getFollowUpEndpointContext(response.getSourceContext()));

				LOGGER.debug("{}sending (next) Block1 [num={}]: {}", tag, nextBlock.getOptions().getBlock1().getNum(),
						nextBlock);
				exchange.setCurrentRequest(nextBlock);
				lower().sendRequest(exchange, nextBlock);
			}
		} catch (BlockwiseTransferException ex) {
			LOGGER.warn("{}cannot process next block request, aborting request!", tag, ex);
			if (!ex.isCompleted()) {
				exchange.getRequest().setSendError(ex);
			}
		} catch (RuntimeException ex) {
			LOGGER.warn("{}cannot process next block request, aborting request!", tag, ex);
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
	 * @return {@code true}, if response is to be ignored, {@code false},
	 *         otherwise
	 */
	private boolean discardBlock2(KeyUri key, Block2BlockwiseStatus status, Exchange exchange, Response response) {
		BlockOption block = response.getOptions().getBlock2();
		if (status != null) {
			// ongoing blockwise transfer
			boolean starting = (block == null) || (block.getNum() == 0);
			if (starting) {
				if (status.isNew(response)) {
					LOGGER.debug("{}discarding outdated block2 transfer {}, current is [{}]", tag, status.getObserve(),
							response);
					clearBlock2Status(status);
					status.completeOldTransfer(exchange);
				} else {
					LOGGER.debug("{}discarding old block2 transfer [{}], received during ongoing block2 transfer {}",
							tag, response, status.getObserve());
					status.completeNewTranfer(exchange);
					return true;
				}
			} else if (!status.matchTransfer(exchange)) {
				LOGGER.debug("{}discarding outdate block2 response [{}, {}] received during ongoing block2 transfer {}",
						tag, exchange.getNotificationNumber(), response, status.getObserve());
				status.completeNewTranfer(exchange);
				return true;
			}
		} else if (block != null && block.getNum() != 0) {
			LOGGER.debug("{}discarding stale block2 response [{}, {}] received without ongoing block2 transfer for {}",
					tag, exchange.getNotificationNumber(), response, key);
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
		KeyUri key = KeyUri.getKey(exchange);

		if (exchange.getRequest().isCanceled()) {

			// We have received a block of the resource body in response to a
			// request that has been canceled by the application layer. There
			// is no need to retrieve the remaining blocks.
			Block2BlockwiseStatus removedTracker = block2Transfers.remove(key);
			logRemovedBlock2Transfer(removedTracker);

			if (response.isNotification()) {
				// We have received a notification for an observed resource that
				// the application layer is no longer interested in.
				// Let upper layers decide what to do with the notification.
				upper().receiveResponse(exchange, response);
			}

		} else if (responseExceedsMaxBodySize(response)) {

			String msg = String.format(
					"requested resource body [%d bytes] exceeds max buffer size [%d bytes], aborting request",
					response.getOptions().getSize2(), getMaxResourceBodySize(response));
			LOGGER.debug("{}{}", tag, msg);
			exchange.getRequest().setOnResponseError(new IllegalStateException(msg));

		} else if (isRandomAccess(exchange)) {
			// The client has requested this specific block and we deliver it
			exchange.setResponse(response);
			upper().receiveResponse(exchange, response);
		} else {
			Block2BlockwiseStatus status;
			WriteLock lock = block2Transfers.writeLock();
			lock.lock();
			try {
				status = block2Transfers.get(key);
				if (discardBlock2(key, status, exchange, response)) {
					return;
				}
				status = getInboundBlock2Status(key, exchange, response);
			} finally {
				lock.unlock();
			}

			try {
				status.addBlock(response);

				if (block2.isM()) {
					// request next block
					requestNextBlock(exchange, response, status);

				} else {

					// we have received the last block of the block2 transfer

					LOGGER.debug(
							"{}all blocks have been retrieved, assembling response and delivering to application layer",
							tag);
					Response assembled = new Response(response.getCode());
					status.assembleReceivedMessage(assembled);

					// set overall transfer RTT
					assembled.setApplicationRttNanos(exchange.calculateApplicationRtt());
					Long rtt = response.getTransmissionRttNanos();
					if (rtt != null) {
						assembled.setTransmissionRttNanos(rtt);
					}

					clearBlock2Status(status);
					LOGGER.debug("{}assembled response: {}", tag, assembled);
					// Set the original request as current request so that
					// the Matcher can clean up its state based on the latest
					// ("current") request's MID and token
					exchange.setCurrentRequest(exchange.getRequest());
					// Set the assembled response as current response
					exchange.setResponse(assembled);
					upper().receiveResponse(exchange, assembled);
				}

			} catch (BlockwiseTransferException ex) {
				ignoredBlock2.incrementAndGet();
				LOGGER.debug("{}peer {}{}. Ignores response", tag, key, ex.getMessage());
				if (!ex.isCompleted()) {
					exchange.getRequest().setOnResponseError(ex);
				}
			}

		}
	}

	/**
	 * Sends request for the next response block.
	 * 
	 * @param exchange exchange for blockwise transfer
	 * @param response current response block
	 * @param status blockwise status
	 */
	private void requestNextBlock(Exchange exchange, Response response, Block2BlockwiseStatus status) {
		// do late block size negotiation
		int blockSzx = Math.min(response.getOptions().getBlock2().getSzx(), preferredBlockSzx);
		if (response.isNotification() && exchange.isNotification()) {
			// Recreate cleanup message observer
			exchange.getRequest().addMessageObserver(new CleanupMessageObserver(exchange));
		}

		try {
			Request block = status.getNextRequestBlock(blockSzx);

			block.setDestinationContext(status.getFollowUpEndpointContext(response.getSourceContext()));

			/*
			 * WARNING:
			 * 
			 * For Observe, the Matcher then will store the same exchange under
			 * a different KeyToken in exchangesByToken, which is cleaned up
			 * with the CleanupMessageObserver above.
			 */
			if (reuseToken && !response.isNotification()) {
				// we use the same token to ease traceability
				block.setToken(response.getToken());
			}

			if (status.isComplete()) {
				LOGGER.debug("{}stopped block2 transfer, droping response.", tag);
			} else {
				LOGGER.debug("{}requesting next Block2 [num={}]: {}", tag, block.getOptions().getBlock2().getNum(),
						block);
				exchange.setCurrentRequest(block);
				lower().sendRequest(exchange, block);
			}
		} catch (BlockwiseTransferException ex) {
			LOGGER.debug("{}{} Stop next block request!", tag, ex.getMessage());
			if (!ex.isCompleted()) {
				exchange.getRequest().setSendError(ex);
			}
		} catch (RuntimeException ex) {
			LOGGER.debug("{}cannot process next block request, aborting request!", tag, ex);
			if (!exchange.isComplete()) {
				exchange.getRequest().setSendError(ex);
			}
		}
	}

	/////////// HELPER METHODS //////////

	/**
	 * Get outbound block1status.
	 * 
	 * If not available, create new block1status,
	 * 
	 * Acquires write lock on {@link #block1Transfers}.
	 * 
	 * @param key uri-key
	 * @param exchange blockwise exchange.
	 * @param request outer request with complete payload.
	 * @param reset {@code true}, remove and cancel a previous block1status and
	 *            return a new block1status, {@code false}, return the previous
	 *            or new block1status.
	 * @return block1status
	 * @since 3.0
	 */
	private Block1BlockwiseStatus getOutboundBlock1Status(KeyUri key, Exchange exchange, Request request,
			boolean reset) {

		Integer size = null;
		Block1BlockwiseStatus previousStatus = null;
		Block1BlockwiseStatus status = null;
		WriteLock lock = block1Transfers.writeLock();
		lock.lock();
		try {
			if (reset) {
				previousStatus = block1Transfers.remove(key);
			} else {
				status = block1Transfers.update(key);
			}
			if (status == null) {
				status = Block1BlockwiseStatus.forOutboundRequest(key, removeBlock1Handler, exchange, request,
						maxTcpBertBulkBlocks);
				block1Transfers.put(key, status);
				enableStatus = true;
				size = block1Transfers.size();
			}
		} finally {
			lock.unlock();
		}
		if (previousStatus != null && previousStatus.cancelRequest()) {
			LOGGER.debug("{}stop previous block1 transfer {} {} for new {}", tag, key, previousStatus, request);
		}
		if (size != null) {
			LOGGER.debug("{}created tracker for outbound block1 transfer {}, transfers in progress: {}", tag, status,
					size);
		} else {
			LOGGER.debug("{}block1 transfer {} for {}", tag, key, request);
		}
		return status;
	}

	/**
	 * Get inbound block1status.
	 * 
	 * If {@code true} is provided for {@code reset}, remove and complete the
	 * previous block1status. If not available, create new block1status.
	 * 
	 * Acquires write lock on {@link #block1Transfers}.
	 * 
	 * @param key uri-key
	 * @param exchange blockwise exchange.
	 * @param request first received request
	 * @param reset {@code true}, remove and complete a previous block1status
	 *            and return a new block1status, {@code false}, return the
	 *            previous or new block1status.
	 * @return block1status
	 * @since 3.0
	 */
	private Block1BlockwiseStatus getInboundBlock1Status(KeyUri key, Exchange exchange, Request request,
			boolean reset) {

		boolean check = !reset;
		Integer size = null;
		Block1BlockwiseStatus previousStatus = null;
		Block1BlockwiseStatus status = null;
		int maxPayloadSize = getMaxResourceBodySize(request);
		WriteLock lock = block1Transfers.writeLock();
		lock.lock();
		try {
			if (reset) {
				previousStatus = block1Transfers.remove(key);
			} else {
				status = block1Transfers.update(key);
			}
			if (status == null) {
				check = false;
				status = Block1BlockwiseStatus.forInboundRequest(key, removeBlock1Handler, exchange, request,
						maxPayloadSize, maxTcpBertBulkBlocks);
				block1Transfers.put(key, status);
				enableStatus = true;
				size = block1Transfers.size();
			}
		} finally {
			lock.unlock();
		}
		if (previousStatus != null && previousStatus.complete()) {
			LOGGER.debug("{}stop previous block1 transfer {} {} for new {}", tag, key, previousStatus, request);
		}
		if (check && matchingStrategy != null) {
			EndpointContext sourceContext1 = status.firstMessage.getSourceContext();
			EndpointContext sourceContext2 = request.getSourceContext();
			if (!matchingStrategy.isResponseRelatedToRequest(sourceContext1, sourceContext2)) {
				LOGGER.debug("{}stop block1 transfer {} {} by context mismatch!", tag, key, previousStatus);
				// get new inbound block1 status.
				return getInboundBlock1Status(key, exchange, request, true);
			}
		}
		if (size != null) {
			LOGGER.debug("{}created tracker for inbound block1 transfer {}, transfers in progress: {}", tag, status,
					size);
		} else {
			LOGGER.debug("{}block1 transfer {} for {}", tag, key, request);
		}
		// we register a clean up task in case the peer does not retrieve all
		// blocks
		return status;
	}

	/**
	 * Get outbound block2status.
	 * 
	 * If {@code true} is provided for {@code reset}, remove and complete the
	 * previous block2status. If not available, create new block2status.
	 * 
	 * Acquires write lock on {@link #block2Transfers}.
	 * 
	 * @param key uri-key
	 * @param exchange blockwise exchange.
	 * @param response outer response with complete payload.
	 * @param reset {@code true}, remove and complete a previous block2status
	 *            and return a new block2status, {@code false} return the
	 *            previous or new block2status.
	 * @return block2status
	 * @since 3.0
	 */
	private Block2BlockwiseStatus getOutboundBlock2Status(KeyUri key, Exchange exchange, Response response,
			boolean reset) {

		Integer size = null;
		Block2BlockwiseStatus previousStatus = null;
		Block2BlockwiseStatus status = null;
		WriteLock lock = block2Transfers.writeLock();
		lock.lock();
		try {
			if (reset) {
				previousStatus = block2Transfers.remove(key);
			} else {
				status = block2Transfers.update(key);
			}
			if (status == null) {
				status = Block2BlockwiseStatus.forOutboundResponse(key, removeBlock2Handler, exchange, response,
						maxTcpBertBulkBlocks);
				block2Transfers.put(key, status);
				enableStatus = true;
				size = block2Transfers.size();
			}
		} finally {
			lock.unlock();
		}
		if (previousStatus != null && previousStatus.completeResponse()) {
			LOGGER.debug("{}stop previous block2 transfer {} {} for new {}", tag, key, previousStatus, response);
		}
		if (size != null) {
			LOGGER.debug("{}created tracker for outbound block2 transfer {}, transfers in progress: {}", tag, status,
					size);
		} else {
			LOGGER.debug("{}block2 transfer {} for {}", tag, key, response);
		}
		return status;
	}

	/**
	 * Get get inbound block2status.
	 * 
	 * If not available, create new block2status,
	 * 
	 * Acquires write lock on {@link #block2Transfers}.
	 * 
	 * @param key uri-key
	 * @param exchange blockwise exchange.
	 * @param response first blockwise response.
	 * @return block2status
	 */
	private Block2BlockwiseStatus getInboundBlock2Status(final KeyUri key, final Exchange exchange,
			final Response response) {
		Integer size = null;
		int maxPayloadSize = getMaxResourceBodySize(response);
		Block2BlockwiseStatus status;
		WriteLock lock = block2Transfers.writeLock();
		lock.lock();
		try {
			status = block2Transfers.update(key);
			if (status == null) {
				status = Block2BlockwiseStatus.forInboundResponse(key, removeBlock2Handler, exchange, response,
						maxPayloadSize, maxTcpBertBulkBlocks);
				block2Transfers.put(key, status);
				enableStatus = true;
				size = block2Transfers.size();
			}
		} finally {
			lock.unlock();
		}
		if (size != null) {
			LOGGER.debug("{}created tracker for inbound block2 transfer {}, transfers in progress: {}, {}", tag, 
					status, size, response);
		}
		return status;
	}

	/**
	 * Cleanup expired block status.
	 * 
	 * Acquires write lock on {@link #block1Transfers} and
	 * {@link #block2Transfers}.
	 * 
	 * @param dump {code true}, always log using {@link #HEALTH_LOGGER} with
	 *            {@code debug}, {@code false}, log only using {@link #LOGGER}
	 *            with {@code info}, when expired status are removed.
	 */
	private void cleanupExpiredBlockStatus(boolean dump) {
		int count = 0;
		count += block1Transfers.removeExpiredEntries(128);
		count += block2Transfers.removeExpiredEntries(128);
		if (dump) {
			HEALTH_LOGGER.debug("{}cleaned up {} block transfers!", tag, count);
		} else if (enableStatus && count > 0) {
			LOGGER.info("{}cleaned up {} block transfers!", tag, count);
		}
	}

	/**
	 * Clear block1status.
	 * 
	 * Acquires write lock on {@link #block1Transfers}.
	 * 
	 * @param status status to remove
	 */
	private void clearBlock1Status(Block1BlockwiseStatus status) {
		Block1BlockwiseStatus removedTracker = block1Transfers.remove(status.getKeyUri(), status);
		logRemovedBlock1Transfer(removedTracker);
	}

	/**
	 * Log removed block1status.
	 * 
	 * @param removedTracker removed block1 transfer tracker
	 * @since 3.9
	 */
	private void logRemovedBlock1Transfer(Block1BlockwiseStatus removedTracker) {
		if (removedTracker != null && removedTracker.complete()) {
			LOGGER.debug("{}removing block1 tracker [{}], block1 transfers still in progress: {}", tag,
					removedTracker.getKeyUri(), block1Transfers.size());
		}
	}

	/**
	 * Clear block2status.
	 * 
	 * Acquires write lock on {@link #block2Transfers}.
	 * 
	 * @param status status to remove
	 */
	private void clearBlock2Status(Block2BlockwiseStatus status) {
		Block2BlockwiseStatus removedTracker = block2Transfers.remove(status.getKeyUri(), status);
		logRemovedBlock2Transfer(removedTracker);
	}

	/**
	 * Log removed block2status.
	 * 
	 * @param removedTracker removed block2 transfer tracker
	 * @since 3.9
	 */
	private void logRemovedBlock2Transfer(Block2BlockwiseStatus removedTracker) {
		if (removedTracker != null && removedTracker.complete()) {
			LOGGER.debug("{}removing block2 tracker [{}], block2 transfers still in progress: {}", tag,
					removedTracker.getKeyUri(), block2Transfers.size());
		}
	}

	private boolean requiresBlock1wise(Request request) {
		boolean blockwiseRequired = request.getPayloadSize() > maxMessageSize;
		if (blockwiseRequired) {
			LOGGER.debug("{}request body [{}/{}] requires blockwise transfer", tag, request.getPayloadSize(),
					maxMessageSize);
		}
		return blockwiseRequired;
	}

	private boolean requiresBlock2wise(Response response, BlockOption requestBlock2) {

		boolean blockwiseRequired = response.getPayloadSize() > maxMessageSize;

		if (!blockwiseRequired && requestBlock2 != null) {
			int szx = Math.min(requestBlock2.getSzx(), preferredBlockSzx);
			int size = BlockOption.szx2Size(szx);
			blockwiseRequired = response.getPayloadSize() > size;
		}
		if (blockwiseRequired) {
			LOGGER.debug("{}response body [{}/{}] requires blockwise transfer", tag, response.getPayloadSize(),
					maxMessageSize);
		}
		return blockwiseRequired;
	}

	private boolean requiresBlock2(BlockOption requestBlock2) {

		boolean block2Required = strictBlock2Option && requestBlock2 != null;
		if (block2Required) {
			LOGGER.debug("{}response requires requested {} blockwise transfer", tag, requestBlock2);
		}
		return block2Required;
	}

	/**
	 * Check, if exchange is a random-access blockwise exchange.
	 * 
	 * @param exchange exchange to check.
	 * @return {@code true}, if the initiating request,
	 *         {@link Exchange#getRequest()}, contains a block2 option with a
	 *         block-number larger as 0. {@code false}, otherwise.
	 * @since 3.0
	 */
	private boolean isRandomAccess(final Exchange exchange) {
		BlockOption block2 = exchange.getRequest().getOptions().getBlock2();
		return block2 != null && block2.getNum() > 0;
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

	private BlockOption getLimitedBlockOption(BlockOption block) {
		if (preferredBlockSzx < block.getSzx()) {
			int offset = block.getOffset();
			int size = BlockOption.szx2Size(preferredBlockSzx);
			if (offset % size != 0) {
				throw new IllegalStateException(
						"Block offset " + offset + " doesn't align with preferred blocksize " + size + "!");
			}
			return new BlockOption(preferredBlockSzx, block.isM(), offset / size);
		} else {
			return block;
		}
	}

	public boolean isEmpty() {
		return block1Transfers.size() == 0 && block2Transfers.size() == 0;
	}
}
