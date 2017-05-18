/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - return null for ACK with mismatching MID
 *    Achim Kraus (Bosch Software Innovations GmbH) - reset blockwise-cleanup on 
 *                                                    complete exchange. Issue #103
 *    Achim Kraus (Bosch Software Innovations GmbH) - use save removes with
 *                                                    additional object to remove
 *                                                    as argument. 
 *                                                    Fix null response in
 *                                                    ExchangeObserverImpl
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Iterator;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.deduplication.Deduplicator;
import org.eclipse.californium.core.network.deduplication.DeduplicatorFactory;
import org.eclipse.californium.core.observe.ObserveRelation;

public class Matcher {

	private final static Logger LOGGER = Logger.getLogger(Matcher.class.getCanonicalName());
	
	private boolean started;
	private final ExchangeObserver exchangeObserver = new ExchangeObserverImpl();
	
	/* the executor, by default the one of the protocol stage */
	private ScheduledExecutorService executor;
	
	/* managing the MID per endpoint requires remote endpoint management */
	private final AtomicInteger currendMID;
	
	/* limit the token size to save bytes in closed environments */
	private final int tokenSizeLimit;
	
	private final ConcurrentHashMap<KeyMID, Exchange> exchangesByMID; // for all
	private final ConcurrentHashMap<KeyToken, Exchange> exchangesByToken; // for outgoing
	private final ConcurrentHashMap<KeyUri, Exchange> ongoingExchanges; // for blockwise
	
	// TODO: Multicast Exchanges: should not be removed from deduplicator
	private final Deduplicator deduplicator;
	// Idea: Only store acks/rsts and not the whole exchange. Responses should be sent CON.
	
	/* Health status output */
	private final Level healthStatusLevel;
	private final int healthStatusInterval; // seconds
	
	public Matcher(NetworkConfig config) {
		this.started = false;
		this.exchangesByMID = new ConcurrentHashMap<KeyMID, Exchange>();
		this.exchangesByToken = new ConcurrentHashMap<KeyToken, Exchange>();
		this.ongoingExchanges = new ConcurrentHashMap<KeyUri, Exchange>();

		DeduplicatorFactory factory = DeduplicatorFactory.getDeduplicatorFactory();
		this.deduplicator = factory.createDeduplicator(config);
		
		boolean randomMID = config.getBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START);
		if (randomMID) {
			currendMID = new AtomicInteger(new Random().nextInt(1<<16));
		} else {
			currendMID = new AtomicInteger(0);
		}
		
		tokenSizeLimit = config.getInt(NetworkConfig.Keys.TOKEN_SIZE_LIMIT);
		
		LOGGER.config("Matcher uses USE_RANDOM_MID_START="+randomMID+" and TOKEN_SIZE_LIMIT="+tokenSizeLimit);
		
		healthStatusLevel = Level.parse(config.getString(NetworkConfig.Keys.HEALTH_STATUS_PRINT_LEVEL));
		healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL);
	}
	
	public synchronized void start() {
		if (started) return;
		else started = true;
		
		if (executor == null)
			throw new IllegalStateException("Matcher has no executor to schedule exchange removal");
		
		deduplicator.start();
		
		// this is a useful health metric that could later be exported to some kind of monitoring interface
		if (LOGGER.isLoggable(healthStatusLevel)) {
			executor.scheduleAtFixedRate(new Runnable() {
				@Override
				public void run() {
					LOGGER.log(healthStatusLevel, "Matcher state: " + exchangesByMID.size() + " exchangesByMID, " + exchangesByToken.size() + " exchangesByToken, " + ongoingExchanges.size() + " ongoingExchanges");
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
	}
	
	public synchronized void stop() {
		if (!started) return;
		else started = false;
		deduplicator.stop();
		clear();
	}
	
	public synchronized void setExecutor(ScheduledExecutorService executor) {
		deduplicator.setExecutor(executor);
		this.executor = executor;
		// health status runnable is not migrated at the moment
	}
	
	public void sendRequest(Exchange exchange, Request request) {
		
		// ensure MID is set
		if (request.getMID() == Message.NONE) {
			request.setMID(currendMID.getAndIncrement()%(1<<16));
		}
		// request MID is from the local namespace -- use blank address
		KeyMID idByMID = new KeyMID(request.getMID(), null, 0);

		// ensure Token is set
		KeyToken idByToken;
		if (request.getToken() == null) {
			byte[] token;
			do {
				token = createNewToken();
				idByToken = new KeyToken(token);
			} while (exchangesByToken.get(idByToken) != null);
			
			request.setToken(token);
			
		} else {
			idByToken = new KeyToken(request.getToken());
			// ongoing requests may reuse token
			if (!(exchange.getFailedTransmissionCount()>0 || request.getOptions().hasBlock1() || request.getOptions().hasBlock2() || request.getOptions().hasObserve()) && exchangesByToken.get(idByToken) != null) {
				LOGGER.warning("Manual token overrides existing open request: "+idByToken);
			}
		}
		
		exchange.setObserver(exchangeObserver);
		
		if (LOGGER.isLoggable(Level.FINE)) LOGGER.fine("Stored open request by "+idByMID+", "+idByToken);
		
		exchangesByMID.put(idByMID, exchange);
		exchangesByToken.put(idByToken, exchange);
	}

	public void sendResponse(Exchange exchange, Response response) {
		
		// ensure MID is set
		if (response.getMID() == Message.NONE) {
			response.setMID(currendMID.getAndIncrement()%(1<<16));
		}
		
		// ensure Token is set
		response.setToken(exchange.getCurrentRequest().getToken());

		// If this is a CON notification we now can forget all previous NON notifications
		if (response.getType() == Type.CON || response.getType() == Type.ACK) {
			removeNotificatoinsOf(exchange);
		}
		
		// Blockwise transfers are identified by URI and remote endpoint
		if (response.getOptions().hasBlock2()) {
			Request request = exchange.getCurrentRequest();
			KeyUri idByUri = new KeyUri(request.getURI(), response.getDestination().getAddress(), response.getDestinationPort());
			// Observe notifications only send the first block, hence do not store them as ongoing
			if (exchange.getResponseBlockStatus()!=null && !response.getOptions().hasObserve()) {
				// Remember ongoing blockwise GET requests
				if (ongoingExchanges.put(idByUri, exchange)==null) {
					LOGGER.fine("Ongoing Block2 started late, storing "+idByUri + " for " + request);
				} else {
					LOGGER.fine("Ongoing Block2 continued, storing "+idByUri + " for " + request);
				}
			} else {
				LOGGER.fine("Ongoing Block2 completed, cleaning up "+idByUri + " for " + request);
				ongoingExchanges.remove(idByUri, exchange);
			}
		}
		
		// Insert CON and NON to match ACKs and RSTs to the exchange.
		// Do not insert ACKs and RSTs.
		if (response.getType() == Type.CON || response.getType() == Type.NON) {
			KeyMID idByMID = new KeyMID(response.getMID(), null, 0);
			exchangesByMID.put(idByMID, exchange);
		}
		
		// Only CONs and Observe keep the exchange active
		if (response.getType() != Type.CON && response.isLast()) {
			exchange.setComplete();
		}
	}

	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		
		// ensure Token is set
		message.setToken(new byte[0]);
		
		if (message.getType() == Type.RST && exchange != null) {
			// We have rejected the request or response
			exchange.setComplete();
		}
	}

	public Exchange receiveRequest(Request request) {
		/*
		 * This request could be
		 *  - Complete origin request => deliver with new exchange
		 *  - One origin block        => deliver with ongoing exchange
		 *  - Complete duplicate request or one duplicate block (because client got no ACK) 
		 *      =>
		 * 		if ACK got lost => resend ACK
		 * 		if ACK+response got lost => resend ACK+response
		 * 		if nothing has been sent yet => do nothing
		 * (Retransmission is supposed to be done by the retransm. layer)
		 */
		
		KeyMID idByMID = new KeyMID(request.getMID(), request.getSource().getAddress(), request.getSourcePort());
		
		/*
		 * The differentiation between the case where there is a Block1 or
		 * Block2 option and the case where there is none has the advantage that
		 * all exchanges that do not need blockwise transfer have simpler and
		 * faster code than exchanges with blockwise transfer.
		 */
		if (!request.getOptions().hasBlock1() && !request.getOptions().hasBlock2()) {

			Exchange exchange = new Exchange(request, Origin.REMOTE);
			Exchange previous = deduplicator.findPrevious(idByMID, exchange);
			if (previous == null) {
				exchange.setObserver(exchangeObserver);
				return exchange;
				
			} else {
				LOGGER.info("Duplicate request: "+request);
				request.setDuplicate(true);
				return previous;
			}
			
		} else {
			
			KeyUri idByUri = new KeyUri(request.getURI(), request.getSource().getAddress(), request.getSourcePort());
			
			if (LOGGER.isLoggable(Level.FINE)) LOGGER.fine("Looking up ongoing exchange for "+idByUri);
			
			Exchange ongoing = ongoingExchanges.get(idByUri);
			if (ongoing != null) {
				
				Exchange prev = deduplicator.findPrevious(idByMID, ongoing);
				if (prev != null) {
					LOGGER.info("Duplicate ongoing request: "+request);
					request.setDuplicate(true);
				} else {
					// the exchange is continuing, we can (i.e., must) clean up the previous response
					// check for null, in case no response was created (e.g., because the resource handler crashed...)
					if (ongoing.getCurrentResponse()!=null && ongoing.getCurrentResponse().getType() != Type.ACK && !ongoing.getCurrentResponse().getOptions().hasObserve()) {
						idByMID = new KeyMID(ongoing.getCurrentResponse().getMID(), null, 0);
						if (LOGGER.isLoggable(Level.FINE)) LOGGER.fine("Ongoing exchange got new request, cleaning up "+idByMID);
						exchangesByMID.remove(idByMID, ongoing);
					}
				}
				return ongoing;
		
			} else {
				// We have no ongoing exchange for that request block. 
				/*
				 * Note the difficulty of the following code: The first message
				 * of a blockwise transfer might arrive twice due to a
				 * retransmission. The new Exchange must be inserted in both the
				 * hash map 'ongoing' and the deduplicator. They must agree on
				 * which exchange they store!
				 */
				
				Exchange exchange = new Exchange(request, Origin.REMOTE);
				Exchange previous = deduplicator.findPrevious(idByMID, exchange);
				if (previous == null) {
					LOGGER.fine("New ongoing request, storing "+idByUri+" for "+request);
					exchange.setObserver(exchangeObserver);
					ongoingExchanges.put(idByUri, exchange);
					return exchange;
				} else {
					LOGGER.info("Duplicate initial request: "+request);
					request.setDuplicate(true);
					return previous;
				}
			} // if ongoing
		} // if blockwise
	}

	public Exchange receiveResponse(Response response) {
		
		/*
		 * This response could be
		 * - The first CON/NCON/ACK+response => deliver
		 * - Retransmitted CON (because client got no ACK)
		 * 		=> resend ACK
		 */
		
		KeyMID idByMID;
		if (response.getType() == Type.ACK) {
			// own namespace
			idByMID = new KeyMID(response.getMID(), null, 0);
		} else {
			// remote namespace
			idByMID = new KeyMID(response.getMID(), response.getSource().getAddress(), response.getSourcePort());
		}
		
		KeyToken idByToken = new KeyToken(response.getToken());
		
		Exchange exchange = exchangesByToken.get(idByToken);
		
		if (exchange != null) {
			if (response.getType() == Type.ACK && exchange.getCurrentRequest().getMID() != response.getMID()) {
				// The token matches but not the MID.
				LOGGER.warning("Possible MID reuse before lifetime end: "+response.getTokenString()+" expected MID "+exchange.getCurrentRequest().getMID()+" but received "+response.getMID());
				// when nested blockwise request/responses occurs (e.g. caused
				// by retransmission), a old response may stop the
				// retransmission of the current blockwise request. This seems
				// to be a side effect of reusing the token. If the response to
				// this current request is lost, the blockwise transfer times
				// out, because the retransmission is stopped too early.
				// Therefore don't return a exchange when the MID doesn't match.
				// See issue #275
				return null;
			}
			
			// There is an exchange with the given token
			Exchange prev = deduplicator.findPrevious(idByMID, exchange);
			if (prev != null) { // (and thus it holds: prev == exchange)
				LOGGER.info("Duplicate response for open exchange: "+response);
				response.setDuplicate(true);
			} else {
				idByMID = new KeyMID(exchange.getCurrentRequest().getMID(), null, 0);
				exchangesByMID.remove(idByMID, exchange);
				if (LOGGER.isLoggable(Level.FINE)) LOGGER.fine("Closed open request with "+idByMID);
			}
			
			return exchange;
			
		} else {
			// There is no exchange with the given token.
			if (response.getType() != Type.ACK) {
				// only act upon separate responses
				Exchange prev = deduplicator.find(idByMID);
				if (prev != null) {
					LOGGER.info("Duplicate response for completed exchange: "+response);
					response.setDuplicate(true);
					return prev;
				}
			} else {
				LOGGER.info("Ignoring unmatchable piggy-backed response from "+response.getSource()+":"+response.getSourcePort()+": "+response);
			}
			// ignore response
			return null;
		}
	}

	public Exchange receiveEmptyMessage(EmptyMessage message) {
		
		// local namespace
		KeyMID idByMID = new KeyMID(message.getMID(), null, 0);
		
		Exchange exchange = exchangesByMID.get(idByMID);
		
		if (exchange != null) {
			if (LOGGER.isLoggable(Level.FINE)) LOGGER.fine("Exchange got reply: Cleaning up "+idByMID);
			exchangesByMID.remove(idByMID, exchange);
			return exchange;
		} else {
			LOGGER.info("Ignoring unmatchable empty message from "+message.getSource()+":"+message.getSourcePort()+": "+message);
			return null;
		}
	}
	
	public void clear() {
		this.exchangesByMID.clear();
		this.exchangesByToken.clear();
		this.ongoingExchanges.clear();
		deduplicator.clear();
	}
	
	private void removeNotificatoinsOf(Exchange exchange) {
		ObserveRelation relation = exchange.getRelation();
		if (null != relation) {
			LOGGER.fine("Remove all remaining NON-notifications of observe relation");
			for (Iterator<Response> iterator = relation.getNotificationIterator(); iterator.hasNext();) {
				Response previous = iterator.next();
				// notifications are local MID namespace
				KeyMID idByMID = new KeyMID(previous.getMID(), null, 0);
				exchangesByMID.remove(idByMID, exchange);
				iterator.remove();
			}
		}
	}
	
	/**
	 * Creates a new token that is never the empty token (i.e., always 1-8 bytes).
	 * @return the new token
	 */
	private byte[] createNewToken() {
		
		Random random = new Random();
		
		// random length between 1 and tokenSizeLimit
		byte[] token = new byte[random.nextInt(tokenSizeLimit)+1];
		// random value
		random.nextBytes(token);
		
		return token;
	}
	
	private class ExchangeObserverImpl implements ExchangeObserver {

		@Override
		public void completed(Exchange exchange) {

			/* 
			 * Logging in this method leads to significant performance loss.
			 * Uncomment logging code only for debugging purposes.
			 */
			if (exchange.isComplete()) {
				// not for completeCurrentRequest
				exchange.setBlockCleanupHandle(null);
			}
			if (exchange.getOrigin() == Origin.LOCAL) {
				// this endpoint created the Exchange by issuing a request

				Request originRequest = exchange.getCurrentRequest();

				if (originRequest.hasMID()) {
					KeyMID idByMID = new KeyMID(originRequest.getMID(), null, 0);
					// in case an empty ACK was lost
					exchangesByMID.remove(idByMID, exchange);
				}

				if (originRequest.getToken() == null) {
					// this should not happen because we only register the observer
					// if we have successfully registered the exchange
					LOGGER.log(
							Level.WARNING,
							"exchange observer has been completed on unregistered exchange [peer: {0}:{1}, origin: {2}]",
							new Object[]{ originRequest.getDestination(), originRequest.getDestinationPort(),
									exchange.getOrigin()});
				} else {
					KeyToken idByToken = new KeyToken(originRequest.getToken());
					exchangesByToken.remove(idByToken, exchange);
					LOGGER.log(Level.FINER, "Exchange [{0}, origin: {1}] completed", new Object[]{ idByToken, exchange.getOrigin() });
				}

			} else { // Origin.REMOTE
				// this endpoint created the Exchange to respond to a request

				Response response = exchange.getCurrentResponse();
				if (response != null && response.getType() != Type.ACK) {
					// only response MIDs are stored for ACK and RST, no reponse Tokens
					KeyMID midKey = new KeyMID(response.getMID(), null, 0);
					LOGGER.log(Level.FINE, "Remote ongoing completed, cleaning up {0}", midKey);
					exchangesByMID.remove(midKey, exchange);
				}
				
				Request request = exchange.getCurrentRequest();
				if (request != null && (request.getOptions().hasBlock1() || (response != null && response.getOptions().hasBlock2())) ) {
					KeyUri uriKey = new KeyUri(request.getURI(), request.getSource().getAddress(), request.getSourcePort());
					LOGGER.fine("Remote ongoing completed, cleaning up "+uriKey);
					ongoingExchanges.remove(uriKey, exchange);
				}
				
				// Remove all remaining NON-notifications if this exchange is an observe relation
				removeNotificatoinsOf(exchange);
			}
		}
		
	}
	
}
