/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Iterator;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
	private ExchangeObserver exchangeObserver = new ExchangeObserverImpl();
	
	/** The executor. */
	private ScheduledExecutorService executor;
	
	// TODO: Make per endpoint
	private AtomicInteger currendMID; 
	
	private ConcurrentHashMap<KeyMID, Exchange> exchangesByMID; // Outgoing
	private ConcurrentHashMap<KeyToken, Exchange> exchangesByToken;
	
	private ConcurrentHashMap<KeyUri, Exchange> ongoingExchanges; // for blockwise
	
	// TODO: Multicast Exchanges: should not be removed from deduplicator
	private Deduplicator deduplicator;
	// Idea: Only store acks/rsts and not the whole exchange. Responses should be sent CON.
	
	public Matcher(NetworkConfig config) {
		this.started = false;
		this.exchangesByMID = new ConcurrentHashMap<KeyMID, Exchange>();
		this.exchangesByToken = new ConcurrentHashMap<KeyToken, Exchange>();
		this.ongoingExchanges = new ConcurrentHashMap<KeyUri, Exchange>();

		DeduplicatorFactory factory = DeduplicatorFactory.getDeduplicatorFactory();
		this.deduplicator = factory.createDeduplicator(config);
		
		if (config.getBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START))
			currendMID = new AtomicInteger(new Random().nextInt(1<<16));
		else currendMID = new AtomicInteger(0);
	}
	
	public synchronized void start() {
		if (started) return;
		else started = true;
		if (executor == null)
			throw new IllegalStateException("Matcher has no executor to schedule exchange removal");
		deduplicator.start();
		
		// this is a useful health metric that could later be exported to some kind of monitoring interface
		executor.scheduleAtFixedRate(new Runnable() {
			@Override
			public void run() {
				LOGGER.finer("Matcher state: " + exchangesByMID.size() + " exchangesByMID, " + exchangesByToken.size() + " exchangesByToken, " + ongoingExchanges.size() + " ongoingExchanges");
			}
		}, 60, 60, TimeUnit.SECONDS);
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
	}
	
	public void sendRequest(Exchange exchange, Request request) {
		if (request.getMID() == Message.NONE)
			request.setMID(currendMID.getAndIncrement()%(1<<16));

		/*
		 * The request is a CON or NON and must be prepared for these responses
		 * - CON  => ACK/RST/ACK+response/CON+response/NON+response
		 * - NON => RST/CON+response/NON+response
		 * If this request goes lost, we do not get anything back.
		 */
		
		KeyMID idByMID = new KeyMID(request.getMID(), 
				request.getDestination().getAddress(), request.getDestinationPort());
		KeyToken idByTok = new KeyToken(request.getToken(),
				request.getDestination().getAddress(), request.getDestinationPort());
		
		exchange.setObserver(exchangeObserver);
		
		LOGGER.fine("Stored open request by "+idByMID+", "+idByTok);
		
		exchangesByMID.put(idByMID, exchange);
		exchangesByToken.put(idByTok, exchange);
	}

	public void sendResponse(Exchange exchange, Response response) {
		if (response.getMID() == Message.NONE)
			response.setMID(currendMID.getAndIncrement()%(1<<16));
		
		/*
		 * The response is a CON or NON or ACK and must be prepared for these
		 * - CON  => ACK/RST // we only care to stop retransmission
		 * - NON => RST // we don't care
		 * - ACK  => nothing!
		 * If this response goes lost, we must be prepared to get the same 
		 * CON/NON request with same MID again. We then find the corresponding
		 * exchange and the ReliabilityLayer resends this response.
		 */
		
		if (response.getDestination() == null)
			throw new NullPointerException("Response has no destination address set");
		if (response.getDestinationPort() == 0)
			throw new NullPointerException("Response hsa no destination port set");

		// If this is a CON notification we now can forget all previous NON notifications
		if (response.getType() == Type.CON || response.getType() == Type.ACK) {
			ObserveRelation relation = exchange.getRelation();
			if (relation != null) {
				removeNotificatoinsOf(relation);
			}
		}
		
		if (response.getOptions().hasBlock2()) {
			Request request = exchange.getRequest();
			KeyUri idByUri = new KeyUri(request.getURI(),
					response.getDestination().getAddress(), response.getDestinationPort());
			if (exchange.getResponseBlockStatus()!=null && !response.getOptions().hasObserve()) {
				// Remember ongoing blockwise GET requests
				LOGGER.fine("Ongoing Block2 started, storing "+idByUri + "\nOngoing " + request + "\nOngoing " + response);
				ongoingExchanges.put(idByUri, exchange);
			} else {
				LOGGER.fine("Ongoing Block2 completed, cleaning up "+idByUri + "\nOngoing " + request + "\nOngoing " + response);
				ongoingExchanges.remove(idByUri);
			}
		}
		
		// Insert CON and NON to match ACKs and RSTs to the exchange.
		// Do not insert ACKs and RSTs.
		if (response.getType() == Type.CON || response.getType() == Type.NON) {
			KeyMID idByMID = new KeyMID(response.getMID(), 
					response.getDestination().getAddress(), response.getDestinationPort());
			exchangesByMID.put(idByMID, exchange);
		}
		
		if (response.getType() == Type.ACK || response.getType() == Type.NON) {
			// Since this is an ACK or NON, the exchange is over with sending this response.
			if (response.isLast()) {
				exchange.setComplete();
			}
		} // else this is a CON and we need to wait for the ACK or RST.
	}

	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		
		if (message.getType() == Type.RST && exchange != null) {
			// We have rejected the request or response
			exchange.setComplete();
		}
		
		/*
		 * We do not expect any response for an empty message
		 */
		if (message.getMID() == Message.NONE)
			LOGGER.severe("Empy message "+ message+" has no MID // debugging");
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
				LOGGER.info("Message is a duplicate, ignore: "+request);
				request.setDuplicate(true);
				return previous;
			}
			
		} else {
			
			KeyUri idByUri = new KeyUri(request.getURI(),
					request.getSource().getAddress(), request.getSourcePort());
			
			LOGGER.fine("Lookup ongoing exchange for "+idByUri);
			Exchange ongoing = ongoingExchanges.get(idByUri);
			if (ongoing != null) {
				
				Exchange prev = deduplicator.findPrevious(idByMID, ongoing);
				if (prev != null) {
					LOGGER.info("Message is a duplicate: "+request);
					request.setDuplicate(true);
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
				LOGGER.fine("New ongoing exchange for remote Block1 request with key "+idByUri);
				if (previous == null) {
					exchange.setObserver(exchangeObserver);
					ongoingExchanges.put(idByUri, exchange);
					return exchange;
				} else {
					LOGGER.info("Message is a duplicate: "+request);
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

		KeyMID idByMID = new KeyMID(response.getMID(), 
				response.getSource().getAddress(), response.getSourcePort());
		
		KeyToken idByTok = new KeyToken(response.getToken(), 
				response.getSource().getAddress(), response.getSourcePort());
		
		Exchange exchange = exchangesByToken.get(idByTok);
		
		if (exchange != null) {
			// There is an exchange with the given token
			
			Exchange prev = deduplicator.findPrevious(idByMID, exchange);
			if (prev != null) { // (and thus it holds: prev == exchange)
				LOGGER.fine("Duplicate response "+response);
				response.setDuplicate(true);
			} else {
				LOGGER.fine("Exchange got reply: Cleaning up "+idByMID);
				exchangesByMID.remove(idByMID);
			}
			
			if (response.getType() == Type.ACK && exchange.getCurrentRequest().getMID() != response.getMID()) {
				// The token matches but not the MID. This is a response for an older exchange
				LOGGER.warning("Token matches but not MID: Expected "+exchange.getCurrentRequest().getMID()+" but was "+response.getMID());
				// ignore response
				return null;
			} else {
				// this is a separate response that we can deliver
				return exchange;
			}
			
		} else {
			// There is no exchange with the given token.
			if (response.getType() != Type.ACK) {
				Exchange prev = deduplicator.find(idByMID);
				if (prev != null) {
					response.setDuplicate(true);
					return prev;
				}
			}
			// ignore response
			return null;
		}
	}

	public Exchange receiveEmptyMessage(EmptyMessage message) {
		
		KeyMID idByMID = new KeyMID(message.getMID(),
				message.getSource().getAddress(), message.getSourcePort());
		
		Exchange exchange = exchangesByMID.get(idByMID);
		
		if (exchange != null) {
			LOGGER.fine("Exchange got reply: Cleaning up "+idByMID);
			exchangesByMID.remove(idByMID);
			return exchange;
		} else {
			LOGGER.info("Matcher received empty message that does not match any exchange: "+message);
			// ignore message;
			return null;
		} // else, this is an ACK for an unknown exchange and we ignore it
	}
	
	public void clear() {
		this.exchangesByMID.clear();
		this.exchangesByToken.clear();
		this.ongoingExchanges.clear();
		deduplicator.clear();
	}
	
	private void removeNotificatoinsOf(ObserveRelation relation) {
		LOGGER.fine("Remove all remaining NON-notifications of observe relation");
		for (Iterator<Response> iterator = relation.getNotificationIterator(); iterator.hasNext();) {
			Response previous = iterator.next();
			KeyMID idByMID = new KeyMID(previous.getMID(), 
					previous.getDestination().getAddress(), previous.getDestinationPort());
			exchangesByMID.remove(idByMID);
			iterator.remove();
		}
	}
	
	private class ExchangeObserverImpl implements ExchangeObserver {

		@Override
		public void completed(Exchange exchange) {
			
			/* 
			 * Logging in this method leads to significant performance loss.
			 * Uncomment logging code only for debugging purposes.
			 */
			
			if (exchange.getOrigin() == Origin.LOCAL) {
				// this endpoint created the Exchange by issuing a request
				Request request = exchange.getRequest();
				KeyToken idByTok = new KeyToken(exchange.getCurrentRequest().getToken(), request.getDestination().getAddress(), request.getDestinationPort());
				KeyMID idByMID = new KeyMID(request.getMID(), request.getDestination().getAddress(), request.getDestinationPort());
				
//				LOGGER.fine("Exchange completed: Cleaning up "+idByTok);
				exchangesByToken.remove(idByTok);
				// in case an empty ACK was lost
				exchangesByMID.remove(idByMID);
			
			} else {
				// this endpoint created the Exchange to respond a request
				Request request = exchange.getCurrentRequest();
				if (request != null) {
					// TODO: We can optimize this and only do it, when the request really had blockwise transfer
					KeyUri uriKey = new KeyUri(request.getURI(),
							request.getSource().getAddress(), request.getSourcePort());
//					LOGGER.fine("Remote ongoing completed, cleaning up "+uriKey);
					ongoingExchanges.remove(uriKey);
				}
				// TODO: What if the request is only a block?
				// TODO: This should only happen if the transfer was blockwise

				Response response = exchange.getResponse();
				if (response != null) {
					// only response MIDs are stored for ACK and RST, no reponse Tokens
					KeyMID midKey = new KeyMID(response.getMID(), 
							response.getDestination().getAddress(), response.getDestinationPort());
//					LOGGER.fine("Remote ongoing completed, cleaning up "+midKey);
					exchangesByMID.remove(midKey);
				}
				
				// Remove all remaining NON-notifications if this exchange is an observe relation
				ObserveRelation relation = exchange.getRelation();
				if (relation != null) {
					removeNotificatoinsOf(relation);
				}
			}
		}
		
	}
	
}
