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
 *    Stefan Jucker - DTLS implementation
 *    Julien Vermillard - Sierra Wireless
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.ConnectorBase;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSFlight;
import org.eclipse.californium.scandium.dtls.DTLSMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.FragmentedHandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHello;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * A {@link Connector} implementation for securing the inner datagrams using the DTLS standard.	
 * 
 */
public class DTLSConnector extends ConnectorBase {
	/*
	 * Note: DTLSConnector can also implement the interface Connector instead of
	 * extending ConnectorBase
	 */
	
	private final static Logger LOGGER = Logger.getLogger(DTLSConnector.class.getCanonicalName());

	/** all the configuration options for the DTLS connector */ 
	private final DTLSConnectorConfig config = new DTLSConnectorConfig(this);
	
	private final InetSocketAddress address;
	
	private DatagramSocket socket;
	
	/** The timer daemon to schedule retransmissions. */
	private Timer timer = new Timer(true); // run as daemon
	
	/** Storing sessions according to peer-addresses */
	private Map<String, DTLSSession> dtlsSessions = new ConcurrentHashMap<String, DTLSSession>();

	/** Storing handshakers according to peer-addresses. */
	private Map<String, Handshaker> handshakers = new ConcurrentHashMap<String, Handshaker>();

	/** Storing flights according to peer-addresses. */
	private Map<String, DTLSFlight> flights = new ConcurrentHashMap<String, DTLSFlight>();
	
	/** root authorities certificates */
	private final Certificate[] rootCerts;
	
	/**
	 * Create a DTLS connector.
	 * @param address the address to bind
	 * @param rootCertificates list of trusted self-signed root certificates
	 */
	public DTLSConnector(InetSocketAddress address, Certificate[] rootCertificates) {
		super(address);
		this.address = address;
		this.rootCerts = rootCertificates;
	}
	
	
	/**
	 * Close the DTLS session with all peers.
	 */
	public void close() {
		for (DTLSSession session : dtlsSessions.values()) {
			this.close(session.getPeer());
		}
	}
	
	/**
	 * Close the DTLS session with the given peer.
	 * 
	 * @param peerAddress the remote endpoint of the session to close
	 */
	public void close(InetSocketAddress peerAddress) {
	   String addrKey = addressToKey(peerAddress); 
		try {
			DTLSSession session = dtlsSessions.get(addrKey);
			
			if (session != null) {
				DTLSMessage closeNotify = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
				
				DTLSFlight flight = new DTLSFlight();
				flight.addMessage(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), closeNotify, session));
				flight.setRetransmissionNeeded(false);
				
				cancelPreviousFlight(peerAddress);
		
				flight.setPeerAddress(peerAddress);
				flight.setSession(session);

				if (LOGGER.isLoggable(Level.FINE)) {
					LOGGER.fine("Sending CLOSE_NOTIFY to " + peerAddress.toString());
				}
				
				sendFlight(flight);
			} else {
				if (LOGGER.isLoggable(Level.WARNING)) {
					LOGGER.warning("Session to close not found: " + peerAddress.toString());
				}
			}
		} finally {
			//clear sessions
			dtlsSessions.remove(addrKey);
			handshakers.remove(addrKey);
			flights.remove(addrKey);
		}
	}
	
	@Override
	public synchronized void start() throws IOException {
		socket = new DatagramSocket(address.getPort(), address.getAddress());
		super.start();
		if (LOGGER.isLoggable(Level.INFO)) {
			LOGGER.info("DLTS connector listening on "+address);
		}
	}
	
	@Override
	public synchronized void stop() {
		this.close();
		this.socket.close();
		super.stop();
	}
	
	// TODO: We should not return null
	@Override
	protected RawData receiveNext() throws Exception {
		byte[] buffer = new byte[config.getMaxPayloadSize()];
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
		socket.receive(packet);
		
		if (packet.getLength() == 0)
			return null;

		InetSocketAddress peerAddress = new InetSocketAddress(packet.getAddress(), packet.getPort());

		if (LOGGER.isLoggable(Level.FINEST)) {
			LOGGER.finest(" => find handshaker for key "+peerAddress.toString());
		}
		DTLSSession session = dtlsSessions.get(addressToKey(peerAddress));
		Handshaker handshaker = handshakers.get(addressToKey(peerAddress));
		byte[] data = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength());

		try {
			List<Record> records = Record.fromByteArray(data);

			for (Record record : records) {
				record.setSession(session);

				RawData raw = null;

				ContentType contentType = record.getType();
				LOGGER.finest(" => contentType: "+contentType);
				DTLSFlight flight = null;
				switch (contentType) {
				case APPLICATION_DATA:
					if (session == null) {
						// There is no session available, so no application data
						// should be received, discard it
						if (LOGGER.isLoggable(Level.INFO)) {
							LOGGER.info("Discarded unexpected application data message from " + peerAddress.toString());
						}
						return null;
					}
					// at this point, the current handshaker is not needed
					// anymore, remove it
					handshakers.remove(addressToKey(peerAddress));

					ApplicationMessage applicationData = (ApplicationMessage) record.getFragment();
					raw = new RawData(applicationData.getData());
					break;

				case ALERT:
					AlertMessage alert = (AlertMessage) record.getFragment();
					switch (alert.getDescription()) {
					case CLOSE_NOTIFY:
						session.setActive(false);
						
						if (LOGGER.isLoggable(Level.FINE)) {
							LOGGER.fine("Received CLOSE_NOTIFY from " + peerAddress.toString());
						}
						// server must reply with CLOSE_NOTIFY
						if (!session.isClient()) {
							DTLSMessage closeNotify = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
							flight = new DTLSFlight();
							flight.addMessage(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), closeNotify, session));
							flight.setRetransmissionNeeded(false);
						}
						
						if (dtlsSessions.remove(addressToKey(peerAddress))!=null) {
							if (LOGGER.isLoggable(Level.INFO)) {
								LOGGER.info("Closed session with peer: " + peerAddress.toString());
							}
						} else {
							if (LOGGER.isLoggable(Level.WARNING)) {
								LOGGER.warning("Session to close not found: " + peerAddress.toString());
						
							}
						}
						break;
					
					// remote implementation might use any alert (e.g., against padding oracle attack)
					default:
						if (LOGGER.isLoggable(Level.WARNING)) {
							LOGGER.warning(alert.getDescription() + " with " + peerAddress.toString());
						}
						// cleaning up
						cancelPreviousFlight(peerAddress);
						dtlsSessions.remove(addressToKey(peerAddress));
						handshakers.remove(addressToKey(peerAddress));
						break;
						
						//TODO somehow tell CoAP endpoint to cancel
					}
					break;
				case CHANGE_CIPHER_SPEC:
				case HANDSHAKE:
					if (LOGGER.isLoggable(Level.FINEST)) {
						LOGGER.finest(" => handshaker: "+handshaker);
					}
					if (handshaker == null) {
						/*
						 * A handshake message received, but no handshaker
						 * available: this must mean that we either received
						 * a HelloRequest (from server) or a ClientHello
						 * (from client) => initialize appropriate
						 * handshaker type
						 */

						HandshakeMessage handshake = (HandshakeMessage) record.getFragment();

						switch (handshake.getMessageType()) {
						case HELLO_REQUEST:
							/*
							 * Client side: server desires a re-handshake
							 */
							if (session == null) {
								// create new session
								session = new DTLSSession(peerAddress, true);
								// store session according to peer address
								dtlsSessions.put(addressToKey(peerAddress), session);

								if (LOGGER.isLoggable(Level.INFO)) {
									LOGGER.info("Created new session as client with peer: " + peerAddress.toString());
								}
							};
							handshaker = new ClientHandshaker(peerAddress, null, session, rootCerts, config);
							handshaker.setMaxFragmentLength(config.getMaxFragmentLength());
							
							handshakers.put(addressToKey(peerAddress), handshaker);
							
							if (LOGGER.isLoggable(Level.FINEST)) {
								LOGGER.finest("Stored re-handshaker: " + handshaker.toString() + " for " + peerAddress.toString());
							}
							break;

						case CLIENT_HELLO:
							/*
							 * Server side: server received a client hello:
							 * check first if client wants to resume a
							 * session (message must contain session
							 * identifier) and then check if particular
							 * session still available, otherwise conduct
							 * full handshake with fresh session.
							 */

							if (!(handshake instanceof FragmentedHandshakeMessage)) {
								// check if session identifier set
								ClientHello clientHello = (ClientHello) handshake;
								session = getSessionByIdentifier(clientHello.getSessionId().getSessionId());
							}
							
							if (session == null) {
								// create new session
								session = new DTLSSession(peerAddress, false);
								// store session according to peer address
								dtlsSessions.put(addressToKey(peerAddress), session);

								if (LOGGER.isLoggable(Level.INFO)) {
									LOGGER.info("Created new session as server with peer: " + peerAddress.toString());
								}
								handshaker = new ServerHandshaker(peerAddress, session, rootCerts, config);
								handshaker.setMaxFragmentLength(config.getMaxFragmentLength());
							} else {
								handshaker = new ResumingServerHandshaker(peerAddress, session, rootCerts, config);
								handshaker.setMaxFragmentLength(config.getMaxFragmentLength());
							}
							handshakers.put(addressToKey(peerAddress), handshaker);
							if (LOGGER.isLoggable(Level.FINEST)) {
								LOGGER.finest("Stored handshaker: " + handshaker.toString() + " for " + peerAddress.toString());
							}
							break;

						default:
							LOGGER.severe("Received unexpected first handshake message (type="+handshake.getMessageType()+") from " + peerAddress.toString() + ":\n" + handshake.toString());
							break;
						}
					}
					flight = handshaker.processMessage(record);
					break;

				default:
					LOGGER.severe("Received unknown DTLS record from " + peerAddress.toString() + ":\n" + ByteArrayUtils.toHexString(data));
					break;
				}

				if (flight != null) {
					cancelPreviousFlight(peerAddress);

					flight.setPeerAddress(peerAddress);
					flight.setSession(session);

					if (flight.isRetransmissionNeeded()) {
						flights.put(addressToKey(peerAddress), flight);
						scheduleRetransmission(flight);
					}

					sendFlight(flight);
				}

				if (raw != null) {

					raw.setAddress(packet.getAddress());
					raw.setPort(packet.getPort());

					return raw;
				}
			}

		} catch (Exception e) {
			/*
			 * If it is a known handshake failure, send the specific Alert,
			 * otherwise the general Handshake_Failure Alert. 
			 */
			DTLSFlight flight = new DTLSFlight();
			flight.setRetransmissionNeeded(false);
			flight.setPeerAddress(peerAddress);
			flight.setSession(session);
			
			AlertMessage alert;
			if (e instanceof HandshakeException) {
				alert = ((HandshakeException) e).getAlert();
				LOGGER.severe("Handshake Exception (" + peerAddress.toString() + "): " + e.getMessage()+" we close the session");
				close(session.getPeer());
			} else {
				alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
				LOGGER.log(Level.SEVERE, "Unknown Exception (" + peerAddress + ").", e);
			}

			LOGGER.log(Level.SEVERE, "Datagram which lead to exception (" + peerAddress + "): " + ByteArrayUtils.toHexString(data), e);
			
			if (session == null) {
				// if the first received message failed, no session has been set
				session = new DTLSSession(peerAddress, false);
			}
			cancelPreviousFlight(peerAddress);
			
			flight.addMessage(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), alert, session));
			sendFlight(flight);
		} // receive()
		return null;
	}

	@Override
	protected void sendNext(RawData message) throws Exception {
		
		InetSocketAddress peerAddress = message.getInetSocketAddress();
		if (LOGGER.isLoggable(Level.FINE)) {
			LOGGER.fine("Sending message to " + peerAddress);
		}
		DTLSSession session = dtlsSessions.get(addressToKey(peerAddress));
		
		/*
		 * When the DTLS layer receives a message from an upper layer, there is
		 * either a already a DTLS session available with the peer or a new
		 * handshake must be executed. If a session is available and active, the
		 * message will be encrypted and send to the peer, otherwise a short
		 * handshake will be initiated.
		 */
		Record encryptedMessage = null;
		Handshaker handshaker = null;

		if (session == null) {
			// no session with endpoint available, create new empty session,
			// start fresh handshake
			session = new DTLSSession(peerAddress, true);
			dtlsSessions.put(addressToKey(peerAddress), session);
			handshaker = new ClientHandshaker(peerAddress, message, session, rootCerts, config);
			handshaker.setMaxFragmentLength(config.getMaxFragmentLength());
			
		} else {

			if (session.isActive()) {
				// session to peer is active, send encrypted message
				DTLSMessage fragment = new ApplicationMessage(message.getBytes());
				encryptedMessage = new Record(ContentType.APPLICATION_DATA, session.getWriteEpoch(), session.getSequenceNumber(), fragment, session);
				
			} else {
				// try resuming session
				handshaker = new ResumingClientHandshaker(peerAddress, message, session, rootCerts, config);
				handshaker.setMaxFragmentLength(config.getMaxFragmentLength());
			}
			
		}
		
		DTLSFlight flight = new DTLSFlight();
		// the CoAP message can not be encrypted since no session with peer
		// available, start DTLS handshake protocol
		if (handshaker != null) {
			// get starting handshake message
			handshakers.put(addressToKey(peerAddress), handshaker);
			if (LOGGER.isLoggable(Level.FINEST)) {
				LOGGER.finest("Stored handshaker on send: " + handshaker.toString() + " for " + peerAddress.toString());
			}
			flight = handshaker.getStartHandshakeMessage();
			flights.put(addressToKey(peerAddress), flight);
			scheduleRetransmission(flight);
		}
		
		// the CoAP message has been encrypted and can be sent to the peer
		if (encryptedMessage != null) {
			flight.addMessage(encryptedMessage);
		}
		
		flight.setPeerAddress(peerAddress);
		flight.setSession(session);
		sendFlight(flight);
	}
	
	/**
	 * Searches through all stored sessions and returns that session which
	 * matches the session identifier or <code>null</code> if no such session
	 * available. This method is used when the server receives a
	 * {@link ClientHello} containing a session identifier indicating that the
	 * client wants to resume a previous session. If a matching session is
	 * found, the server will resume the session with a abbreviated handshake,
	 * otherwise a full handshake (with new session identifier in
	 * {@link ServerHello}) is conducted.
	 * 
	 * @param sessionID
	 *            the client's session identifier.
	 * @return the session which matches the session identifier or
	 *         <code>null</code> if no such session exists.
	 */
	private DTLSSession getSessionByIdentifier(byte[] sessionID) {
		if (sessionID == null) {
			return null;
		}
		
		for (Entry<String, DTLSSession> entry : dtlsSessions.entrySet()) {
			// FIXME session identifiers may not be set, when the handshake failed after the initial message
			// these sessions must be deleted when this happens
			try {
				byte[] id = entry.getValue().getSessionIdentifier().getSessionId();
				if (Arrays.equals(sessionID, id)) {
					return entry.getValue();
				}
			} catch (Exception e) {
				continue;
			}
		}
		
		for (DTLSSession session:dtlsSessions.values()) {
			try {
				byte[] id = session.getSessionIdentifier().getSessionId();
				if (Arrays.equals(sessionID, id)) {
					return session;
				}
			} catch (Exception e) {
				continue;
			}
		}
		
		return null;
	}
	
	private void sendFlight(DTLSFlight flight) {
		byte[] payload = new byte[] {};
		
		// put as many records into one datagram as allowed by the block size
		List<DatagramPacket> datagrams = new ArrayList<DatagramPacket>();

		for (Record record : flight.getMessages()) {
			if (flight.getTries() > 0) {
				// adjust the record sequence number
				int epoch = record.getEpoch();
				record.setSequenceNumber(flight.getSession().getSequenceNumber(epoch));
			}
			
			byte[] recordBytes = record.toByteArray();
			if (payload.length + recordBytes.length > config.getMaxPayloadSize()) {
				// can't add the next record, send current payload as datagram
				DatagramPacket datagram = new DatagramPacket(payload, payload.length, flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
				datagrams.add(datagram);
				payload = new byte[] {};
			}

			// retrieve payload
			payload = ByteArrayUtils.concatenate(payload, recordBytes);
		}
		DatagramPacket datagram = new DatagramPacket(payload, payload.length, flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
		datagrams.add(datagram);

		// send it over the UDP socket
		try {
			for (DatagramPacket datagramPacket : datagrams) {
				socket.send(datagramPacket);
			}
			
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Could not send the datagram", e);
		}
	}
	
	private void handleTimeout(DTLSFlight flight) {

		// set DTLS retransmission maximum
		final int max = config.getMaxRetransmit();

		// check if limit of retransmissions reached
		if (flight.getTries() < max) {

			flight.incrementTries();

			sendFlight(flight);

			// schedule next retransmission
			scheduleRetransmission(flight);

		} else {
			LOGGER.fine("Maximum retransmissions reached.");
		}
	}

	private void scheduleRetransmission(DTLSFlight flight) {

		// cancel existing schedule (if any)
		if (flight.getRetransmitTask() != null) {
			flight.getRetransmitTask().cancel();
		}
		
		if (flight.isRetransmissionNeeded()) {
			// create new retransmission task
			flight.setRetransmitTask(new RetransmitTask(flight));
	
			// calculate timeout using exponential back-off
			if (flight.getTimeout() == 0) {
				// use initial timeout
				flight.setTimeout(config.getRetransmissionTimeout());
			} else {
				// double timeout
				flight.incrementTimeout();
			}
	
			// schedule retransmission task
			timer.schedule(flight.getRetransmitTask(), flight.getTimeout());
		}
	}
	
	/**
	 * Cancels the retransmission timer of the previous flight (if available).
	 * 
	 * @param peerAddress
	 *            the peer's address.
	 */
	private void cancelPreviousFlight(InetSocketAddress peerAddress) {
		DTLSFlight previousFlight = flights.get(addressToKey(peerAddress));
		if (previousFlight != null) {
			previousFlight.getRetransmitTask().cancel();
			previousFlight.setRetransmitTask(null);
			flights.remove(addressToKey(peerAddress));
		}
	}

	@Override
	public String getName() {
		return "DTLS";
	}

	public InetSocketAddress getAddress() {
		if (socket == null) return getLocalAddr();
		else return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}
	
	private class RetransmitTask extends TimerTask {

		private DTLSFlight flight;

		RetransmitTask(DTLSFlight flight) {
			this.flight = flight;
		}

		@Override
		public void run() {
			handleTimeout(flight);
		}
	}
	
	private String addressToKey(InetSocketAddress address) {
		return address.toString().split("/")[1];
	}


    public DTLSConnectorConfig getConfig() {
        return config;
    }
}
