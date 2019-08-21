/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.util.PskUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ClientHandshaker does the protocol handshaking from the point of view of a
 * client. It is driven by handshake messages as delivered by the parent
 * {@link Handshaker} class. The client doesn't send a CCS and uses a FINISH
 * with epoch 0.
 */
public class AdversaryClientHandshaker extends ClientHandshaker {

	private static final Logger LOGGER = LoggerFactory.getLogger(AdversaryClientHandshaker.class.getName());

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a server.
	 * 
	 * @param session the session to negotiate with the server.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration.
	 * @param maxTransmissionUnit the MTU value reported by the network
	 *            interface the record layer is bound to.
	 * @throws IllegalStateException if the message digest required for
	 *             computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException if session, recordLayer or config is
	 *             <code>null</code>
	 */
	public AdversaryClientHandshaker(DTLSSession session, RecordLayer recordLayer, Connection connection,
			DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(session, recordLayer, connection, config, maxTransmissionUnit);
	}

	// Methods ////////////////////////////////////////////////////////

	/**
	 * {@inheritDoc} This implementation doesn't send a CCS and uses a FINISH
	 * with epoch 0 (not encrypted).
	 */
	@Override
	protected void receivedServerHelloDone(ServerHelloDone message)
			throws HandshakeException, GeneralSecurityException {

		if (serverHelloDone != null && (serverHelloDone.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}
		serverHelloDone = message;
		flightNumber += 2;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);

		createCertificateMessage(flight);

		/*
		 * Second, send ClientKeyExchange as specified by the key exchange
		 * algorithm.
		 */
		ClientKeyExchange clientKeyExchange;
		byte[] premasterSecret;
		switch (getKeyExchangeAlgorithm()) {
		case EC_DIFFIE_HELLMAN:
			clientKeyExchange = new ECDHClientKeyExchange(ecdhe.getPublicKey(), session.getPeer());
			premasterSecret = ecdhe.getSecret(ephemeralServerPublicKey).getEncoded();
			generateKeys(premasterSecret);
			break;
		case PSK:
			PskUtil pskUtilPlain = new PskUtil(sniEnabled, session, pskStore);
			LOGGER.debug("Using PSK identity: {}", pskUtilPlain.getPskPrincipal());
			session.setPeerIdentity(pskUtilPlain.getPskPrincipal());
			clientKeyExchange = new PSKClientKeyExchange(pskUtilPlain.getPskPublicIdentity(), session.getPeer());
			premasterSecret = generatePremasterSecretFromPSK(pskUtilPlain.getPreSharedKey(), null);
			generateKeys(premasterSecret);
			break;
		case ECDHE_PSK:
			PskUtil pskUtil = new PskUtil(sniEnabled, session, pskStore);
			LOGGER.debug("Using PSK identity: {}", pskUtil.getPskPrincipal());
			session.setPeerIdentity(pskUtil.getPskPrincipal());
			clientKeyExchange = new EcdhPskClientKeyExchange(pskUtil.getPskPublicIdentity(), ecdhe.getPublicKey(),
					session.getPeer());
			byte[] otherSecret = ecdhe.getSecret(ephemeralServerPublicKey).getEncoded();
			premasterSecret = generatePremasterSecretFromPSK(pskUtil.getPreSharedKey(), otherSecret);
			generateKeys(premasterSecret);
			break;

		default:
			throw new HandshakeException("Unknown key exchange algorithm: " + getKeyExchangeAlgorithm(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		}
		wrapMessage(flight, clientKeyExchange);

		/*
		 * Third, send CertificateVerify message if necessary.
		 */
		if (certificateRequest != null && negotiatedSignatureAndHashAlgorithm != null) {
			// prepare handshake messages
			DatagramWriter handshakeMessages = new DatagramWriter(2048);
			handshakeMessages.writeBytes(clientHello.toByteArray());
			handshakeMessages.writeBytes(serverHello.toByteArray());
			handshakeMessages.writeBytes(serverCertificate.toByteArray());
			handshakeMessages.writeBytes(serverKeyExchange.toByteArray());
			handshakeMessages.writeBytes(certificateRequest.toByteArray());
			handshakeMessages.writeBytes(serverHelloDone.toByteArray());
			handshakeMessages.writeBytes(clientCertificate.toByteArray());
			handshakeMessages.writeBytes(clientKeyExchange.toByteArray());

			certificateVerify = new CertificateVerify(negotiatedSignatureAndHashAlgorithm, privateKey,
					handshakeMessages.toByteArray(), session.getPeer());

			wrapMessage(flight, certificateVerify);
		}

		/*
		 * Fourth, send ChangeCipherSpec, dropped !
		 */
		/*
		 * ChangeCipherSpecMessage changeCipherSpecMessage = new
		 * ChangeCipherSpecMessage(session.getPeer()); wrapMessage(flight,
		 * changeCipherSpecMessage); setCurrentWriteState();
		 */

		/*
		 * Fifth, send the finished message.
		 */
		// create hash of handshake messages
		// can't do this on the fly, since there is no explicit ordering of
		// messages
		md.update(clientHello.toByteArray());
		md.update(serverHello.toByteArray());
		if (serverCertificate != null) {
			md.update(serverCertificate.toByteArray());
		}
		if (serverKeyExchange != null) {
			md.update(serverKeyExchange.toByteArray());
		}
		if (certificateRequest != null) {
			md.update(certificateRequest.toByteArray());
		}
		md.update(serverHelloDone.toByteArray());

		if (clientCertificate != null) {
			md.update(clientCertificate.toByteArray());
		}
		md.update(clientKeyExchange.toByteArray());

		if (certificateVerify != null) {
			md.update(certificateVerify.toByteArray());
		}

		MessageDigest mdWithClientFinished = null;
		try {
			mdWithClientFinished = (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException("Cannot create FINISHED message",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, message.getPeer()));
		}

		handshakeHash = md.digest();
		Finished finished = new Finished(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(),
				session.getMasterSecret(), isClient, handshakeHash, session.getPeer());
		wrapMessage(flight, finished);

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();
		sendFlight(flight);
	}

	public void sendApplicationData(byte[] data) throws GeneralSecurityException {
		DTLSFlight flight = new DTLSFlight(getSession(), 100);
		Record record = new Record(ContentType.APPLICATION_DATA, session.getWriteEpoch(), session.getSequenceNumber(),
				new ApplicationMessage(data, session.getPeer()), session, true, 0);
		flight.addMessage(record);
		sendFlight(flight);
	}
}
