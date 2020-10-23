/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * ClientHandshaker does the protocol handshaking from the point of view of a
 * client. It is driven by handshake messages as delivered by the parent
 * {@link Handshaker} class. The client doesn't send a CCS and uses a FINISH
 * with epoch 0.
 */
public class AdversaryClientHandshaker extends ClientHandshaker {

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a server.
	 * 
	 * @param session the session to negotiate with the server.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission (since 2.4).
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration.
	 * @throws IllegalStateException if the message digest required for
	 *             computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException if session, recordLayer or config is
	 *             <code>null</code>
	 */
	public AdversaryClientHandshaker(DTLSSession session, RecordLayer recordLayer, ScheduledExecutorService timer, Connection connection,
			DtlsConnectorConfig config) {
		super(session, recordLayer, timer, connection, config, false);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected void processMasterSecret(SecretKey masterSecret) throws HandshakeException {
		DTLSFlight flight = createFlight();

		applyMasterSecret(masterSecret);

		createCertificateMessage(flight);

		wrapMessage(flight, clientKeyExchange);

		/*
		 * Third, send CertificateVerify message if necessary.
		 */
		if (certificateRequest != null && negotiatedSignatureAndHashAlgorithm != null) {
			CertificateType clientCertificateType = session.sendCertificateType();
			if (!isSupportedCertificateType(clientCertificateType, supportedClientCertificateTypes)) {
				throw new HandshakeException(
						"Server wants to use not supported client certificate type " + clientCertificateType,
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.ILLEGAL_PARAMETER,
								session.getPeer()));
			}

			// prepare handshake messages

			CertificateVerify certificateVerify = new CertificateVerify(negotiatedSignatureAndHashAlgorithm, privateKey, handshakeMessages, session.getPeer());

			wrapMessage(flight, certificateVerify);
		}

		/*
		 * Fourth, send ChangeCipherSpec, dropped !
		 */
//		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
//		wrapMessage(flight, changeCipherSpecMessage);
//		setCurrentWriteState();

		/*
		 * Fifth, send the finished message.
		 */
		// create hash of handshake messages
		// can't do this on the fly, since there is no explicit ordering of
		// messages
		MessageDigest md = getHandshakeMessageDigest();
		MessageDigest mdWithClientFinished;
		try {
			mdWithClientFinished = (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException(
					"Cannot create FINISHED message",
					new AlertMessage(
							AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
		}

		Finished finished = new Finished(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, isClient, md.digest(), session.getPeer());
		wrapMessage(flight, finished);

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();
		sendFlight(flight);
		expectChangeCipherSpecMessage();
	}

	public void sendApplicationData(final byte[] data) {
		DTLSFlight flight = new DTLSFlight(getSession(), 100) {
			public List<Record> getRecords(int maxDatagramSize, int maxFragmentSize, boolean useMultiHandshakeMessageRecords)
					throws HandshakeException {
				try {
					Record record = new Record(ContentType.APPLICATION_DATA, session.getWriteEpoch(), session.getSequenceNumber(),
							new ApplicationMessage(data, session.getPeer()), session, true, 0);
					return Arrays.asList(record);
				} catch (GeneralSecurityException e) {
					throw new HandshakeException("Cannot create record",
							new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()), e);
				}
			}
		};
		sendFlight(flight);
	}
}
