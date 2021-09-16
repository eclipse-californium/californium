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
	 * @param context the DTLS context to negotiate with the server.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission (since 2.4).
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration.
	 * @throws IllegalStateException if the message digest required for
	 *             computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException if session, recordLayer or config is
	 *             {@code null}
	 */
	public AdversaryClientHandshaker(DTLSSession session, RecordLayer recordLayer, ScheduledExecutorService timer, Connection connection,
			DtlsConnectorConfig config) {
		super(null, recordLayer, timer, connection, config, false);
		getSession().set(session);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected void completeProcessingServerHelloDone() throws HandshakeException {

		DTLSSession session = getSession();
		if (session.getCipherSuite().isEccBased()) {
			expectEcc();
		}

		/*
		 * Third, send CertificateVerify message if necessary.
		 */
		SignatureAndHashAlgorithm negotiatedSignatureAndHashAlgorithm = session.getSignatureAndHashAlgorithm();
		if (negotiatedSignatureAndHashAlgorithm != null) {
			// valid negotiated signature and hash algorithm
			// prepare certificate verify message
			CertificateVerify certificateVerify = new CertificateVerify(negotiatedSignatureAndHashAlgorithm, privateKey,
					handshakeMessages);
			wrapMessage(flight5, certificateVerify);
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
		MessageDigest mdWithClientFinished = cloneMessageDigest(md);

		Finished finished = createFinishedMessage(md.digest());
		wrapMessage(flight5, finished);

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();
		sendFlight(flight5);
		expectChangeCipherSpecMessage();
	}

	public void sendApplicationData(final byte[] data) {
		DTLSFlight flight = new DTLSFlight(getDtlsContext(), 100, getPeerAddress()) {
			public List<Record> getRecords(int maxDatagramSize, int maxFragmentSize, boolean useMultiHandshakeMessageRecords)
					throws HandshakeException {
				try {
					DTLSContext context = getDtlsContext();
					Record record = new Record(ContentType.APPLICATION_DATA, context.getWriteEpoch(), new ApplicationMessage(data),
							context, true, 0);
					return Arrays.asList(record);
				} catch (GeneralSecurityException e) {
					throw new HandshakeException("Cannot create record",
							new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR), e);
				}
			}
		};
		sendFlight(flight);
	}
}
