/*******************************************************************************
 * Copyright 2018 University of Rostock, Institute of Applied Microelectronics and Computer Engineering
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
 *    Vikram (University of Rostock)- Initial creation, adapted from ClientHandshaker
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extracts psk credentials from the current {@code DTLSSession}.
 */
public class PskUtil implements Destroyable {

	private static final Logger LOGGER = LoggerFactory.getLogger(PskUtil.class.getName());

	private final SecretKey pskSecret;

	private final PskPublicInformation pskIdentity;

	private final PreSharedKeyIdentity pskPrincipal;

	/**
	 * Retrieves preshared key identity and preshared key for the given dtls
	 * session from the psk store.
	 * 
	 * @param sniEnabled - {@code true} if SNI should be enabled for negotiating
	 *            the given session
	 * @param session - {@code DTLSSession}
	 * @param pskStore - {@code PskStore}
	 * @throws HandshakeException if no data is available for the provided
	 *             session
	 * @throws NullPointerException if either session or pskStore is
	 *             {@code null}
	 */
	public PskUtil(boolean sniEnabled, DTLSSession session, PskStore pskStore) throws HandshakeException {
		this(sniEnabled, session, pskStore, lookupIdentity(sniEnabled, session, pskStore));
	}

	/**
	 * Retrieves a preshared key for the given dtls session and identity from
	 * the psk store.
	 * 
	 * @param sniEnabled - {@code true} if SNI should be enabled for negotiating
	 *            the given session
	 * @param session - {@code DTLSSession}
	 * @param pskStore - {@code PskStore}
	 * @param pskIdentity - the identity received in the key exchange maessage.
	 * @throws HandshakeException if no data is available for the provided
	 *             identity
	 * @throws NullPointerException if either session, pskStore, or pskIdentity
	 *             is {@code null}
	 */
	public PskUtil(boolean sniEnabled, DTLSSession session, PskStore pskStore, PskPublicInformation pskIdentity)
			throws HandshakeException {
		if (session == null) {
			throw new NullPointerException("Dtls session must not be null");
		}
		if (pskStore == null) {
			throw new NullPointerException("psk store must not be null");
		}
		if (pskIdentity == null) {
			throw new NullPointerException("psk identity must not be null");
		}
		this.pskIdentity = pskIdentity;
		String virtualHostName = session.getVirtualHost();
		if (virtualHostName == null) {
			LOGGER.debug("client [{}] uses PSK identity [{}]", session.getPeer(), pskIdentity);
		} else {
			LOGGER.debug("client [{}] uses PSK identity [{}] for server [{}]", session.getPeer(), pskIdentity,
					virtualHostName);
		}
		ServerNames virtualHost = session.getServerNames();
		if (sniEnabled && virtualHost != null) {
			pskSecret = pskStore.getKey(virtualHost, pskIdentity);
		} else {
			pskSecret = pskStore.getKey(pskIdentity);
		}
		if (pskSecret == null) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_PSK_IDENTITY,
					session.getPeer());
			if (virtualHostName != null) {
				throw new HandshakeException(
						String.format("No pre-shared key found for [virtual host: %s, identity: %s]", virtualHostName,
								pskIdentity),
						alert);
			} else {
				throw new HandshakeException(String.format("No pre-shared key found for [identity: %s]", pskIdentity),
						alert);
			}
		}
		if (sniEnabled) {
			this.pskPrincipal = new PreSharedKeyIdentity(virtualHostName, pskIdentity.getPublicInfoAsString());
		} else {
			this.pskPrincipal = new PreSharedKeyIdentity(pskIdentity.getPublicInfoAsString());
		}
		session.setPeerIdentity(pskPrincipal);
	}

	/**
	 * Lookup identity for the provided session from the psk store.
	 * 
	 * @param sniEnabled - {@code true} if SNI should be enabled for negotiating
	 *            the given session
	 * @param session - {@code DTLSSession}
	 * @param pskStore - {@code PskStore}
	 * @return psk identity
	 * @throws HandshakeException if no data is available for the provided
	 *             session
	 */
	private static PskPublicInformation lookupIdentity(boolean sniEnabled, DTLSSession session, PskStore pskStore)
			throws HandshakeException {
		if (session == null) {
			throw new NullPointerException("Dtls session must not be null");
		}
		if (pskStore == null) {
			throw new NullPointerException("psk store must not be null");
		}
		PskPublicInformation pskIdentity;
		ServerNames virtualHost = session.getServerNames();
		if (sniEnabled && virtualHost != null) {
			if (!session.isSniSupported()) {
				LOGGER.warn(
						"client is configured to use SNI but server does not support it, PSK authentication is likely to fail");
			}
			// look up identity in scope of virtual host
			pskIdentity = pskStore.getIdentity(session.getPeer(), virtualHost);
			if (pskIdentity == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE,
						session.getPeer());
				throw new HandshakeException(String.format("No Identity found for peer [address: %s, virtual host: %s]",
						session.getPeer(), session.getVirtualHost()), alert);
			}
		} else {
			pskIdentity = pskStore.getIdentity(session.getPeer());
			if (pskIdentity == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE,
						session.getPeer());
				throw new HandshakeException(
						String.format("No Identity found for peer [address: %s]", session.getPeer()), alert);
			}
		}
		return pskIdentity;
	}

	/**
	 * This method returns the psk principal either for the virtual host hosted
	 * on session's peer or for the session's peer itself.
	 * 
	 * @return {@code PreSharedKeyIdentity}
	 */
	public PreSharedKeyIdentity getPskPrincipal() {
		return this.pskPrincipal;
	}

	/**
	 * Returns the PSK identity.
	 * 
	 * @return identity as public information
	 */
	public PskPublicInformation getPskPublicIdentity() {
		return this.pskIdentity;
	}

	/**
	 * The premaster secret is formed as follows: if the PSK is N octets long,
	 * concatenate a uint16 with the value N, N zero octets, a second uint16
	 * with the value N, and the PSK itself.
	 * 
	 * @param otherSecret - either is zeroes (plain PSK case) or comes from the
	 *            EC Diffie-Hellman exchange (ECDHE_PSK).
	 * @see <a href="http://tools.ietf.org/html/rfc4279#section-2">RFC 4279</a>
	 * @return byte array with generated premaster secret.
	 */
	public SecretKey generatePremasterSecretFromPSK(SecretKey otherSecret) {
		/*
		 * What we are building is the following with length fields in between:
		 * struct { opaque other_secret<0..2^16-1>; opaque psk<0..2^16-1>; };
		 */
		byte[] pskBytes = pskSecret.getEncoded();
		int pskLength = pskBytes.length;
		byte[] otherBytes = otherSecret != null ? otherSecret.getEncoded() : new byte[pskLength];
		DatagramWriter writer = new DatagramWriter(true);
		writer.write(otherBytes.length, 16);
		writer.writeBytes(otherBytes);
		writer.write(pskLength, 16);
		writer.writeBytes(pskBytes);
		byte[] secret = writer.toByteArray();
		writer.close();
		SecretKey premaster = SecretUtil.create(secret, "MAC");
		Bytes.clear(pskBytes);
		Bytes.clear(otherBytes);
		Bytes.clear(secret);
		return premaster;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(pskSecret);
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(pskSecret);
	}
}
