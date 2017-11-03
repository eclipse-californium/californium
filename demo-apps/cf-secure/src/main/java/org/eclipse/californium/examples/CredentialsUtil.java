/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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

package org.eclipse.californium.examples;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustAllRpks;

/**
 * Credentials utility for setup DTLS credentials.
 */
public class CredentialsUtil {

	/**
	 * Credentials mode.
	 */
	public enum Mode {
		/**
		 * Preshared secret keys.
		 */
		PSK,
		/**
		 * Raw public key certificates.
		 */
		RPK,
		/**
		 * X.509 certificates.
		 */
		X509,
		/**
		 * raw public key certificates just trusted (client only).
		 */
		RPK_TRUST,
		/**
		 * X.509 certificates just trusted (client only).
		 */
		X509_TRUST,
		/**
		 * No client authentication (server only).
		 */
		NO_AUTH,
	}

	/**
	 * Default list of modes.
	 * 
	 * Value is PSK, RPK, X509.
	 */
	public static final List<Mode> DEFAULT_MODES = Arrays.asList(new Mode[] { Mode.PSK, Mode.RPK, Mode.X509 });

	// from ETSI Plugtest test spec
	public static final String PSK_IDENTITY = "password";
	public static final byte[] PSK_SECRET = "sesame".getBytes();

	// from demo-certs
	public static final String SERVER_NAME = "server";
	public static final String CLIENT_NAME = "client";
	private static final String TRUST_NAME = "root";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

	/**
	 * Parse arguments to modes.
	 * 
	 * @param args arguments
	 * @param defaults default modes to use, if argument is empty or only
	 *            contains {@link Mode#NO_AUTH}.
	 * @param supported supported modes
	 * @return array of modes.
	 */
	public static List<Mode> parse(String[] args, List<Mode> defaults, List<Mode> supported) {
		List<Mode> modes;
		if (args.length == 0) {
			modes = new ArrayList<>();
			if (defaults != null) {
				modes.addAll(defaults);
			}
		} else {
			modes = new ArrayList<>(args.length);
			for (String mode : args) {
				try {
					modes.add(Mode.valueOf(mode));
				} catch (IllegalArgumentException ex) {
					throw new IllegalArgumentException("Argument '" + mode + "' unkown!");
				}
			}
		}
		if (supported != null) {
			for (Mode mode : modes) {
				if (!supported.contains(mode)) {
					throw new IllegalArgumentException("Mode '" + mode + "' not supported!");
				}
			}
		}
		// adjust default for "NO_AUTH"
		if (defaults != null && modes.size() == 1 && modes.contains(Mode.NO_AUTH)) {
			modes.addAll(defaults);
		}
		return modes;
	}

	/**
	 * Setup credentials for DTLS connector.
	 * 
	 * If PSK is provided and no PskStore is already set for the builder, a
	 * {@link InMemoryPskStore} containing {@link #PSK_IDENTITY} assigned with
	 * {@link #PSK_SECRET} is set. If PSK is provided with other mode(s) and
	 * loading the certificates failed, this is just treated as warning and the
	 * configuration is setup to use PSK only.
	 * 
	 * If RPK is provided, the certificates loaded for the provided alias and
	 * this certificate is used as identity.
	 * 
	 * If X509 is provided, the trusts are also loaded an set additionally to
	 * the credentials for the alias.
	 * 
	 * The Modes can be mixed. If RPK is before X509 in the list, RPK is set as
	 * preferred.
	 * 
	 * Examples:
	 * 
	 * <pre>
	 * PSK, RPK setup for PSK an RPK.
	 * RPK, X509 setup for RPK and X509, prefer RPK
	 * PSK, X509, RPK setup for PSK, RPK and X509, prefer X509
	 * </pre>
	 * 
	 * @param config DTLS configuration builder. May be already initialized with
	 *            PskStore.
	 * @param certificateAlias alias for certificate to load as credentials.
	 * @param modes list of supported mode. If a RPK is in the list before X509,
	 *            or RPK is provided but not X509, then the RPK is setup as
	 *            preferred.
	 * @throws IllegalArgumentException if loading the certificates fails for
	 *             some reason
	 */
	public static void setupCredentials(DtlsConnectorConfig.Builder config, String certificateAlias, List<Mode> modes) {

		boolean psk = modes.contains(Mode.PSK);
		if (psk && config.getIncompleteConfig().getPskStore() == null) {
			// Pre-shared secret keys
			InMemoryPskStore pskStore = new InMemoryPskStore();
			pskStore.setKey(PSK_IDENTITY, PSK_SECRET);
			config.setPskStore(pskStore);
		}
		boolean x509Trust = modes.contains(Mode.X509_TRUST);
		int x509 = modes.indexOf(Mode.X509);
		int rpk = modes.indexOf(Mode.RPK);

		if (x509 >= 0 || rpk >= 0 || x509Trust) {
			SslContextUtil.Credentials serverCredentials = null;
			Certificate[] trustedCertificates = null;

			try {
				// try to read certificates
				serverCredentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
						certificateAlias, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
				if (x509 >= 0 || x509Trust) {
					trustedCertificates = SslContextUtil.loadTrustedCertificates(
							SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, TRUST_NAME, TRUST_STORE_PASSWORD);
					if (x509 >= 0) {
						config.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
								rpk >= 0 && rpk < x509);
					}
					config.setTrustStore(trustedCertificates);
				} else {
					config.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
							true);
				}
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
				System.err.println("certificates are invalid!");
				if (psk) {
					System.err.println("Therefore certificates are not supported!");
				} else {
					throw new IllegalArgumentException(e.getMessage());
				}
			} catch (IOException e) {
				e.printStackTrace();
				System.err.println("certificates are missing!");
				if (psk) {
					System.err.println("Therefore certificates are not supported!");
				} else {
					throw new IllegalArgumentException(e.getMessage());
				}
			}
		}
		if (modes.contains(Mode.RPK_TRUST)) {
			config.setRpkTrustStore(new TrustAllRpks());
		}
		if (modes.contains(Mode.NO_AUTH)) {
			config.setClientAuthenticationRequired(false);
		}
	}
}
