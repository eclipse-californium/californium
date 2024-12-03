/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.scandium.dtls.ServerKeyExchange;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalSignature;

/**
 * The ASN.1 signatures.
 * <p>
 * See
 * <a href="https://tools.ietf.org/html/rfc4492#section-5.4" target="_blank">
 * RFC 4492, section 5.4 Server Key Exchange</a> for details regarding the
 * message format.
 * <p>
 * According <a href="https://tools.ietf.org/html/rfc8422#section-5.1.1" target=
 * "_blank">RFC 8422, 5.1.1. Supported Elliptic Curves Extension</a> only "named
 * curves" are valid, the "prime" and "char2" curve descriptions are deprecated.
 * Also only "UNCOMPRESSED" as point format is valid, the other formats have
 * been deprecated.
 * 
 * @since 3.13
 */
public final class SignedMessage {

	private static final int HASH_ALGORITHM_BITS = 8;
	private static final int SIGNATURE_ALGORITHM_BITS = 8;
	private static final int SIGNATURE_LENGTH_BITS = 16;

	private final byte[] signatureEncoded;

	/**
	 * The signature and hash algorithm which must be included into the
	 * digitally-signed struct.
	 */
	private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;

	/**
	 * Called when reconstructing from the byte array.
	 * 
	 * @param signatureAndHashAlgorithm the algorithm to use
	 * @param signatureEncoded the signature (encoded)
	 * @throws NullPointerException if only one of the parameters
	 *             signatureAndHashAlgorithm and signatureEncoded is
	 *             {@code null}, or any of the other parameters
	 */
	private SignedMessage(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] signatureEncoded) {
		if (signatureAndHashAlgorithm == null) {
			throw new NullPointerException("signature and hash algorithm cannot be null");
		}
		if (signatureEncoded == null) {
			throw new NullPointerException("signature cannot be null");
		}
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
		this.signatureEncoded = signatureEncoded;
	}

	/**
	 * Read signed message from reader.
	 * 
	 * @param reader reader to read signed message
	 * @return signed message
	 */
	public static SignedMessage fromReader(DatagramReader reader) {
		int hashAlgorithm = reader.read(HASH_ALGORITHM_BITS);
		int signatureAlgorithm = reader.read(SIGNATURE_ALGORITHM_BITS);
		SignatureAndHashAlgorithm signAndHash = new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
		byte[] signatureEncoded = reader.readVarBytes(SIGNATURE_LENGTH_BITS);
		return new SignedMessage(signAndHash, signatureEncoded);
	}

	/**
	 * Called by the client after receiving the server's
	 * {@link ServerKeyExchange} message. Verifies the contained signature.
	 * 
	 * @param serverPublicKey the server's public key.
	 * @param data data to sign.
	 * @throws GeneralSecurityException if the signature could not be verified.
	 */
	public void verifySignature(PublicKey serverPublicKey, byte[]... data) throws GeneralSecurityException {
		ThreadLocalSignature localSignature = signatureAndHashAlgorithm.getThreadLocalSignature();
		Signature signature = localSignature.currentWithCause();
		signature.initVerify(serverPublicKey);
		for (byte[] d : data) {
			if (d != null) {
				signature.update(d);
			}
		}
		if (signature.verify(signatureEncoded)) {
			if (JceProviderUtil.isEcdsaVulnerable()
					&& signatureAndHashAlgorithm.getSignature() == SignatureAlgorithm.ECDSA) {
				Asn1DerDecoder.checkEcDsaSignature(signatureEncoded, serverPublicKey);
			}
			return;
		}
		throw new GeneralSecurityException("Signature verification failed!");
	}
}
