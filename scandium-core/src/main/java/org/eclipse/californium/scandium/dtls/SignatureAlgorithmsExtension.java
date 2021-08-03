/*******************************************************************************
 * Copyright (c) 2020 Softech and others.
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
 *    Softech - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Implements the hello extension for signature and hash algorithms.
 * 
 * @since 2.3
 */
public class SignatureAlgorithmsExtension extends HelloExtension {

	private static final int LIST_LENGTH_BITS = 16;

	private static final int SIGNATURE_ALGORITHM_BITS = 16;

	private static final int SIGNATURE_BITS = 8;

	private static final int HASH_BITS = 8;

	/** The list holding the supported signature and hash algorithms */

	private final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;

	/**
	 * Creates an instance using the signature algorithms and the hash
	 * algorithms codes
	 * 
	 * @param signatureAndHashAlgorithms list of signature algorithms and hash
	 *            algorithms to be used by the extension.
	 */
	public SignatureAlgorithmsExtension(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
		super(ExtensionType.SIGNATURE_ALGORITHMS);
		this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
	}

	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
		return signatureAndHashAlgorithms;
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		String indentation2 = StringUtil.indentation(indent + 2);
		sb.append(indentation).append("Signature Algorithms (").append(signatureAndHashAlgorithms.size())
				.append(" algorithms):").append(StringUtil.lineSeparator());

		for (SignatureAndHashAlgorithm signatureAndHashAlgoritm : signatureAndHashAlgorithms) {
			sb.append(indentation2).append("Signature and Hash Algorithm: ").append(signatureAndHashAlgoritm)
					.append(StringUtil.lineSeparator());
		}
		return sb.toString();
	}

	@Override
	protected int getExtensionLength() {
		// fixed: list length (2 bytes)
		// variable: number of signature algorithms * 2 (1 byte for signature
		// algorithm, 1 byte for hash algorithm )
		return (LIST_LENGTH_BITS / Byte.SIZE)
				+ (signatureAndHashAlgorithms.size() * (SIGNATURE_ALGORITHM_BITS / Byte.SIZE));
	}

	@Override
	protected void writeExtensionTo(DatagramWriter writer) {
		int listLength = signatureAndHashAlgorithms.size() * (SIGNATURE_ALGORITHM_BITS / Byte.SIZE);
		writer.write(listLength, LIST_LENGTH_BITS);

		for (SignatureAndHashAlgorithm signatureAndHashAlgorithm : signatureAndHashAlgorithms) {
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), HASH_BITS);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), SIGNATURE_BITS);
		}
	}

	public static SignatureAlgorithmsExtension fromExtensionDataReader(DatagramReader extensionDataReader) {

		List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = new ArrayList<SignatureAndHashAlgorithm>();
		int listLength = extensionDataReader.read(LIST_LENGTH_BITS);
		DatagramReader rangeReader = extensionDataReader.createRangeReader(listLength);
		while (rangeReader.bytesAvailable()) {
			int hashId = rangeReader.read(HASH_BITS);
			int signatureId = rangeReader.read(SIGNATURE_BITS);

			signatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(hashId, signatureId));
		}
		signatureAndHashAlgorithms = Collections.unmodifiableList(signatureAndHashAlgorithms);
		return new SignatureAlgorithmsExtension(signatureAndHashAlgorithms);
	}

}
