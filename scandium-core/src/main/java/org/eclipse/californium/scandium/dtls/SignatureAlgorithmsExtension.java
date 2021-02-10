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
	// DTLS-specific constants ////////////////////////////////////////

	private static final int LIST_LENGTH_BITS = 16;

	private static final int SIGNATURE_ALGORITHM_BITS = 16;

	private static final int SIGNATURE_BITS = 8;

	private static final int HASH_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	/** The list holding the supported signature and hash algorithms */

	private final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;

	// Constructor ////////////////////////////////////////////////////

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

	// Serialization //////////////////////////////////////////////////

	@Override
	protected void addExtensionData(DatagramWriter writer) {
		int listLength = signatureAndHashAlgorithms.size() * (SIGNATURE_ALGORITHM_BITS / Byte.SIZE);
		writer.write(listLength + (LIST_LENGTH_BITS / Byte.SIZE), LENGTH_BITS);
		writer.write(listLength, LIST_LENGTH_BITS);

		for (SignatureAndHashAlgorithm signatureAndHashAlgorithm : signatureAndHashAlgorithms) {
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), HASH_BITS);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), SIGNATURE_BITS);
		}
	}

	public static HelloExtension fromExtensionDataReader(DatagramReader extensionDataReader) {

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

	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getLength() {
		// fixed: type (2 bytes), length (2 bytes), list length (2 bytes)
		// variable: number of signature algorithms * 2 (1 byte for signature
		// algorithm, 1 byte for hash algorithm )
		return 6 + (signatureAndHashAlgorithms.size() * (SIGNATURE_ALGORITHM_BITS / Byte.SIZE));
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append("\t\t\t\tLength: ").append(getLength() - 4);
		sb.append(StringUtil.lineSeparator()).append("\t\t\t\tSignature Algorithms Length: ").append(getLength() - 6);
		sb.append(StringUtil.lineSeparator()).append("\t\t\t\tSignature Algorithms (")
				.append(signatureAndHashAlgorithms.size()).append(" algorithm):");

		for (SignatureAndHashAlgorithm signatureAndHashAlgoritm : signatureAndHashAlgorithms) {
			sb.append(StringUtil.lineSeparator()).append("\t\t\t\t\tSignature Algorithm: ");
			sb.append(StringUtil.lineSeparator()).append("\t\t\t\t\t\tSignature Hash Algorithm Hash: ");
			if (signatureAndHashAlgoritm.getHash() != null) {
				sb.append(signatureAndHashAlgoritm.getHash());
			} else {
				sb.append("unknown");
			}
			sb.append(StringUtil.lineSeparator()).append("\t\t\t\t\t\tSignature Hash Algorithm Signature: ");
			if (signatureAndHashAlgoritm.getSignature() != null) {
				sb.append(signatureAndHashAlgoritm.getSignature());
			} else {
				sb.append("unknown");
			}
		}
		sb.append(StringUtil.lineSeparator());
		return sb.toString();
	}

	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
		return signatureAndHashAlgorithms;
	}
}
