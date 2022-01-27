/*******************************************************************************
 * Copyright (c) 2022 RISE and others.
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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.eclipse.californium.elements.util.Bytes;

/**
 * Class for encoding the bytes of an OSCORE CoAP option.
 * 
 * See the structure of the option:
 * https://datatracker.ietf.org/doc/html/rfc8613#section-6.1
 * 
 */
public class OscoreOptionEncoder {

	private boolean encoded;
	private byte[] encodedBytes;

	private byte[] idContext;
	private byte[] partialIV;
	private byte[] kid;

	/**
	 * Retrieve the encoded bytes of the OSCORE option.
	 * 
	 * @return the encoded OSCORE option bytes
	 */
	public byte[] getBytes() {
		if (!encoded) {
			encodedBytes = encode();
		}

		return encodedBytes;
	}

	/**
	 * Encode the set parameters into the bytes of the OSCORE option.
	 * 
	 * @return the bytes of the OSCORE option
	 */
	private byte[] encode() {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();

		boolean hasContextID = this.idContext != null;
		boolean hasPartialIV = this.partialIV != null;
		boolean hasKid = this.kid != null;

		// If the Context ID should be included, set its bit
		if (hasContextID) {
			firstByte = firstByte | 0x10;
		}

		// If the KID should be included, set its bit
		if (hasKid) {
			firstByte = firstByte | 0x08; // Set the KID bit
		}

		// If the Partial IV should be included, encode it
		if (hasPartialIV) {
			byte[] partialIV = this.partialIV;
			firstByte = firstByte | (partialIV.length & 0x07);

			bRes.write(firstByte);
			try {
				bRes.write(partialIV);
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			bRes.write(firstByte);
		}

		// Encode the Context ID length and value if to be included
		if (hasContextID) {
			try {
				bRes.write(this.idContext.length);
				bRes.write(this.idContext);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Encode Sender ID (KID)
		if (hasKid) {
			try {
				bRes.write(this.kid);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Set the option as encoded
		encoded = true;

		// If the OSCORE option is length 1 and 0x00, it should be empty
		// https://tools.ietf.org/html/draft-ietf-core-object-security-16#section-2
		byte[] optionBytes = bRes.toByteArray();
		if (optionBytes.length == 1 && optionBytes[0] == 0x00) {
			return Bytes.EMPTY;
		} else {
			return optionBytes;
		}
	}

	/**
	 * Retrieve the set ID Context
	 * 
	 * @return the ID Context (kid context)
	 */
	public byte[] getIdContext() {
		return idContext;
	}

	/**
	 * Set the ID Context
	 * 
	 * @param idContext the ID Context (kid context) to set
	 */
	public void setIdContext(byte[] idContext) {
		encoded = false;
		this.idContext = idContext;
	}

	/**
	 * Retrieve the set Partial IV
	 * 
	 * @return the Partial IV
	 */
	public byte[] getPartialIV() {
		return partialIV;
	}

	/**
	 * Set the Partial IV
	 * 
	 * @param partialIV the Partial IV to set
	 */
	public void setPartialIV(byte[] partialIV) {
		encoded = false;
		this.partialIV = partialIV;
	}

	/**
	 * Set the Partial IV (based on an integer sequence number)
	 * 
	 * @param senderSeq the sequence number to set as Partial IV
	 */
	public void setPartialIV(int senderSeq) {
		encoded = false;
		this.partialIV = OSSerializer.processPartialIV(senderSeq);
	}

	/**
	 * Retrieve the set KID
	 * 
	 * @return the KID
	 */
	public byte[] getKid() {
		return kid;
	}

	/**
	 * Set the KID
	 * 
	 * @param kid the KID to set
	 */
	public void setKid(byte[] kid) {
		encoded = false;
		this.kid = kid;
	}

}
