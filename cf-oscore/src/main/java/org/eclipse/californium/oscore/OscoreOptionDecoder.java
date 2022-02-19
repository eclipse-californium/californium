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

import java.util.Arrays;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.elements.util.DatagramReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class for decoding the bytes of an OSCORE CoAP option.
 * 
 * See the structure of the option:
 * https://datatracker.ietf.org/doc/html/rfc8613#section-6.1
 * 
 */
public class OscoreOptionDecoder {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OscoreOptionDecoder.class);

	private byte[] encodedBytes;

	private byte[] idContext;
	private byte[] partialIV;
	private byte[] kid;

	private int n;
	private int k;
	private int h;

	/**
	 * Initialize the OSCORE option with a certain array of bytes and decode
	 * them into the parameters of the option.
	 * 
	 * @param encodedBytes the encoded bytes of the option
	 * @throws CoapOSException if the option is malformed
	 */
	public OscoreOptionDecoder(byte[] encodedBytes) throws CoapOSException {
		this.encodedBytes = encodedBytes;
		decode();
	}

	/**
	 * Set the OSCORE option to a certain array of bytes and decode them into
	 * the parameters of the option.
	 * 
	 * @param encodedBytes the encoded bytes of the option
	 * @throws CoapOSException if the option is malformed
	 */
	public void setBytes(byte[] encodedBytes) throws CoapOSException {
		this.encodedBytes = encodedBytes;
		decode();
	}

	/**
	 * Performs the decoding of the option and stores the resulting parameters
	 * in this object.
	 * 
	 * @throws CoapOSException if the option is malformed
	 */
	private void decode() throws CoapOSException {
		byte[] total = encodedBytes;

		/**
		 * If the OSCORE option value is a zero length byte array it represents
		 * a byte array of length 1 with a byte 0x00 See
		 * https://tools.ietf.org/html/draft-ietf-core-object-security-16#section-2
		 */
		if (total.length == 0) {
			total = new byte[] { 0x00 };
		}

		byte flagByte = total[0];

		int n = flagByte & 0x07;
		int k = (flagByte & 0x08) >> 3;
		int h = (flagByte & 0x10) >> 4;

		byte[] partialIV = null;
		byte[] kid = null;
		byte[] kidContext = null;
		int index = 1;

		try {
			// Parsing Partial IV
			if (n > 0) {
				partialIV = Arrays.copyOfRange(total, index, index + n);
				index += n;
			}
		} catch (Exception e) {
			LOGGER.error("Failed to parse Partial IV in OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		try {
			// Parsing KID Context
			if (h != 0) {
				int s = total[index++];

				kidContext = Arrays.copyOfRange(total, index, index + s);

				index += s;
			}
		} catch (Exception e) {
			LOGGER.error("Failed to parse KID Context in OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		try {
			// Parsing KID
			if (k != 0) {
				kid = Arrays.copyOfRange(total, index, total.length);
			}
		} catch (Exception e) {
			LOGGER.error("Failed to parse KID in OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		// Check option length consistency
		if (k == 0 && index != total.length) {
			// If KID is not present there should be no further data
			LOGGER.error("Extranous data at end of OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		// Store parsed data in this object
		this.n = n;
		this.k = k;
		this.h = h;
		this.partialIV = partialIV;
		this.kid = kid;
		this.idContext = kidContext;
	}

	/**
	 * Retrieve the ID Context
	 * 
	 * @return the ID Context (kid context)
	 */
	public byte[] getIdContext() {
		return idContext;
	}

	/**
	 * Retrieve the Partial IV
	 * 
	 * @return the Partial IV
	 */
	public byte[] getPartialIV() {
		return partialIV;
	}

	/**
	 * Retrieve the sequence number
	 * 
	 * @return the sequence number (based on the Partial IV)
	 */
	public int getSequenceNumber() {
		if (partialIV == null) {
			return 0;
		}

		return new DatagramReader(partialIV, false).read(partialIV.length * Byte.SIZE);
	}

	/**
	 * Retrieve the KID
	 * 
	 * @return the KID
	 */
	public byte[] getKid() {
		return kid;
	}

	/**
	 * Retrieve the n flag bit
	 * 
	 * @return the n bit (length of Partial IV)
	 */
	public int getN() {
		return n;
	}

	/**
	 * Retrieve the k flag bit
	 * 
	 * @return the k bit (if KID is present)
	 */
	public int getK() {
		return k;
	}

	/**
	 * Retrieve the h flag bit
	 * 
	 * @return the h bit (if ID Context is present)
	 */
	public int getH() {
		return h;
	}

}
