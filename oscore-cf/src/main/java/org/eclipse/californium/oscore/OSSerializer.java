/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.elements.util.DatagramWriter;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * Implements methods for serializing OSCORE data, creating AAD, reading data
 * and generating nonce.
 *
 */
public class OSSerializer {

	private static final byte[] ONE_ZERO = new byte[] { 0x00 };
	private static final byte[] EMPTY = new byte[0];
	private static final byte[] ZEROS = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00 };

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OSSerializer.class.getName());

	/**
	 * Prepare options and payload for encrypting.
	 * 
	 * @param options the options
	 * 
	 * @param payload the payload
	 * 
	 * @return the serialized plaintext for OSCore
	 */
	public static byte[] serializeConfidentialData(OptionSet options, byte[] payload, int realCode) {
		if (options != null) {
			DatagramWriter writer = new DatagramWriter();
			if (realCode > 0) {
				OptionSet filteredOptions = OptionJuggle.prepareEoptions(options);
				writer.write(realCode, CoAP.MessageFormat.CODE_BITS);
				DataSerializer.serializeOptionsAndPayload(writer, filteredOptions, payload);
				return writer.toByteArray();
			} else {
				LOGGER.error(ErrorDescriptions.COAP_CODE_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.COAP_CODE_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
			throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
		}
	}

	/**
	 * Prepare the additional authenticated data of a response to be sent.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param ctx the OSCore context
	 * @param options the option set
	 * 
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeSendResponseAAD(int version, OSCoreCtx ctx, OptionSet options, boolean newPartialIV) {
		if (version == CoAP.VERSION) {
			if (ctx != null) {
				if (options != null) {
					CBORObject algorithms = CBORObject.NewArray();
					algorithms.Add(ctx.getAlg().AsCBOR());

					CBORObject aad = CBORObject.NewArray();
					aad.Add(version);
					aad.Add(algorithms);
					aad.Add(ctx.getRecipientId());

					if (newPartialIV) {
						aad.Add(processPartialIV(ctx.getSenderSeq()));
					} else {
						aad.Add(processPartialIV(ctx.getReceiverSeq()));
					}

					return aad.EncodeToBytes();
				} else {
					LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
					throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.CTX_NULL);
				throw new NullPointerException(ErrorDescriptions.CTX_NULL);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}

	/**
	 * Prepare the additional authenticated data of a received response.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param seq the sequence number
	 * @param ctx the OSCore context
	 * @param options the option set
	 * 
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeReceiveResponseAAD(int version, int seq, OSCoreCtx ctx, OptionSet options) {
		if (version == CoAP.VERSION) {
			if (seq > -1) {
				if (ctx != null) {
					if (options != null) {
						CBORObject algorithms = CBORObject.NewArray();
						algorithms.Add(ctx.getAlg().AsCBOR());

						CBORObject aad = CBORObject.NewArray();
						aad.Add(version);
						aad.Add(algorithms);
						aad.Add(ctx.getSenderId());
						aad.Add(processPartialIV(seq));
						return aad.EncodeToBytes();
					} else {
						LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
						throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
					}
				} else {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new NullPointerException(ErrorDescriptions.CTX_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SEQ_NBR_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.SEQ_NBR_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}

	/**
	 * Prepare the additional authenticated data of a request to be sent.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param ctx the OSCore context@param code
	 * @param options the option set
	 * 
	 *
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeSendRequestAAD(int version, OSCoreCtx ctx, OptionSet options) {
		if (version == CoAP.VERSION) {
			if (ctx != null) {
				if (options != null) {
					CBORObject algorithms = CBORObject.NewArray();
					algorithms.Add(ctx.getAlg().AsCBOR());

					CBORObject aad = CBORObject.NewArray();
					aad.Add(version);
					aad.Add(algorithms);
					aad.Add(ctx.getSenderId());
					aad.Add(processPartialIV(ctx.getSenderSeq()));
					return aad.EncodeToBytes();
				} else {
					LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
					throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.CTX_NULL);
				throw new NullPointerException(ErrorDescriptions.CTX_NULL);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}

	/**
	 * Prepare the additional authenticated data of a received request.
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_seq :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param seq the sent sequence number
	 * @param ctx the OSCore context@param code
	 * @param options the option set
	 * 
	 *
	 * @return the serialized AAD for OSCore
	 */
	public static byte[] serializeReceiveRequestAAD(int version, int seq, OSCoreCtx ctx, OptionSet options) {
		if (version == CoAP.VERSION) {
			if (seq > -1) {
				if (ctx != null) {
					if (options != null) {
						CBORObject algorithms = CBORObject.NewArray();
						algorithms.Add(ctx.getAlg().AsCBOR());

						CBORObject aad = CBORObject.NewArray();
						aad.Add(version);
						aad.Add(algorithms);
						aad.Add(ctx.getRecipientId());
						aad.Add(processPartialIV(seq));
						return aad.EncodeToBytes();
					} else {
						LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
						throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
					}
				} else {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new NullPointerException(ErrorDescriptions.CTX_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SEQ_NBR_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.SEQ_NBR_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}

	/**
	 * Generates the nonce.
	 * 
	 * @param partialIV
	 * @param senderID
	 * @param commonIV
	 * @param nonceLength the algorithm dependent length of nonce
	 * @return the generated nonce or null if either one of the input parameters
	 *         are null
	 * @throws OSException if any of the parameters are unvalid
	 */
	public static byte[] nonceGeneration(byte[] partialIV, byte[] senderID, byte[] commonIV, int nonceLength)
			throws OSException {
		if (partialIV != null) {
			if (senderID != null) {
				if (commonIV != null) {
					if (nonceLength > 0) {
						int s = senderID.length;
						int zeroes = 5 - partialIV.length;

						if (zeroes > 0) {
							partialIV = leftPaddingZeroes(partialIV, zeroes);
						}

						zeroes = (nonceLength - 6) - senderID.length;

						if (zeroes > 0) {
							senderID = leftPaddingZeroes(senderID, zeroes);
						}

						zeroes = nonceLength - commonIV.length;

						if (zeroes > 0) {
							commonIV = leftPaddingZeroes(commonIV, zeroes);
						}

						byte[] tmp = new byte[1 + senderID.length + partialIV.length];
						tmp[0] = (byte) s;
						System.arraycopy(senderID, 0, tmp, 1, senderID.length);
						System.arraycopy(partialIV, 0, tmp, senderID.length + 1, partialIV.length);

						byte[] result = new byte[commonIV.length];

						int i = 0;
						for (byte b : tmp) {
							result[i] = (byte) (b ^ commonIV[i++]);
						}

						return result;
					} else {
						LOGGER.error(ErrorDescriptions.NONCE_LENGTH_INVALID);
						throw new IllegalArgumentException(ErrorDescriptions.NONCE_LENGTH_INVALID);
					}
				} else {
					LOGGER.error(ErrorDescriptions.COMMON_IV_NULL);
					throw new NullPointerException(ErrorDescriptions.COMMON_IV_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SENDER_ID_NULL);
				throw new NullPointerException(ErrorDescriptions.SENDER_ID_NULL);
			}
		} else {
			LOGGER.error(ErrorDescriptions.PARTIAL_IV_NULL);
			throw new NullPointerException(ErrorDescriptions.PARTIAL_IV_NULL);
		}
	}

	/**
	 * Padds the left side of the byte array paddMe with zeros as the int zeros
	 * has
	 * 
	 * @param paddMe
	 * @param zeros
	 * @return
	 */
	public static byte[] leftPaddingZeroes(byte[] paddMe, int zeros) {
		byte[] tmp = new byte[zeros + paddMe.length];
		System.arraycopy(paddMe, 0, tmp, zeros, paddMe.length);
		return tmp;
	}

	/**
	 * Processes a partialIV correctly
	 * 
	 * @param partialIV the partialIV
	 * @return the processed partialIV
	 */
	public static byte[] processPartialIV(int value) {
		byte[] partialIV = ByteBuffer.allocate(Decryptor.INTEGER_BYTES).putInt(value).array();
		return stripZeroes(partialIV);
	}

	/**
	 * Remove trailing zeroes in a byte array
	 * 
	 * @param in the incoming array
	 * @return the array with trailing zeroes removed
	 */
	public static byte[] stripZeroes(byte[] in) {
		if (in != null) {
			if (in.length == 0) {
				return EMPTY;
			}
			if (in.length == 1)
				return in;

			int firstValue = 0;

			while (firstValue < in.length && in[firstValue] == 0) {
				firstValue++;
			}

			int newLength = in.length - firstValue;

			if (newLength == 0) {
				return ONE_ZERO;
			}

			byte[] out = new byte[newLength];
			System.arraycopy(in, firstValue, out, 0, out.length);

			return out;
		} else {
			LOGGER.error(ErrorDescriptions.BYTE_ARRAY_NULL);
			throw new NullPointerException(ErrorDescriptions.BYTE_ARRAY_NULL);
		}
	}
}
