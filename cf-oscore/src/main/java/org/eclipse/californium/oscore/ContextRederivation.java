/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.security.SecureRandom;
import java.util.Arrays;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;

/**
 * Methods for perform re-derivation of contexts as detailed in Appendix B.2. It
 * uses two message exchanges together with varying the Context ID field in the
 * OSCORE option to securely generate a new shared context. The second exchange
 * will be for the request the client actually wants to send.
 * 
 * Note that the implementation requires that no additional requests are sent
 * without first getting the response to the pending request during the 2
 * request/response exchanges of the procedure.
 *
 * See https://tools.ietf.org/html/rfc8613#appendix-B.2
 */
public class ContextRederivation {

	private static SecureRandom random = new SecureRandom();

	private static final String SCHEME = "coap://";

	/**
	 * The different phases of the re-derivation procedure.
	 *
	 */
	public static enum PHASE {
		INACTIVE, CLIENT_INITIATE, SERVER_INITIATE, SERVER_PHASE_1, SERVER_PHASE_2, SERVER_PHASE_3, CLIENT_PHASE_1, CLIENT_PHASE_2, CLIENT_PHASE_3;
	}

	/**
	 * Length of each segment (ID1, S2 and R3) in the Context ID when performing
	 * context re-derivation. R2 will be of length 2 segments since it is
	 * actually composed of S2 || HMAC(S2).
	 */
	protected static int SEGMENT_LENGTH = 8;

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ContextRederivation.class);

	/**
	 * Method to indicate that the mutable parts of an OSCORE context has been
	 * lost. In such case the context re-derivation procedure is triggered.
	 * 
	 * @param db context DB
	 * @param uri the URI associated with context information has been lost for
	 * @throws CoapOSException if re-generation of the context fails
	 */
	public static void setLostContext(OSCoreCtxDB db, String uri) throws CoapOSException
	{
		try {
			initiateRequest(db, uri);
		} catch (ConnectorException | OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new CoapOSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED, ResponseCode.BAD_REQUEST);
		}
	}

	/* Client side related methods below */

	/**
	 * This method will be triggered by the client before sending a request that
	 * initiates the context re-derivation procedure. This request is identified
	 * as request #1 in Appendix B.2.
	 * 
	 * @param db context db
	 * @param uri uri
	 * @throws ConnectorException if send/receiving messages failed
	 * @throws OSException if context re-derivation fails
	 */
	private static void initiateRequest(OSCoreCtxDB db, String uri) throws ConnectorException, OSException {

		// Retrieve the context for the target URI
		OSCoreCtx ctx = db.getContext(uri);

		// Check that context re-derivation is enabled for this context
		if (ctx.getContextRederivationEnabled() == false) {
			LOGGER.error("Context re-derivation is not enabled for this context.");
			throw new IllegalStateException("Context re-derivation is not enabled for this context.");
		}

		printStateLogging(ctx);

		// Generate a random Context ID (ID1)
		byte[] contextID1 = Bytes.createBytes(random, SEGMENT_LENGTH);

		// Create new context with the generated Context ID
		OSCoreCtx newCtx = rederiveWithContextID(ctx, contextID1);

		// In the request include ID1 as a CBOR byte string (bstr)
		newCtx.setIncludeContextId(encodeToCborBstrBytes(contextID1));
		newCtx.setContextRederivationPhase(ContextRederivation.PHASE.CLIENT_PHASE_1);
		newCtx.setNonceHandover(ctx.getNonceHandover());

		db.removeContext(ctx);
		db.addContext(uri, newCtx);
	}

	/**
	 * Handle incoming response messages (for client).
	 * 
	 * @param db the context db
	 * @param ctx the context
	 * @param contextID the context ID in the incoming response
	 * @return an updated context
	 * @throws OSException if context re-derivation fails
	 */
	static OSCoreCtx incomingResponse(OSCoreCtxDB db, OSCoreCtx ctx, byte[] contextID) throws OSException {

		// Check if context re-derivation is enabled for this context
		if (ctx.getContextRederivationEnabled() == false) {
			LOGGER.debug("Context re-derivation not considered due to it being disabled for this context");
			return ctx;
		}

		// Handle client phase 3 operations
		if (ctx.getContextRederivationPhase() == PHASE.CLIENT_PHASE_3) {

			printStateLogging(ctx);

			ctx.setIncludeContextId(false);
			ctx.setContextRederivationPhase(PHASE.INACTIVE);
			return ctx;
		} else if (ctx.getContextRederivationPhase() == PHASE.CLIENT_PHASE_1) {

			printStateLogging(ctx);

			// Handle client phase 1 operations (reception of response #1)

			// The Context ID in the incoming response is identified as R2
			// It is first decoded as it is a CBOR byte string
			byte[] contextR2 = decodeFromCborBstrBytes(contextID);

			// The Context ID of the original request in this exchange is ID1
			byte[] contextID1 = ctx.getIdContext();

			// Create Context ID to generate the new context with (R2 || ID1)
			byte[] verifyContextID = Bytes.concatenate(contextR2, contextID1);

			// Generate a new context with the concatenated Context ID
			OSCoreCtx newCtx = rederiveWithContextID(ctx, verifyContextID);
			newCtx.setNonceHandover(ctx.getNonceHandover());

			// Add the new context to the context DB (replacing the old)
			newCtx.setContextRederivationPhase(PHASE.CLIENT_PHASE_2);
			db.removeContext(ctx);
			db.addContext(SCHEME + ctx.getUri(), newCtx);
			return newCtx;
		} else if (ctx.getContextRederivationPhase() == PHASE.INACTIVE) {

			printStateLogging(ctx);

			// It may be that it was the server that lost the mutable parts of
			// the context. In this case, if context re-derivation is explicitly
			// enabled on the client, it should check if the response is in fact
			// part of a context re-derivation procedure initiated by the
			// server. This situation would be the client receiving a response
			// #1 without sending request #1 (which would be just a normal
			// client request).

			// For this to be a valid response #1 from the server it must have a
			// contextID set and not match the one used in the client's context
			// (ID1 is different from R2)
			if (contextID == null || Arrays.equals(ctx.getIdContext(), contextID) == true) {
				return ctx;
			}

			String supplemental = "client received response with server initiated re-derivation";
			LOGGER.debug("Context re-derivation phase: {} ({})", PHASE.INACTIVE, supplemental);

			// The Context ID in the incoming response is identified as R2
			// It is first decoded as it is a CBOR byte string
			byte[] contextR2 = decodeFromCborBstrBytes(contextID);

			// The Context ID of the original request in this exchange is ID1
			byte[] contextID1 = ctx.getIdContext();

			// Create Context ID to generate the new context with (R2 || ID1)
			byte[] verifyContextID = Bytes.concatenate(contextR2, contextID1);

			// Generate a new context with the concatenated Context ID
			OSCoreCtx newCtx = rederiveWithContextID(ctx, verifyContextID);

			// Add the new context to the context DB (replacing the old)
			newCtx.setContextRederivationPhase(PHASE.CLIENT_PHASE_2);
			
			newCtx.setNonceHandover(ctx.getNonceHandover());
			db.removeContext(ctx);
			db.addContext(SCHEME + ctx.getUri(), newCtx);

			return newCtx;
		}

		return ctx;
	}

	/**
	 * Handle outgoing request messages (for client).
	 * 
	 * @param db the context db
	 * @param ctx the context
	 * @return an updated context
	 * @throws OSException if context re-derivation fails
	 */
	static OSCoreCtx outgoingRequest(OSCoreCtxDB db, OSCoreCtx ctx) throws OSException {

		// Handle client phase 2 operations (sending of request #2)
		if (ctx.getContextRederivationPhase() == PHASE.CLIENT_PHASE_2) {

			printStateLogging(ctx);

			// Extract the R2 Context ID value from the current context
			// Currently the value will be R2 || ID1
			byte[] currentContextID = ctx.getIdContext();
			byte[] contextR2 = Arrays.copyOfRange(currentContextID, 0, currentContextID.length - SEGMENT_LENGTH);

			// Now create the random Context ID value R3
			byte[] contextR3 = Bytes.createBytes(random, SEGMENT_LENGTH);

			// Concatenate R2 and R3 to get the Context ID to use
			byte[] protectContextID = Bytes.concatenate(contextR2, contextR3);

			// Generate a new context with the concatenated Context ID
			OSCoreCtx newCtx = rederiveWithContextID(ctx, protectContextID);

			// In the outgoing request from this context, include the Context ID
			// as a CBOR byte string
			newCtx.setIncludeContextId(encodeToCborBstrBytes(protectContextID));

			// Indicate that the context re-derivation procedure is ongoing
			newCtx.setContextRederivationPhase(PHASE.CLIENT_PHASE_3);

			// Add the new context to the context DB (replacing the old)
			db.removeContext(ctx);
			db.addContext(SCHEME + ctx.getUri(), newCtx);
			return newCtx;
		}

		return ctx;
	}

	/* Server side related methods below */

	/**
	 * Handle incoming request messages (for server).
	 * 
	 * @param db db the context db
	 * @param ctx the context
	 * @param contextID the context ID in the incoming request
	 * @param rid the RID in the incoming request
	 * @return an updated context
	 * @throws OSException if context re-derivation fails
	 */
	static OSCoreCtx incomingRequest(OSCoreCtxDB db, OSCoreCtx ctx, byte[] contextID, byte[] rid) throws OSException {

		// Try to retrieve the context based on the RID only if no context was
		// found. Since the ID Context in the initial request will be a new one
		// and not match existing contexts.
		if (ctx == null) {
			ctx = db.getContext(rid);
		}

		// No context found still
		if (ctx == null) {
			return null;
		}

		// Check if context re-derivation is enabled for this context
		if (ctx.getContextRederivationEnabled() == false) {
			LOGGER.debug("Context re-derivation not considered due to it being disabled for this context");
			return ctx;
		 }

		// Handle server phase 2 operations (reception of request #2)
		if (ctx.getContextRederivationPhase() == PHASE.SERVER_PHASE_2) {

			printStateLogging(ctx);

			/*
			 * Verify the Context ID (R2) using S2 and an HMAC function. The
			 * Context ID in this message is (R2 || R3). R2 in turn is composed
			 * of S2 || HMAC output.
			 */

			// Extract S2 from the Context ID
			byte[] contextS2 = Arrays.copyOfRange(ctx.getIdContext(), 0, SEGMENT_LENGTH);

			// Generate HMAC output using S2
			byte[] hmacOutput = performHMAC(ctx.getContextRederivationKey(), contextS2);

			// Compare the HMAC output with the equivalent in the message
			byte[] messageHmacOutput = Arrays.copyOfRange(ctx.getIdContext(), SEGMENT_LENGTH, SEGMENT_LENGTH * 2);
			if (Arrays.equals(hmacOutput, messageHmacOutput) == false) {
				throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			}

			// Generate a new context with the received Context ID, after
			// decoded from a CBOR byte string
			byte[] contextIdParsed = decodeFromCborBstrBytes(contextID);
			OSCoreCtx newCtx = rederiveWithContextID(ctx, contextIdParsed);

			// Set the next phase of the re-derivation procedure
			newCtx.setContextRederivationPhase(PHASE.SERVER_PHASE_3);

			// Add the new context to the context DB (replacing the old)
			db.removeContext(ctx);
			db.addContext(newCtx);

			return newCtx;
		} else if (ctx.getContextRederivationPhase() == PHASE.INACTIVE) {

			printStateLogging(ctx);

			// Handle initiation of re-derivation procedure (reception of
			// request #1)

			// Check if the received Context ID (ID1) matches the one in the
			// context, if so do nothing. This means that this is a normal
			// message and not meant to initiate context re-derivation.
			if (contextID == null || Arrays.equals(contextID, ctx.getIdContext())) {
				return ctx;
			}

			// If this is about context re-derivation decode the Context ID as a
			// CBOR byte string. The Context ID in the request is identified as
			// ID1. If the ID Context in the incoming request is not a CBOR byte
			// string the re-derivation procedure will be aborted.
			byte[] contextID1 = null;
			try {
				contextID1 = decodeFromCborBstrBytes(contextID);
			} catch (CBORException e) {
				LOGGER.debug(
						"Client initiated context re-derivation not started as ID Context in request is not a CBOR byte string.");
				return ctx;
			}

			// Generate a new context with the received Context ID
			OSCoreCtx newCtx = rederiveWithContextID(ctx, contextID1);

			// Set next phase of the re-derivation procedure
			newCtx.setContextRederivationPhase(PHASE.SERVER_PHASE_1);

			// Add the new context to the context DB (replacing the old)
			db.removeContext(ctx);
			db.addContext(newCtx);
			return newCtx;
		} else if (ctx.getContextRederivationPhase() == PHASE.SERVER_INITIATE) {

			printStateLogging(ctx);

			// Handle initiation of re-derivation procedure
			// In this case it is the server that initiates this procedure since
			// it lost the mutable parts of the context. This situation would be
			// the server sending response #1 without first getting a request #1
			// from the client (which would just be a normal request)

			// The Context ID to use as ID1 is the same as the one used in the
			// old context. The client may not include this in the request.
			byte[] contextID1 = ctx.getIdContext();

			// Generate a new context with the received Context ID
			OSCoreCtx newCtx = rederiveWithContextID(ctx, contextID1);

			// Set next phase of the re-derivation procedure
			newCtx.setContextRederivationPhase(PHASE.SERVER_PHASE_1);

			// Add the new context to the context DB (replacing the old)
			db.removeContext(ctx);
			db.addContext(newCtx);
			return newCtx;
		}

		return ctx;
	}

	/**
	 * Handle outgoing response messages (for server).
	 * 
	 * @param db the context db
	 * @param ctx the context
	 * @return an updated context
	 * @throws OSException if context re-derivation fails
	 */
	static OSCoreCtx outgoingResponse(OSCoreCtxDB db, OSCoreCtx ctx) throws OSException {

		// Handle server phase 3 operations (sending of response #2)
		if (ctx.getContextRederivationPhase() == PHASE.SERVER_PHASE_3) {

			printStateLogging(ctx);

			ctx.setIncludeContextId(false);
			ctx.setContextRederivationPhase(PHASE.INACTIVE);
			return ctx;
		} else if (ctx.getContextRederivationPhase() == PHASE.SERVER_PHASE_1) {

			printStateLogging(ctx);

			// Handle server phase 1 operations (sending of response #1)

			// Set a random context re-derivation key
			int keyLength = ctx.getSenderKey().length;
			byte[] contextRederivationKey = Bytes.createBytes(random, keyLength);
			ctx.setContextRederivationKey(contextRederivationKey);

			// The Context ID in the original request is identified as ID1
			byte[] contextID1 = ctx.getIdContext();

			/*
			 * Generate new Context ID (R2) with a byte array (S2) & an HMAC
			 * function.
			 */

			// Generate S2
			byte[] contextS2 = Bytes.createBytes(random, SEGMENT_LENGTH);

			// Generate HMAC output using S2
			byte[] hmacOutput = performHMAC(ctx.getContextRederivationKey(), contextS2);

			// Create R2 by concatenating S2 and the HMAC output
			byte[] contextR2 = Bytes.concatenate(contextS2, hmacOutput);

			/* Create Context ID to generate the new context with (R2 || ID1) */

			byte[] protectContextID = Bytes.concatenate(contextR2, contextID1);

			// Generate a new context with the concatenated Context ID
			OSCoreCtx newCtx = rederiveWithContextID(ctx, protectContextID);
			newCtx.setNonceHandover(ctx.getNonceHandover());

			// Outgoing response from this context only uses R2 as
			// Context ID (not concatenated one used to generate the context).
			// It will be encoded as a CBOR byte string.
			newCtx.setIncludeContextId(encodeToCborBstrBytes(contextR2));

			// Indicate that the context re-derivation procedure is ongoing
			newCtx.setContextRederivationPhase(PHASE.SERVER_PHASE_2);

			// Add the new context to the context DB (replacing the old)
			db.removeContext(ctx);
			db.addContext(newCtx);
			return newCtx;
		}

		return ctx;
	}

	/**
	 * Re-derive a context with the same input parameters except Context ID.
	 * Also retain the same context re-derivation key.
	 * 
	 * @param ctx the OSCORE context to re-derive
	 * @param contextID the new context ID to use
	 * @return the new re-derived context
	 * @throws OSException if the KDF is not supported
	 */
	private static OSCoreCtx rederiveWithContextID(OSCoreCtx ctx, byte[] contextID) throws OSException {
		OSCoreCtx newCtx = new OSCoreCtx(ctx.getMasterSecret(), true, ctx.getAlg(), ctx.getSenderId(),
				ctx.getRecipientId(), ctx.getKdf(), ctx.getRecipientReplaySize(), ctx.getSalt(),
				contextID, ctx.getMaxUnfragmentedSize());
		newCtx.setContextRederivationKey(ctx.getContextRederivationKey());
		newCtx.setContextRederivationEnabled(ctx.getContextRederivationEnabled());
		return newCtx;
	}

	/**
	 * Perform HMAC on input data with a key.
	 * 
	 * @param contextRederivationKey the context re-derivation key
	 * @param input the input data
	 * @return HMAC output
	 * @throws OSException if performing the HMAC fails
	 */
	private static byte[] performHMAC(byte[] contextRederivationKey, byte[] input) throws OSException {
		byte[] key = null;
		try {
			key = OSCoreCtx.deriveKey(contextRederivationKey, contextRederivationKey, SEGMENT_LENGTH, "SHA256", input);
		} catch (CoseException e) {
			throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
		}
		return key;
	}

	/**
	 * Returns the byte representation of the input Java byte array encoded as a
	 * CBOR byte string. The input Java array is first made into a CBORObject
	 * representing a CBOR byte string, the byte representation of this CBOR
	 * byte string is returned.
	 * 
	 * @param array the input Java byte array to encode
	 * @return encoded bytes
	 */
	private static byte[] encodeToCborBstrBytes(byte[] array) {
		CBORObject arrayBstr = CBORObject.FromObject(array);
		return arrayBstr.EncodeToBytes();
	}

	/**
	 * Returns a Java byte array decoded from the input CBOR byte string. The
	 * input is the bytes of the encoded CBOR byte string, which when decoded
	 * into a CBORObject represents a CBOR byte string. The contents of this
	 * CBOR byte string is returned.
	 * 
	 * @param bstr a byte array containing the encoded CBOR byte string
	 * @return decoded bytes
	 */
	private static byte[] decodeFromCborBstrBytes(byte[] bstr) {
		CBORObject arrayBstr = CBORObject.DecodeFromBytes(bstr);
		return arrayBstr.GetByteString();
	}

	/**
	 * Provides logging output indicating the current state. Uses debug level
	 * output for the inactive state since that is the default for typical use.
	 * 
	 * @param ctx the OSCORE context in use
	 */
	private static void printStateLogging(OSCoreCtx ctx) {

		if (!LOGGER.isDebugEnabled()) {
			return;
		}

		PHASE currentPhase = ctx.getContextRederivationPhase();

		String supplemental = "";
		switch (currentPhase) {
		case INACTIVE:
			supplemental = "client/server context re-derivation inactive";
			break;
		case CLIENT_INITIATE:
			supplemental = "client will initiate context re-derivation";
			break;
		case SERVER_INITIATE:
			supplemental = "server will initiate context re-derivation";
			break;
		case CLIENT_PHASE_1:
			supplemental = "client has sent the first request in the procedure and is receving the response";
			break;
		case CLIENT_PHASE_2:
			supplemental = "client is sending the second request in the procedure";
			break;
		case CLIENT_PHASE_3:
			supplemental = "client has received the second response in the procedure and is concluding";
			break;
		case SERVER_PHASE_1:
			supplemental = "server has received the first request in the procedure and is sending the response";
			break;
		case SERVER_PHASE_2:
			supplemental = "server is receiving the second request in the procedure";
			break;
		case SERVER_PHASE_3:
			supplemental = "server has sent the second response in the procedure and is concluding";
			break;
		default:
			supplemental = "context re-derivation is in unknown state indicating a problem";
			break;
		}

		if (currentPhase == PHASE.INACTIVE) {
			LOGGER.trace("Context re-derivation phase: {} ({})", currentPhase, supplemental);
		} else {
			LOGGER.debug("Context re-derivation phase: {} ({})", currentPhase, supplemental);
		}
	}

}
