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
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * 
 * Handles OSExceptions (determines if an EmptyMessage should be sent) and
 * CoapOSExceptions (creates and returns the response with the correct response
 * code).
 *
 */
public class CoapOSExceptionHandler {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapOSExceptionHandler.class);

	/**
	 * 
	 * Process the exception e which was provoked by the received request.
	 * 
	 * @param e the exception which was thrown because of the received request.
	 * @param request the received request.
	 * @return the appropriate error message in a response.
	 */
	public static Response manageError(CoapOSException e, Request request) {
		ResponseCode responseCode = e.getResponseCode();
		Response error = null;

		if (request != null) {
			if (request.getType() != null) {
				if (responseCode.isClientError()) {

					error = Response.createResponse(request, responseCode);

					Type tmp = Type.NON;
					Type t = request.getType();

					if (t.equals(Type.CON)) {
						tmp = Type.ACK;
					}

					error.setType(tmp);
					error.setPayload(e.getMessage());
					error.getOptions().setMaxAge(0);
					
					//Set MID of error response to match request
					error.setMID(request.getMID());
					
					//Set content format to text/plain
					error.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
					
					return error;
				} else {
					LOGGER.error("{} {}", ErrorDescriptions.CANNOT_CREATE_ERROR_MESS,
							ErrorDescriptions.ERROR_MESS_NULL);
				}
			} else {
				LOGGER.error("{} {}", ErrorDescriptions.CANNOT_CREATE_ERROR_MESS, ErrorDescriptions.TYPE_NULL);
			}
		} else {
			LOGGER.error("{} {}", ErrorDescriptions.CANNOT_CREATE_ERROR_MESS, ErrorDescriptions.REQUEST_NULL);
		}
		return null;
	}

	/**
	 * 
	 * Initiates the EmptyMessage in response to a received response in the case
	 * of a thrown OSException.
	 * 
	 * @param e the exception which was thrown because of the received response.
	 * @param response the received response.
	 * @return the initiated EmptyMessage
	 */
	public static EmptyMessage manageError(OSException e, Response response) {
		if (e == null) {
			LOGGER.error(ErrorDescriptions.EXCEPTION_NULL);
			throw new NullPointerException(ErrorDescriptions.EXCEPTION_NULL);
		}

		String errMess = e.getMessage();

		if (errMess == null) {
			LOGGER.error(ErrorDescriptions.ERROR_MESS_NULL);
			throw new NullPointerException(ErrorDescriptions.ERROR_MESS_NULL);
		}
		
		if (!response.isConfirmable()) {
			LOGGER.error("An Empty Message will not be created");
			return null;
		}
		
		LOGGER.debug("Sending empty RST message");
		return EmptyMessage.newRST(response);
	}
}
