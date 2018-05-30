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
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
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
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapOSExceptionHandler.class.getName());

	/**
	 * 
	 * Process the exception e which was provoked by the received request.
	 * 
	 * @param e the exception which was thrown because of the received request.
	 * @param request the received request.
	 * @return the appropriate error message in a response.
	 * @throws OSException
	 */
	public static Response manageError(CoapOSException e, Request request) throws OSException {
		ResponseCode responseCode = e.getResponseCode();
		Response error = null;
		boolean includeErrMess = true;

		if (request != null) {
			if (request.getType() != null) {
				if (ResponseCode.isClientError(responseCode)) {

					error = Response.createResponse(request, responseCode);

					Type tmp = Type.NON;
					Type t = request.getType();

					if (t.equals(Type.CON)) {
						tmp = Type.ACK;
					}

					error.setType(tmp);
					if (includeErrMess) {
						error.setPayload(e.getMessage());
					}

					error.getOptions().setMaxAge(0);

					return error;
				} else {
					LOGGER.error(Error.CANNOT_CREATE_ERROR_MESS + ": " + Error.ERROR_MESS_NULL);
				}
			} else {
				LOGGER.error(Error.CANNOT_CREATE_ERROR_MESS + ": " + Error.TYPE_NULL);
			}
		} else {
			LOGGER.error(Error.CANNOT_CREATE_ERROR_MESS + ": " + Error.REQUEST_NULL);
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
			LOGGER.error(Error.EXCEPTION_NULL);
			throw new NullPointerException(Error.EXCEPTION_NULL);
		}

		String errMess = e.getMessage();

		if (errMess == null) {
			LOGGER.error(Error.ERROR_MESS_NULL);
			throw new NullPointerException(Error.ERROR_MESS_NULL);
		}

		if (!response.isConfirmable()) {
			LOGGER.error("An Empty Message will not be created");
			return null;
		}
		return EmptyMessage.newACK(response);
	}
}
