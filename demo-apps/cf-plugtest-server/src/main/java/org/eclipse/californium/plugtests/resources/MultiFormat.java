/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

/**
 * This resource implements a test of specification for the ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class MultiFormat extends CoapResource {

	public MultiFormat() {
		super("multi-format");
		getAttributes().setTitle("Resource that exists in different content formats");
		getAttributes().addContentType(0);
		getAttributes().addContentType(41);
		getAttributes().addContentType(50);
		getAttributes().addContentType(60);
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// get request to read out details
		final Request request = exchange.advanced().getRequest();
		
		// successively create response
		Response response = new Response(CONTENT);

		String format = "";
		byte[] binary = null;
		
		try {
				
			switch (exchange.getRequestOptions().getAccept()) {
				case UNDEFINED:
				case TEXT_PLAIN:
					response.getOptions().setContentFormat(TEXT_PLAIN);
					format = "Status type: \"%s\"\nCode: \"%s\"\nMID: \"%d\"\nAccept: \"%d\"";
					break;
		
				case APPLICATION_XML:
					response.getOptions().setContentFormat(APPLICATION_XML);
					format = "<msg type=\"%s\" code=\"%s\" mid=\"%d\" accept=\"%d\"/>"; // should fit 64 bytes
					break;
		
				case APPLICATION_JSON:
					response.getOptions().setContentFormat(APPLICATION_JSON);
					format = "{ \"type\":\"%s\", \"code\":\"%s\", \"mid\":%d, \"accept\":%d }"; // should fit 64 bytes
					
					JsonFactory jsonF = new JsonFactory();
					ByteArrayOutputStream jsonO = new ByteArrayOutputStream();
					
					JsonGenerator jsonG = jsonF.createGenerator(jsonO, JsonEncoding.UTF8);
	
					jsonG.writeStartObject();
					jsonG.writeStringField("type", request.getType().name());
					jsonG.writeStringField("code", request.getCode().name());
					jsonG.writeNumberField("mid", request.getMID());
					jsonG.writeNumberField("accept", request.getOptions().getAccept());
					jsonG.writeEndObject();
					jsonG.close();
					
					binary = jsonO.toByteArray();
					jsonO.close();
					break;
		
				case APPLICATION_CBOR:
					response.getOptions().setContentFormat(APPLICATION_CBOR);
					
					CBORFactory cborF = new CBORFactory();
					ByteArrayOutputStream cborO = new ByteArrayOutputStream();
					
					CBORGenerator cborG = cborF.createGenerator(cborO, JsonEncoding.UTF8);
	
					cborG.writeStartObject();
					cborG.writeStringField("type", request.getType().name());
					cborG.writeStringField("code", request.getCode().name());
					cborG.writeNumberField("mid", request.getMID());
					cborG.writeNumberField("accept", request.getOptions().getAccept());
					cborG.writeEndObject();
					cborG.close();
					
					binary = cborO.toByteArray();
					cborO.close();
					break;
		
				default:
					response = new Response(NOT_ACCEPTABLE);
					format = "text/plain or application/xml only";
					break;
			}
			
			if (binary!=null) {
				response.setPayload(binary);
			} else {
				response.setPayload( 
						String.format(format, 
								request.getType(), 
								request.getCode(), 
								request.getMID(),
								request.getOptions().getAccept()) // no MediaTypeRegistry.toString() to keep below 64 bytes
						);
			}
			
			exchange.respond(response);
			
		} catch (IOException e) {
			exchange.respond(new Response(INTERNAL_SERVER_ERROR));
		}
	}
}
