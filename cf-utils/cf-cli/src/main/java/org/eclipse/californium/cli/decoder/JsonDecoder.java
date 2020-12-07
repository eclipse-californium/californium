/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch.IO GmbH)     - moved from cf-plugtest-client
 ******************************************************************************/
package org.eclipse.californium.cli.decoder;

import org.eclipse.californium.core.coap.CoAP;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

public class JsonDecoder implements Decoder {

	@Override
	public String decode(byte[] payload) {
		try {
			JsonElement element = JsonParser.parseString(new String(payload, CoAP.UTF8_CHARSET));
			GsonBuilder builder = new GsonBuilder();
			builder.setPrettyPrinting();
			Gson gson = builder.create();
			return gson.toJson(element);
		} catch (JsonSyntaxException ex) {
			ex.printStackTrace();
			throw ex;
		}
	}

}