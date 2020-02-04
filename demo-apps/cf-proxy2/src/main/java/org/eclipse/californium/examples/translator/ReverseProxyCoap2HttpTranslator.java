/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from org.eclipse.californium.proxy
 ******************************************************************************/

package org.eclipse.californium.examples.translator;

import java.net.InetSocketAddress;
import java.net.URI;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.proxy2.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.TranslationException;

/**
 * Provides fixed destination URI to forward regular coap requests to that http
 * destination.
 */
public class ReverseProxyCoap2HttpTranslator extends Coap2HttpTranslator {

	private final URI destination;

	public ReverseProxyCoap2HttpTranslator(String destination) {
		this.destination = URI.create(destination);
	}

	@Override
	public URI getDestinationURI(Request incomingRequest, InetSocketAddress exposed) throws TranslationException {
		return destination;
	}

}
