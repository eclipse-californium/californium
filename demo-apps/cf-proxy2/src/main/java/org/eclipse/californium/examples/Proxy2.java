/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.eclipse.californium.elements.exception.ConnectorException;

/**
 * Main starter class for jar execution.
 */
public class Proxy2 {

	private static final String CROSS_PROXY = CrossExampleProxy2.class.getSimpleName();
	private static final String SECURE_PROXY = ExampleSecureProxy2.class.getSimpleName();
	private static final String COAP_CLIENT = ExampleProxy2CoapClient.class.getSimpleName();
	private static final String HTTP_CLIENT = ExampleProxy2HttpClient.class.getSimpleName();
	private static final String COAP_SERVER = ExampleCoapServer.class.getSimpleName();
	private static final String HTTP_SERVER = ExampleHttpServer.class.getSimpleName();

	public static void main(String[] args)
			throws IOException, ConnectorException, InterruptedException, GeneralSecurityException {
		String start = args.length > 0 ? args[0] : null;
		if (start != null) {
			String[] args2 = Arrays.copyOfRange(args, 1, args.length);
			if (CROSS_PROXY.equals(start)) {
				CrossExampleProxy2.main(args2);
				return;
			} else if (SECURE_PROXY.equals(start)) {
				ExampleSecureProxy2.main(args2);
				return;
			} else if (COAP_CLIENT.equals(start)) {
				ExampleProxy2CoapClient.main(args2);
				return;
			} else if (HTTP_CLIENT.equals(start)) {
				ExampleProxy2HttpClient.main(args2);
				return;
			} else if (COAP_SERVER.equals(start)) {
				ExampleCoapServer.main(args2);
				return;
			} else if (HTTP_SERVER.equals(start)) {
				ExampleHttpServer.main(args2);
				return;
			}
		}
		System.out.println("\nCalifornium (Cf) Proxy2-Starter");
		System.out.println("(c) 2020, Bosch.IO GmbH and others");
		System.out.println();
		System.out.println("Usage: " + Proxy2.class.getSimpleName() + " (" + CROSS_PROXY + "|" + SECURE_PROXY + "|"
				+ COAP_CLIENT + "|" + HTTP_CLIENT + "|" + COAP_SERVER + "|" + HTTP_SERVER + ")");
		if (start != null) {
			System.out.println("   '" + start + "' is not supported!");
		}
		System.exit(-1);
	}
}
