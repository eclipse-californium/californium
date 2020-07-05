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
import java.util.Arrays;

import org.eclipse.californium.elements.exception.ConnectorException;

/**
 * Main starter class for jar execution.
 */
public class Client {

	private static final String HELLO_WORLD = GETClient.class.getSimpleName();
	private static final String MULTICAST = MulticastTestClient.class.getSimpleName();

	public static void main(String[] args) throws IOException, ConnectorException, InterruptedException {
		String start = args.length > 0 ? args[0] : null;
		if (start != null) {
			String[] args2 = Arrays.copyOfRange(args, 1, args.length);
			if (HELLO_WORLD.equals(start)) {
				GETClient.main(args2);
				return;
			} else if (MULTICAST.equals(start)) {
				MulticastTestClient.main(args2);
				return;
			}
		}
		System.out.println("\nCalifornium (Cf) Server-Starter");
		System.out.println("(c) 2020, Bosch.IO GmbH and others");
		System.out.println();
		System.out.println("Usage: " + Client.class.getSimpleName() + " (" + HELLO_WORLD + "|" + MULTICAST + ")");
		if (start != null) {
			System.out.println("   '" + start + "' is not supported!");
		}
		System.exit(-1);
	}
}
