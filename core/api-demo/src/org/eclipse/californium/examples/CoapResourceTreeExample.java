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
 *    Martin Lanter - architect and initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;

public class CoapResourceTreeExample {

	public static void main(String[] args) {
		
		CoapServer server = new CoapServer();
		
		server.add(
			new CoapResource("A").add(
				new CoapResource("A1").add(
					new CoapResource("A1_a"),
					new CoapResource("A1_b"),
					new CoapResource("A1_c"),
					new CoapResource("A1_d")
				),
				new CoapResource("A2").add(
					new CoapResource("A2_a"),
					new CoapResource("A2_b"),
					new CoapResource("A2_c"),
					new CoapResource("A2_d")
				)
			),
			new CoapResource("B").add(
				new CoapResource("B1").add(
					new CoapResource("B1_a"),
					new CoapResource("B1_b")
				)
			),
			new CoapResource("C"),
			new CoapResource("D")
		);
		
//		server
//			.add(new CoapResource("A")
//				.add(new CoapResource("A1")
//					.add(new CoapResource("A1_a"))
//					.add(new CoapResource("A1_b"))
//					.add(new CoapResource("A1_c"))
//					.add(new CoapResource("A1_d"))
//				)
//				.add(new CoapResource("A2")
//					.add(new CoapResource("A2_a"))
//					.add(new CoapResource("A2_a"))
//					.add(new CoapResource("A2_a"))
//					.add(new CoapResource("A2_a"))
//				)
//			)
//			.add(new CoapResource("B")
//				.add(new CoapResource("B1")
//					.add(new CoapResource("B1_a"))
//					.add(new CoapResource("B1_b"))
//				)
//			)
//			.add(new CoapResource("C"))
//			.add(new CoapResource("D"));
		
		server.start();
		
	}
	
}
