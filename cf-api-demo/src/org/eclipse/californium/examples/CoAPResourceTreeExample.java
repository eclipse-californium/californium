/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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

import org.eclipse.californium.core.server.Server;
import org.eclipse.californium.core.server.resources.ResourceBase;

public class CoAPResourceTreeExample {

	public static void main(String[] args) {
		
		Server server = new Server();
		
		server.add(
			new ResourceBase("A").add(
				new ResourceBase("A1").add(
					new ResourceBase("A1_a"),
					new ResourceBase("A1_b"),
					new ResourceBase("A1_c"),
					new ResourceBase("A1_d")
				),
				new ResourceBase("A2").add(
					new ResourceBase("A2_a"),
					new ResourceBase("A2_b"),
					new ResourceBase("A2_c"),
					new ResourceBase("A2_d")
				)
			),
			new ResourceBase("B").add(
				new ResourceBase("B1").add(
					new ResourceBase("B1_a"),
					new ResourceBase("B1_b")
				)
			),
			new ResourceBase("C"),
			new ResourceBase("D")
		);
		
//		server
//			.add(new ResourceBase("A")
//				.add(new ResourceBase("A1")
//					.add(new ResourceBase("A1_a"))
//					.add(new ResourceBase("A1_b"))
//					.add(new ResourceBase("A1_c"))
//					.add(new ResourceBase("A1_d"))
//				)
//				.add(new ResourceBase("A2")
//					.add(new ResourceBase("A2_a"))
//					.add(new ResourceBase("A2_a"))
//					.add(new ResourceBase("A2_a"))
//					.add(new ResourceBase("A2_a"))
//				)
//			)
//			.add(new ResourceBase("B")
//				.add(new ResourceBase("B1")
//					.add(new ResourceBase("B1_a"))
//					.add(new ResourceBase("B1_b"))
//				)
//			)
//			.add(new ResourceBase("C"))
//			.add(new ResourceBase("D"));
		
		server.start();
		
	}
	
}
