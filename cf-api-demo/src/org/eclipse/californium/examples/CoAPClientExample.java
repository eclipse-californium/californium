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

import java.io.IOException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

public class CoAPClientExample {

	public static void main(String[] args) {
		
		CoapClient client = new CoapClient("coap://vs0.inf.ethz.ch:5683/obs");
		
//		// synchronous
//		String content1 = client.get().getResponseText();
//		System.out.println(content1);
//		String content2 = client.post("payload", MediaTypeRegistry.TEXT_PLAIN).getResponseText();
//		System.out.println(content2);
//		
		// asynchronous
		
		System.out.println("GET");
		client.get(new CoapHandler() {
			@Override public void onLoad(CoapResponse response) {
				String content = response.getResponseText();
				System.out.println(content);
				System.out.println("HHH");
			}
			
			@Override public void onError() {
				System.err.println("Failed");
			}
		});
		System.out.println("DONE");
		
		try {
			System.in.read();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("EXIT");
//		
//		// observing
//		CoapObserveRelation relation = client.observe(
//				new CoapHandler() {
//					@Override public void onLoad(CoapResponse response) {
//						String content = response.getResponseText();
//						System.out.println(content);
//					}
//					
//					@Override public void onError() {
//						System.err.println("Failed");
//					}
//				});
//		relation.proactiveCancel();
	}
	
}
