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
package org.eclipse.californium.benchmark;

import java.util.List;
import java.util.regex.Pattern;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;


/**
 * This resource recursively computes the Fibonacci numbers and therefore needs
 * a lot of computing power to respond to a request. Use the query ?n=20 to
 * compute the 20. Fibonacci number, e.g.: coap://localhost:5683/fibonacci?n=20.
 */
public class FibonacciResource extends CoapResource {

	private Pattern pattern;
	
	public FibonacciResource(String name) {
		super(name);
		this.pattern = Pattern.compile("n=\\d*");
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		int n = 20;
		if (exchange.getRequestOptions().getURIQueryCount() > 0) {
			try {
				List<String> queries = exchange.getRequestOptions().getUriQuery();
				for (String query:queries) {
					if (pattern.matcher(query).matches()) {
						n = Integer.parseInt(query.split("=")[1]);
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
				exchange.respond(ResponseCode.BAD_REQUEST, e.getMessage());
				return;
			}
		}
		
		int fib = fibonacci(n);
		exchange.respond("fibonacci("+n+") = "+fib);
	}
	
	/**
	 * Recursive Fibonacci algorithm
	 */
	private int fibonacci(int n) {
		if (n <= 1) return n;
		else return fibonacci(n-1) + fibonacci(n-2);
	}
	
}
