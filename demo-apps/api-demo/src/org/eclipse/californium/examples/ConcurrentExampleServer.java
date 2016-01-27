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
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.ConcurrentCoapResource;

/**
 * Creates an example server with resources that have different multi-threading
 * policies. The three resources on top with the name "server-thread" are normal
 * resources that do not define their own executor. Therefore, they all use
 * their parent's executor which ultimately is the server's. The resource
 * "single-threaded" defines its own executor with one thread. Therefore, all
 * requests to that resource will be executed by the same one thread. Its child
 * again is a single-threaded resource that uses its very own single-threaded
 * executor. The resource "four-threaded" uses an executor with four threads.
 * Request can be (concurrently) handled by any of them. The resource has a
 * child and a grand-child that both are normal resources and therefore also use
 * the executor with four threads. Finally, the resource "legacy" reuses a
 * normal resource as implementation but uses a new executor to handle the
 * requests. For the client, the resource behaves exactly like there were no
 * executor.
 * <hr>
 * <blockquote>
 * 
 * <pre>
 * Root
 *  |
 *  |-- server-thread: pool-1-thread-[1-4]
 *  |    `-- server-thread: pool-1-thread-[1-4]
 *  |         `-- server-thread: pool-1-thread-[1-4]
 *  |
 *  |-- single-threaded: pool-2-thread-1
 *  |    `-- single-threaded: pool-3-thread-1
 *  |
 *  |-- four-threaded: pool-4-thread-[1-4]
 *  |    `-- same-as-parent: pool-4-thread-[1-4]
 *  |         `-- same-as-parent: pool-4-thread-[1-4]
 *  |
 *  |-- legacy: pool-5-thread-[1-2]
 * </pre>
 * 
 * </blockquote>
 * <hr>
 **/
public class ConcurrentExampleServer {

	public static void main(String[] args) {
		System.out.println("Starting Concurrent Example Server");
		
		CoapServer server = new CoapServer();
		server.add(new NoThreadResource("server-thread")
					.add(new NoThreadResource("server-thread")
						.add(new NoThreadResource("server-thread"))));
		server.add(new ConcurrentResource("single-threaded", 1)
					.add(new ConcurrentResource("single-threaded", 1)));
		server.add(new ConcurrentResource("four-threaded", 4)
					.add(new NoThreadResource("same-as-parent")
						.add(new NoThreadResource("same-as-parent"))));
		
		// Use an already created resource without executor as implementation
		// for a resource that has its own executor.
		server.add(ConcurrentCoapResource.createConcurrentCoapResource(2, new LegacyResource("legacy")));
		
		// start the server
		server.start();
	}
	
	/**
	 * A resource that uses the executor of its parent/ancestor if defined or
	 * the server's executor otherwise.
	 */
	private static class NoThreadResource extends CoapResource {
		
		public NoThreadResource(String name) {
			super(name);
		}
		
		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT,
					"You have been served by my parent's thread:"+Thread.currentThread().getName(),
					MediaTypeRegistry.TEXT_PLAIN);
		}
	}
	
	/**
	 * A resource with its own executor. Only threads of that executor will
	 * handle GET requests.
	 */
	private static class ConcurrentResource extends ConcurrentCoapResource {
		
		public ConcurrentResource(String name) {
			super(name);
		}
		
		public ConcurrentResource(String name, int threads) {
			super(name, threads);
		}
		
		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, "You have been served by one of my "+getThreadCount()+" threads: "+Thread.currentThread().getName(), MediaTypeRegistry.TEXT_PLAIN);
		}
		
		/**
		 * This method must only be executed by one thread at the time.
		 * Therefore, we make it synchronized. This does not affect handleGET()
		 * which can be executed concurrently.
		 */
		@Override
		public void handlePOST(CoapExchange exchange) {
			exchange.accept();
			synchronized (this) {
				try { Thread.sleep(5000); // waste some time
				} catch (Exception e) { e.printStackTrace(); }
				exchange.respond(ResponseCode.CONTENT, "Your POST request has been handled by one of my "+getThreadCount()+" threads: "+Thread.currentThread().getName());
			}
		}
	}
	
	/**
	 * An already existing resource that we want to use as implementation of a
	 * concurrent resource.
	 */
	private static class LegacyResource extends CoapResource {
		
		public LegacyResource(String name) { super(name); }
		
		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond("You have been served by "+Thread.currentThread());
		}
	}
}
