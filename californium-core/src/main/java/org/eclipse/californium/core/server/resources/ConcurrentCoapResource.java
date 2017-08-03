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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.server.resources;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.util.NamedThreadFactory;

/**
 * A ConcurrentCoapResource is an extension to a typical CoapResource and
 * defines its own {@link Executor}. Arriving request to this resource and to
 * child resources that do not define their own executor will be process by this
 * executor. This class can be used in particular if a resource and potentially
 * its children require a single-threaded environment. In this case, use a
 * ConcurrentCoapResource with a thread-pool of size 1 as parent and
 * CoapResource for all its children.
 * <p>
 * The following example server contains several resources that have different
 * multi-threading policies. The three resources on top with the name
 * "server-thread" are normal resources that do not define their own executor.
 * Therefore, they all use their parent's executor which ultimately is the
 * server's. The resource "single-threaded" defines its own executor with one
 * thread. Therefore, all requests to that resource will be executed by the same
 * one thread. Its child again is a single-threaded resource that uses its very
 * own single-threaded executor. The resource "four-threaded" uses an executor
 * with four threads. Request can be (concurrently) processed by any of them.
 * The resource has a child and a grand-child that both are normal resources and
 * therefore also use the executor with four threads. Finally, the resource
 * "mt-large" reuses a normal resource as implementation but uses a new executor
 * to process the requests. For the client, the resource behaves exactly like
 * there were no executor.
 * <pre>
 * CoapServer server = new CoapServer();
 * server.add(new CoapResource("server-thread")
 *   .add(new CoapResource("server-thread")
 *     .add(new CoapResource("server-thread"))));
 * server.add(new ConcurrentResource("single-threaded", 1)
 *   .add(new ConcurrentResource("single-threaded", 1)));
 * server.add(new ConcurrentResource("four-threaded", 4)
 *   .add(new CoapResource("same-as-parent")
 *     .add(new CoapResource("same-as-parent"))));
 * 
 * server.add(ConcurrentCoapResource.createConcurrentResourceBase(2, new LargeResource("large")));
 * server.start();
 * </pre>
 * The resulting resource three looks like the following
 * <pre>
 * Root
 *  |
 *  |-- server-thread: executed by pool-1 (server threads)
 *  |    `-- server-thread: executed by pool-1 (server threads)
 *  |         `-- server-thread: executed by pool-1 (server threads)
 *  |
 *  |-- single-threaded: executed by pool-2 (1 thread)
 *  |    `-- single-threaded: executed by pool-3 (1 thread)
 *  |
 *  |-- four-threaded: executed by pool-4 (4 threads)
 *  |    `-- same-as-parent: executed by pool-4 (4 threads)
 *  |         `-- same-as-parent: executed by pool-4 (4 threads)
 *  |
 *  |-- large: executed by pool-5 (2 threads)
 * </pre>
 */
public class ConcurrentCoapResource extends CoapResource {
	
	/** The constant 1 for single threaded executors */
	public static int SINGLE_THREADED = 1;
	
	/** The number of threads. */
	private int threads;
	
	/** The executor of this resource or null */
	private ExecutorService executor;

	/**
	 * Constructs a new resource that uses an executor with as many threads as
	 * there are processors available.
	 * 
	 * @param name the name
	 */
	public ConcurrentCoapResource(String name) {
		super(name);
		this.threads = getAvailableProcessors();
		setExecutor(Executors.newFixedThreadPool(threads,
				new NamedThreadFactory("ConcurrentCoapResource-" + name + '#'))); //$NON-NLS-1$
	}
	
	/**
	 * Constructs a new resource that uses the specified amount of threads to
	 * process requests.
	 * 
	 * @param name the name
	 * @param threads the number of threads
	 */
	public ConcurrentCoapResource(String name, int threads) {
		super(name);
		this.threads = threads;
		setExecutor(Executors.newFixedThreadPool(threads,
				new NamedThreadFactory("ConcurrentCoapResource-" + name + '#'))); //$NON-NLS-1$
	}
	
	/**
	 * Constructs a new resource that uses the specified executor service to
	 * process requests.
	 * 
	 * @param name the name
	 * @param executor the executor service to use
	 */
	public ConcurrentCoapResource(String name, ExecutorService executor) {
		super(name);
		this.threads = -1;
		setExecutor(executor);
	}
	
	/**
	 * Sets the specified executor service to the resource.
	 * 
	 * @param executor the executor service
	 */
	public void setExecutor(ExecutorService executor) {
		this.executor = executor;
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.CoapResource#getExecutor()
	 */
	@Override
	public ExecutorService getExecutor() {
		if (executor != null) return executor;
		else return super.getExecutor();
	}
	
	/**
	 * Gets the number of available processors.
	 *
	 * @return the maximum number of processors available to the virtual
     *          machine; never smaller than one
	 */
	protected int getAvailableProcessors() {
		return Runtime.getRuntime().availableProcessors();
	}
	
	/**
	 * Gets the number of threads
	 *
	 * @return the thread count
	 */
	public int getThreadCount() {
		return threads;
	}

	/**
	 * Wraps the specified implementation in a ConcurrentCoapResource that uses
	 * the specified number of threads to process requests. This method can be
	 * used to reuse a given resource but with an own thread-pool.
	 * 
	 * @param threads the number of threads
	 * @param impl the implementation
	 * @return the wrapping resource
	 */
	public static ConcurrentCoapResource createConcurrentCoapResource(int threads, final Resource impl) {
		return new ConcurrentCoapResource(impl.getName(), threads) {
			@Override
			public void handleRequest(Exchange exchange) {
				impl.handleRequest(exchange);
			}
		};
	}
}
