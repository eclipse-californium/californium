/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

/**
 * A factory to create executor services with daemon threads.
 */
public class DaemonThreadFactory extends NamedThreadFactory {

	/**
	 * Creates a new factory for a prefix.
	 * <p>
	 * Sets the thread group to the {@linkplain NamedThreadFactory#COAP_THREAD_GROUP default thread group}.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 */
	public DaemonThreadFactory(final String threadPrefix) {
		super(threadPrefix, null);
	}

	/**
	 * Creates a new factory for a prefix and thread group.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 * @param threadGroup The thread group that thread created by this factory should belong to,
	 *                    may be {@code null}.
	 */
	public DaemonThreadFactory(final String threadPrefix, final ThreadGroup threadGroup) {
		super(threadPrefix, threadGroup);
	}

	/**
	 * Always returns {@code true} since this is a factory for <em>daemon</em> threads.
	 * 
	 * @return {@code true}
	 */
	@Override
	protected boolean createDaemonThreads() {
		return true;
	}
}
