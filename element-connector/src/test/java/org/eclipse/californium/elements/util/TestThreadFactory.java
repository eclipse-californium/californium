/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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

import java.util.concurrent.ThreadFactory;

/**
 * The default test thread factory.
 */
public class TestThreadFactory extends NamedThreadFactory {

	/**
	 * The default thread group for test threads.
	 */
	public static final ThreadGroup TEST_THREAD_GROUP = new ThreadGroup("Test"); //$NON-NLS-1$

	static {
		// reset daemon, may be set by parent group!
		TEST_THREAD_GROUP.setDaemon(false);
	}

	/**
	 * The default thread factory for tests.
	 */
	public static final ThreadFactory TEST_THREAD_FACTORY = new TestThreadFactory("Test"); //$NON-NLS-1$

	/**
	 * Creates a new factory and sets the thread group to test default group.
	 *
	 * @param threadPrefix the prefix, that becomes part of the name of all
	 *            threads, created by this factory.
	 */
	public TestThreadFactory(final String threadPrefix) {
		super(threadPrefix, TEST_THREAD_GROUP);
	}
}
