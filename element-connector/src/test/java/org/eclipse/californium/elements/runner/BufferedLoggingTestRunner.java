/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.runner;

import org.eclipse.californium.elements.util.DirectDatagramSocketImpl;
import org.junit.runner.Description;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.InitializationError;

/**
 * Runner for tests under debugging.
 *
 * Extends {@link RepeatingTestRunner} to buffer messages when using the
 * {@link DirectDatagramSocketImpl} and log them only on failures.
 * 
 * <pre>
 * &#64;RunWith(BufferedLoggingTestRunner.class)
 * public class SomeTests {
 * </pre>
 */
public class BufferedLoggingTestRunner extends RepeatingTestRunner {

	public BufferedLoggingTestRunner(Class<?> klass) throws InitializationError {
		super(klass);
	}

	@Override
	public void run(final RunNotifier notifier) {
		notifier.addListener(new RunListener() {

			@Override
			public void testStarted(Description description) throws Exception {
				DirectDatagramSocketImpl.clearBufferLogging();
			}

			@Override
			public void testFailure(Failure failure) throws Exception {
				DirectDatagramSocketImpl.flushBufferLogging();
			}
		});
		super.run(notifier);
	}
}
