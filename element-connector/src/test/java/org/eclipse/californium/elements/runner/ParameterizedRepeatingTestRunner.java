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
 *    Bosch Software Innovations - initial implementation
 *                                 based on RepeatingTestRunner
 ******************************************************************************/
package org.eclipse.californium.elements.runner;

import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.Parameterized;

/**
 * Parameterized runner for tests under debugging.
 * 
 * Runs a parameterized test repeated until it fails or the maximum number of repeats is
 * reached.
 * 
 * <pre>
 * "org.eclipse.californium.elements.runner.TestRepeater.repeats", maximum number of repeats for test.
 * 0 := repeat test until failure. Default 100.
 * "org.eclipse.californium.elements.runner.TestRepeater.alive", interval in milliseconds.
 * 0 := disabled. Default: 1000
 * </pre>
 * 
 * To use, add runner to JUni test with
 * 
 * <pre>
 * &#64;RunWith(ParameterizedRepeatingTestRunner.class)
 * public class SomeTests {
 * </pre>
 * 
 * For execution with maven {@code -Dtest="XyzAbcTest" -DfailIfNoTests=false}
 * may be used.
 * 
 * Note: If used with "maven-surefire-plugin", parallel testing can not be used!
 */
public class ParameterizedRepeatingTestRunner extends Parameterized {

	private final TestRepeater repeater;

	public ParameterizedRepeatingTestRunner(Class<?> klass) throws Throwable {
		super(klass);
		repeater = new TestRepeater();
	}

	@Override
	public void run(final RunNotifier notifier) {
		repeater.run(new Runner() {

			@Override
			public void run(RunNotifier notifier) {
				ParameterizedRepeatingTestRunner.super.run(notifier);
			}

			@Override
			public Description getDescription() {
				return ParameterizedRepeatingTestRunner.this.getDescription();
			}
		}, notifier);
	}
}
