/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.elements.rule;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Rule to write test names using the logger.
 */
public class TestNameLoggerRule extends TestWatcher {

	public static final Logger LOGGER = LoggerFactory.getLogger(TestNameLoggerRule.class);

	private String name = "";

	/**
	 * Get current test name.
	 * 
	 * @return current test name, or empty string, if no current test name is
	 *         available.
	 * @since 3.0
	 */
	public synchronized String getName() {
		return name;
	}

	/**
	 * Set current test name.
	 * 
	 * @param name current test name, or "", when test gets finished.
	 * @since 3.0
	 */
	private synchronized void setName(String name) {
		this.name = name;
	}

	@Override
	protected void starting(Description description) {
		String name = description.getMethodName();
		setName(name);
		LOGGER.info("Test {}", name);
	}

	@Override
	protected void finished(Description description) {
		setName("");
		LOGGER.info("Test {}", description.getMethodName());
	}
}
