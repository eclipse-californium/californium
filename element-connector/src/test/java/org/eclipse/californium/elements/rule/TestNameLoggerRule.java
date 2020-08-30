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

	@Override
	protected void starting(Description description) {
		LOGGER.info("Test {}", description.getMethodName());
	}

	@Override
	protected void finished(Description description) {
		LOGGER.info("Test {}", description.getMethodName());
	}
}
