/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

/**
 * Configurable test scope and coverage.
 * 
 * Executes intensive tests, which are very time consuming, only on demand.
 * 
 * @since 2.4
 */
public class TestScope {

	private static final boolean INTENSIVE_TESTS;

	static {
		INTENSIVE_TESTS = StringUtil.getConfigurationBoolean("INTENSIVE_TESTS");
		System.out.println("INTENSIVE TEST " + INTENSIVE_TESTS);
	}

	/**
	 * Check, if (time) intensive test are enabled.
	 * 
	 * @return {@code true}, enable (time) intensive tests are enabled,
	 *         {@code false}, otherwise.
	 */
	public static boolean enableIntensiveTests() {
		return INTENSIVE_TESTS;
	}

	private TestScope() {
	}
}
