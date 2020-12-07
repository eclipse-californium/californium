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

import org.junit.rules.ExpectedException;

/**
 * Wrap deprecated {@link ExpectedException#none()} to suppress that warning.
 * 
 * Temporary work-around. May be replaced by test-redesign with java 8.
 * 
 * @since 3.0
 */
public class ExpectedExceptionWrapper {

	@SuppressWarnings("deprecation")
	static public ExpectedException none() {
		return ExpectedException.none();
	}
}
