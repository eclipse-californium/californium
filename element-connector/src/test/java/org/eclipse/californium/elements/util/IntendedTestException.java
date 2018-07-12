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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.PrintStream;
import java.io.PrintWriter;

/**
 * Intended exception during test.
 * 
 * Should be logged without stacktrace.
 */
public class IntendedTestException extends RuntimeException {

	private static final StackTraceElement[] EMPTY = new StackTraceElement[0];

	private static final long serialVersionUID = 1L;

	/**
	 * Create new intended exception during tests.
	 * 
	 * @param message exception message
	 */
	public IntendedTestException(String message) {
		super(message);
	}

	@Override
	public Throwable fillInStackTrace() {
		return this;
	}

	@Override
	public void setStackTrace(StackTraceElement[] stackTrace) {
		// ignored
	}

	@Override
	public StackTraceElement[] getStackTrace() {
		return EMPTY;
	}

	@Override
	public void printStackTrace() {
		// ignored
	}

	@Override
	public void printStackTrace(PrintStream s) {
		// ignored
	}

	@Override
	public void printStackTrace(PrintWriter s) {
		// ignored
	}
}
