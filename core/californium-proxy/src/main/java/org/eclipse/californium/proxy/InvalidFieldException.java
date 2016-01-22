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
 *    Francesco Corazza - HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.IOException;


/**
 * The Class InvalidFieldException.
 */
public class InvalidFieldException extends TranslationException {
	private static final long serialVersionUID = 1L;

	public InvalidFieldException() {
		super();
	}

	public InvalidFieldException(String message) {
		super(message);
	}

	public InvalidFieldException(String string, IOException e) {
		super(string, e);
	}

	public InvalidFieldException(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidFieldException(Throwable cause) {
		super(cause);
	}
}
