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
 * The Class TranslationException.
 */
public class TranslationException extends Exception {
	private static final long serialVersionUID = 1L;

	public TranslationException() {
		super();
	}

	public TranslationException(String message) {
		super(message);
	}

	public TranslationException(String string, IOException e) {
		super(string, e);
	}

	public TranslationException(String message, Throwable cause) {
		super(message, cause);
	}

	public TranslationException(Throwable cause) {
		super(cause);
	}
}
