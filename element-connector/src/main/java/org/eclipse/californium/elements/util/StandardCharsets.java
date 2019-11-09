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
 *    Bosch Software Innovations GmbH - initial implementation
 *                                      fix for issue #567
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.nio.charset.Charset;

/**
 * Used standard character sets for californium.
 * 
 * Replacement of java.nio.charset.StandardCharsets, which requires java 1.7, to
 * support older android versions.
 */
public interface StandardCharsets {
	/**
	 * UTF 8 character set. Default for most cases in CoAP.
	 */
	Charset UTF_8 = Charset.forName("UTF-8");
	/**
	 * US ASCII character set. Used by some encryption functions.
	 */
	Charset US_ASCII = Charset.forName("US-ASCII");
	/**
	 * ISO 8859 1 character set. Used by some HTTP proxy functions.
	 */
	Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

}
