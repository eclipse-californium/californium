/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * Formatter intended to "format" a already formatted message.
 * 
 * Returns the {@link LogRecord#getMessage()}, which must be expanded before.
 */
public class BufferedOutputFormatter extends Formatter {

	/**
	 * {@inheritDoc}
	 * 
	 * Returns the {@link LogRecord#getMessage()}, which is intended to return
	 * the already expanded/formatted message.
	 */
	@Override
	public String format(LogRecord record) {
		return record.getMessage();
	}

}
