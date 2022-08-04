/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;

import javax.security.auth.Destroyable;

/**
 * Resource parser.
 * 
 * @since 3.12
 */
public interface ResourceParser<T extends ResourceParser<T>> extends Destroyable {

	/**
	 * Write resource.
	 * 
	 * @param writer writer to save resource
	 * @throws IOException if an I/O error occurred
	 */
	void save(Writer writer) throws IOException;

	/**
	 * Load resource.
	 * 
	 * @param reader reader for configuration.
	 * @throws IOException if an I/O error occurred
	 */
	void load(Reader reader) throws IOException;

	/**
	 * Create resource parser.
	 * 
	 * @return created resource parser
	 */
	T create();
}
