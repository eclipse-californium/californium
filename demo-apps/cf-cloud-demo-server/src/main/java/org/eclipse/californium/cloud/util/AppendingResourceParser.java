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
import java.io.Writer;

/**
 * Appending resource parser.
 * <p>
 * Keeps new entries for appending.
 * 
 * @since 3.13
 */
public interface AppendingResourceParser<T extends AppendingResourceParser<T>> extends ResourceParser<T> {

	/**
	 * Number of new entries.
	 * 
	 * @return number of new entries
	 */
	int sizeNewEntries();

	/**
	 * Clear new entries.
	 */
	void clearNewEntries();

	/**
	 * Write new entries to resource.
	 * 
	 * @param writer writer to save resource
	 * @throws IOException if an I/O error occurred
	 */
	void saveNewEntries(Writer writer) throws IOException;

}
