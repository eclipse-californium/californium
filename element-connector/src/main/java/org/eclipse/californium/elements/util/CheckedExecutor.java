/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.elements.util;

import java.util.ConcurrentModificationException;
import java.util.concurrent.Executor;

/**
 * Checked owner executor.
 * 
 * @since 3.9
 */
public interface CheckedExecutor extends Executor {

	/**
	 * Assert, that the current thread executes the current job.
	 * 
	 * @throws ConcurrentModificationException if current thread doesn't execute
	 *             the current job
	 */
	void assertOwner();

	/**
	 * Check, if current thread executes the current job.
	 * 
	 * @return {@code true}, if current thread executes the current job,
	 *         {@code false}, otherwise.
	 */
	boolean checkOwner();

}
