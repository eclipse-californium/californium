/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Achim Kraus (Bosch.IO GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

/**
 * Shutdown {@link ConnectorUtil} and {@link ProcessUtil}.
 * 
 * @since 3.0
 */
public class ShutdownUtil {

	/**
	 * Shutdown both, the {@link ConnectorUtil} and the {@link ProcessUtil}.
	 * 
	 * Ensure, that both shutdowns are executed, even if one throws an
	 * exception.
	 * 
	 * @param connectorUtil connector utility. May be {@code null}.
	 * @param processUtil process utility. May be {@code null}.
	 * @throws InterruptedException if the shutdown is interrupted.
	 */
	public static void shutdown(ConnectorUtil connectorUtil, ProcessUtil processUtil) throws InterruptedException {
		try {
			if (connectorUtil != null) {
				connectorUtil.shutdown();
			}
		} finally {
			if (processUtil != null) {
				processUtil.shutdown();
			}
		}
	}

}
