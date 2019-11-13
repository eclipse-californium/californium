/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.SerialExecutor;

public class SyncSerialExecutor extends SerialExecutor {

	private boolean shutdown;

	public SyncSerialExecutor() {
		super(null);
	}

	@Override
	public void shutdown() {
		shutdown = true;
	}

	@Override
	public boolean isShutdown() {
		return shutdown;
	}

	/**
	 * Ensure, the jobs are executed synchronous with the test.
	 */
	@Override
	public void execute(final Runnable command) {
		if (!isShutdown()) {
			command.run();
		}
	}
}
