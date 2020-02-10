/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

/**
 * InternalMessageObserverAdapter to prevent a message observer from being moved
 * for reregistration.
 */
public abstract class InternalMessageObserverAdapter extends MessageObserverAdapter implements InternalMessageObserver {

	@Override
	public boolean isInternal() {
		return true;
	}

}
