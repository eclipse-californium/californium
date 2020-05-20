/*******************************************************************************
 * Copyright (c) 2020 Sierra Wireless and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * Extends MessageObserver to be notified when an error happens on response
 * handling.
 * 
 * @since 2.3
 */
@PublicAPIExtension(type = MessageObserver.class)
public interface MessageObserver2 extends MessageObserver {

	/**
	 * Invoked when an error happens during response handling.
	 * 
	 * @param cause The cause of the failure.
	 */
	void onResponseHandlingError(Throwable cause);
}
