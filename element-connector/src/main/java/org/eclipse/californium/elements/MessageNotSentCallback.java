/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial version
 ******************************************************************************/
package org.eclipse.californium.elements;

public interface MessageNotSentCallback extends MessageCallback {

	/**
	 * Called when an outbound message could not be sent.
	 * If this is used as MessageCallback, a tcp based connector 
	 * should not reopen a connection and instead should call this method.
	 */
	void onNotSent();
}
