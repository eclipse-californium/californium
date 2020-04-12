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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * A connection store which adds support of close notify.
 * @since 2.1
 * @deprecated since 2.3 obsolete, see {@link Connection#close(Record)}.
 */
@Deprecated
public interface CloseSupportingConnectionStore {

	/**
	 * Remove a connection in the address-table in the store.
	 * 
	 * @param connection the connection to update.
	 * @return {@code true}, if removed, {@code false}, otherwise.
	 */
	boolean removeFromAddress(Connection connection);
}
