/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * Health extended interface for {@link DTLSConnector}.
 * 
 * Adds counter for connections.
 * 
 * @since 3.1
 */
@PublicAPIExtension(type = DtlsHealth.class)
public interface DtlsHealthExtended {

	/**
	 * Set number of connections.
	 * 
	 * @param count number of connections
	 */
	void setConnections(int count);
}
