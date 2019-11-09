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
 *    Bosch Software Innovations GmbH - initial creation
 *******************************************************************************/


package org.eclipse.californium.scandium.auth;

import java.security.Principal;

import org.eclipse.californium.elements.auth.AdditionalInfo;

/**
 * A strategy for retrieving additional (application level) information about an authenticated peer.
 */
public interface ApplicationLevelInfoSupplier {

    /**
     * Gets additional information about an authenticated peer.
     * 
     * @param peerIdentity The peer identity.
     * @return The additional information about the peer.
     */
	AdditionalInfo getInfo(Principal peerIdentity);
}
