/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 * Julien Vermillard - Sierra Wireless
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

/**
 * A storage for pre-shared-key identity.
 */
public interface PskStore {
    
    /**
     * Get the key for a given identity.
     * @param identity the identity to authenticate
     * @return the key or <code>null</code> if not found
     */
    byte[] getKey(String identity);
    
    /**
     * Get Identity for a peer address, this is used 
     * when we need to initiate the connection. 
     * In this case we need to know the identity to use for the given peer
     * @param inetAddress address of the peer we want to connect to
     * @return The identity of peer or <code>null</code> if not found
     */
    String getIdentity(InetSocketAddress inetAddress);
}
