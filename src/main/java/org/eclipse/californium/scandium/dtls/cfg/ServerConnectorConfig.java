/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Julien Vermillard - Sierra Wireless
 ******************************************************************************/

package org.eclipse.californium.scandium.dtls.cfg;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * Internal class holding the server related DTLSConnector configuration.
 */
public class ServerConnectorConfig {

    /** store of the PSK for identifying client */
    public PskStore pskStore = null;
    
    /** do the server require the client to authenticate */
    public boolean requireClientAuth = true;
    
    /** the server private key for RPK and X509 mode */
    public PrivateKey privateKey = null;
    
    /** the server certificate for RPK and X509 mode */
    public Certificate[] certChain = null;
    
}
