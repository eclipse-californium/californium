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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Julien Vermillard - Sierra Wireless
 *******************************************************************************/

package org.eclipse.californium.scandium;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.eclipse.californium.scandium.dtls.cfg.ClientConnectorConfig;
import org.eclipse.californium.scandium.dtls.cfg.ServerConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * A class centralizing configuration options for the DTLS connector.
 */
public class DTLSConnectorConfig {

    /** the maximum fragment size before DTLS fragmentation must be applied */
    private int maxFragmentLength = 4096;
    
    /** The overhead for the record header (13 bytes) and the handshake header (12 bytes) is 25 bytes */
    private int maxPayloadSize = maxFragmentLength + 25;

    /** The initial timer value for retransmission; rfc6347, section: 4.2.4.1 */
    private int retransmissionTimeout = 1000;
    
    /** Maximal number of retransmissions before the attempt to transmit a message is canceled */
    private int maxRetransmit = 4;

    
    ClientConnectorConfig clientConfig = new ClientConnectorConfig();
    
    ServerConnectorConfig serverConfig = new ServerConnectorConfig();
   
    private DTLSConnector connector;
     
    public DTLSConnectorConfig(DTLSConnector connector) {
        this.connector = connector;
    }
    
    private void checkStarted() {
       if (connector.isRunning()) {
	        throw new IllegalStateException("can't configure the DTLS connector, it's already started");
       }
    }
    
    /**
	 * Set the Pre-shared key store for identifying the clients in PSK mode. 
	 * @param pskStore the key store for the client keys
	 */
	public void setServerPsk(PskStore pskStore) {
	    checkStarted();
	    serverConfig.pskStore = pskStore;   
	}
	
	/**
	 * Set the server key for raw private key or full X509 mode.
	 * @param key the private key identifying the server 
	 * @param certChain the chain of certificate for the server key
	 */
	public void setServerPrivateKey(PrivateKey key, Certificate[] certChain) {
	    checkStarted();
	    serverConfig.privateKey = key;
	    serverConfig.certChain = certChain;
	}
	
	/**
	 * Does the server require clients to authenticate.
	 * @param requireClientAuth set to <code>true</code> if you require the 
	 * clients to authenticate 
	 */
	public void setServerRequireClientAuth(boolean requireClientAuth) {
	    checkStarted();
	    serverConfig.requireClientAuth = requireClientAuth;
	}
	
	/**
	 * Set the client identity and pre shared secret key for PSK mode.
	 * @param identity the advertised client identity
	 * @param secret the shared secret (password)
	 */
	public void setClientPsk(String identity, byte[] secret) {
	    checkStarted();
	    clientConfig.pskIdentity = identity;
	    clientConfig.pskSecret = secret;
	}
	
	/**
	 * Set the client favorite cipher suite which is going to be placed a the 
	 * top of the advertised supported cipher suites.
	 * @param suite
	 */
	public void setClientPreferredCipherSuite(CipherSuite suite) {
	    checkStarted();
	    clientConfig.preferredCipherSuite = suite;
	}

	/**
     * Set the client key for raw private key or full X509 mode.
     * @param key the private key identifying the client 
     * @param certChain the chain of certificate for the client key
     * @param sendRawKey <code>true</code> the client send raw public cert, <code>false</code> for X509
     */
	public void setClientPrivateKey(PrivateKey key, Certificate[] certChain, boolean sendRawKey) {
	    checkStarted();
	    clientConfig.privateKey = key;
	    clientConfig.certChain = certChain;
	    clientConfig.sendRawKey = sendRawKey;
	}
	
    // SETTER/GETTER
    
    public int getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(int maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
    }

    public int getMaxPayloadSize() {
        return maxPayloadSize;
    }

    public void setMaxPayloadSize(int maxPayloadSize) {
        this.maxPayloadSize = maxPayloadSize;
    }

    public int getRetransmissionTimeout() {
        return retransmissionTimeout;
    }

    public void setRetransmissionTimeout(int retransmissionTimeout) {
        this.retransmissionTimeout = retransmissionTimeout;
    }

    public int getMaxRetransmit() {
        return maxRetransmit;
    }

    public void setMaxRetransmit(int maxRetransmit) {
        this.maxRetransmit = maxRetransmit;
    }
}
