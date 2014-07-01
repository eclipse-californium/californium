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
 * Julien Vermillard - Sierra Wireless
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory pre-shared-key storage. To be used only for testing and evaluation. 
 * You are supposed to store your key in a secure way: 
 * keeping them in-memory is not a good idea.
 */
public class InMemoryPskStore implements PskStore {

    private Map<String, byte[]> keys = new ConcurrentHashMap<>();

    @Override
    public byte[] getKey(String identity) {
        byte[] key = keys.get(identity);
        if (key == null) {
            return null;
        } else {
            // defensive copy
            return Arrays.copyOf(key, key.length);
        }
    }

    /**
     * Set a key value for a given identity.
     * 
     * @param identity the identity associated with the key
     * @param key the key used to authenticate the identity
     */
    public void setKey(String identity, byte[] key) {
        keys.put(identity, key);
    }
}