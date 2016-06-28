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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.KeyMID;


/**
 * The deduplicator has to detect duplicates. Notice that CONs and NONs can be
 * duplicates.
 */
public interface Deduplicator {

	/**
	 * Starts the deduplicator
	 */
	void start();

	/**
	 * Stops the deduplicator. The deduplicator should NOT clear its state.
	 */
	void stop();

	/**
	 * Checks if the specified key is already associated with a previous
	 * exchange and otherwise associates the key with the exchange specified. 
	 * This method can also be though of as 'put if absent'. This is equivalent 
	 * to
     * <pre>
     *   if (!duplicator.containsKey(key))
     *       return duplicator.put(key, value);
     *   else
     *       return duplicator.get(key);
     * </pre>
     * except that the action is performed atomically.
	 * 
	 * @param key the key
	 * @param exchange the exchange
	 * @return the previous exchange associated with the specified key, or
     *         <tt>null</tt> if there was no mapping for the key.
	 */
	Exchange findPrevious(KeyMID key, Exchange exchange);

	Exchange find(KeyMID key);

	boolean isEmpty();

	/**
	 * Clears the state of this deduplicator.
	 */
	void clear();
}
