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
 * This is a dummy implementation that does no deduplication. If a matcher
 * does not want to deduplicate incoming messages, it should use this
 * deduplicator instead of 'null'.
 */
public class NoDeduplicator implements Deduplicator {

	@Override
	public void start() { }

	@Override
	public void stop() { }

	@Override
	public Exchange findPrevious(KeyMID key, Exchange exchange) {
		return null;
	}

	@Override
	public Exchange find(KeyMID key) {
		return null;
	}

	@Override
	public void clear() { }

	@Override
	public boolean isEmpty() {
		return true;
	}
}
