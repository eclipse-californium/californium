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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove contextEstablished.
 *                                                    issue #311
 ******************************************************************************/
package org.eclipse.californium.core.network;


/**
 * The exchange observer can be added to an {@link Exchange} and will be invoked
 * when it has completed, i.e. when the last response has been sent and
 * acknowledged or after the exchange lifecycle time.
 */
public interface ExchangeObserver {

	/**
	 * Invoked when the exchange has completed.
	 * 
	 * @param exchange the exchange
	 */
	void completed(Exchange exchange);
}
