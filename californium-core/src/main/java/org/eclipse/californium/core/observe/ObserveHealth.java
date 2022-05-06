/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
package org.eclipse.californium.core.observe;

/**
 * Observe health interface.
 * 
 * Used by the {@link ObserveManager} to report the statistic events.
 * 
 * @since 3.6
 */
public interface ObserveHealth {

	/**
	 * Report current number of observe relations.
	 * 
	 * @param observeRelations current number of observe relations
	 */
	void setObserveRelations(int observeRelations);

	/**
	 * Report current number of observing endpoints.
	 * 
	 * @param observeEndpoints current number of observing endpoints
	 */
	void setObserveEndpoints(int observeEndpoints);

	/**
	 * Report a received observe request.
	 */
	void receivingObserveRequest();

	/**
	 * Report a received cancel-observe request.
	 */
	void receivingCancelRequest();

	/**
	 * Report a received reject for a notification.
	 */
	void receivingReject();
}
