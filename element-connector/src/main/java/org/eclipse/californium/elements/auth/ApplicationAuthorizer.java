/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.elements.auth;

import java.security.Principal;
import java.util.concurrent.Future;

import org.eclipse.californium.elements.EndpointContext;

/**
 * Application authorize.
 * <p>
 * Sets {@link Principal} from application layers. Used with
 * {@code DtlsConfig.DTLS_APPLICATION_AUTHORIZATION} to authorize or reject
 * anonymous clients.
 * 
 * @since 4.0
 */
public interface ApplicationAuthorizer {

	/**
	 * Authorize the associated connection with the {@link ApplicationPrincipal}
	 * to prevent connection from being removed after in short time.
	 * <p>
	 * The Authorization may be processed asynchronous. A future request
	 * therefore may still not contain the provided principal! Only if the
	 * connection has not already a principal assigned, the provided one will be
	 * assigned.
	 * 
	 * @param context endpoint context
	 * @param principal anonymous principal
	 * @return future with boolean result. Completes with {@code true}, if the
	 *         principal was assigned, {@code false}, otherwise.
	 */
	Future<Boolean> authorize(EndpointContext context, ApplicationPrincipal principal);

	/**
	 * Reject authorization.
	 * 
	 * @param context endpoint context to reject authorization.
	 * @return future completes with removing the connection.
	 */
	Future<Void> rejectAuthorization(EndpointContext context);

}
