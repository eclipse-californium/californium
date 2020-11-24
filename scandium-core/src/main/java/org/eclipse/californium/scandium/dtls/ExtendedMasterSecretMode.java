/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Extended master secret mode
 * <p>
 * See <a href="https://tools.ietf.org/html/rfc7627">RFC 7627</a> for additional
 * details.
 * 
 * @since 3.0
 */
public enum ExtendedMasterSecretMode {
	/**
	 * Disable the use of the extended master secret.
	 */
	NONE,
	/**
	 * Optionally use the extended master secret. Session without extended
	 * master secret may be resumed.
	 */
	OPTIONAL,
	/**
	 * Enable the use of the extended master secret. Session without extended
	 * master secret can not be resumed.
	 */
	ENABLED,
	/**
	 * Requires the use of the extended master secret.
	 */
	REQUIRED
}
