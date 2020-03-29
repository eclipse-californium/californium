/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.net.SocketException;

import org.eclipse.californium.elements.util.NetworkInterfacesUtil;

/**
 * Utility class to determine MTU.
 * 
 * @deprecated use {@link NetworkInterfacesUtil} instead.
 */
@Deprecated
public class MtuUtil {

	/**
	 * Maximum UDP MTU.
	 * 
	 * @deprecated use {@link NetworkInterfacesUtil#MAX_MTU} instead.
	 */
	public static final int MAX_MTU = 65535;

	/**
	 * Get MTU for any interface.
	 * 
	 * Determine the smallest MTU of all network interfaces.
	 * 
	 * @return MTU in bytes
	 * @throws SocketException if an i/o error occurred
	 * @deprecated use {@link NetworkInterfacesUtil#getAnyMtu()} instead.
	 */
	public static int getAnyMtu() throws SocketException {
		return NetworkInterfacesUtil.getAnyMtu();
	}
}
