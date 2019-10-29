/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

/**
 * Utility class to determine MTU.
 */
public class MtuUtil {

	/**
	 * Maximum UDP MTU.
	 */
	public static final int MAX_MTU = 65535;

	/**
	 * MTU for any interface.
	 */
	private static int anyMtu;

	/**
	 * Get MTU for any interface.
	 * 
	 * Determine the smallest MTU of all network interfaces.
	 * 
	 * @return MTU in bytes
	 * @throws SocketException if an i/o error occurred
	 */
	public synchronized static int getAnyMtu() throws SocketException {
		if (anyMtu == 0) {
			int mtu = MAX_MTU;
			Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
			while (interfaces.hasMoreElements()) {
				NetworkInterface iface = interfaces.nextElement();
				int ifaceMtu = iface.getMTU();
				if (ifaceMtu > 0 && ifaceMtu < mtu) {
					mtu = ifaceMtu;
				}
			}
			anyMtu = mtu;
		}

		return anyMtu;
	}
}
