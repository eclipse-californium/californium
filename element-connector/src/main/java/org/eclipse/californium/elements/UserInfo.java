/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *                                      based on PreSharedKeyIdentity
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.security.Principal;

/**
 * A principal representing the URI user info.
 */
public class UserInfo implements Principal {

	private final String userInfo;

	/**
	 * Creates a new instance for a given user info.
	 * 
	 * @param userInfo user info
	 * @throws NullPointerException if the userInfo is {@code null}
	 */
	public UserInfo(String userInfo) {
		if (userInfo == null) {
			throw new NullPointerException("UserInfo must not be null");
		} else {
			this.userInfo = userInfo;
		}
	}

	@Override
	public String getName() {
		return userInfo;
	}

	@Override
	public String toString() {
		return new StringBuilder("UserInfo [").append(userInfo).append("]").toString();
	}

	@Override
	public int hashCode() {
		return userInfo.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof UserInfo)) {
			return false;
		}
		UserInfo other = (UserInfo) obj;
		return userInfo.equals(other.userInfo);
	}
}
