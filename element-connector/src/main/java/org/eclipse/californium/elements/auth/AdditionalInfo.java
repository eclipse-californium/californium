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
 *******************************************************************************/


package org.eclipse.californium.elements.auth;

import java.util.HashMap;
import java.util.Map;

/**
 * An unmodifiable wrapper around additional information about an authenticated peer.
 *
 */
public final class AdditionalInfo {

	private static final Map<String, Object> EMPTY_MAP = new HashMap<>(0);
	private final Map<String, Object> info;

	/**
	 * Creates new additional information.
	 * <p>
	 * A shallow copy of the given information is created in order
	 * to prevent modification of the info after creation.
	 * 
	 * @param additionalInfo The information or {@code null}.
	 */
	private AdditionalInfo(final Map<String, Object> additionalInfo) {
		if (additionalInfo == null) {
			info = EMPTY_MAP;
		} else {
			this.info = new HashMap<>(additionalInfo);
		}
	}

	/**
	 * Creates empty additional information.
	 * 
	 * @return The info.
	 */
	public static AdditionalInfo empty() {
		return new AdditionalInfo(null);
	}

	/**
	 * Creates new additional information.
	 * <p>
	 * A shallow copy of the given information is created in order
	 * to prevent modification of the info after creation.
	 * 
	 * @param info The information or {@code null}.
	 * @return The info.
	 */
	public static AdditionalInfo from(Map<String, Object> info) {
		return new AdditionalInfo(info);
	}

	/**
	 * Gets info for a key.
	 * 
	 * @param <T> The type of the value to get.
	 * @param key The key to get the value for.
	 * @param type The expected type of the value.
	 * @return The value or {@code null} if no value of the given type is
	 *         registered for the key.
	 */
	public <T> T get(final String key, final Class<T> type) {
		Object value = info.get(key);
		if (type.isInstance(value)) {
			return type.cast(value);
		} else {
			return null;
		}
	}
}
