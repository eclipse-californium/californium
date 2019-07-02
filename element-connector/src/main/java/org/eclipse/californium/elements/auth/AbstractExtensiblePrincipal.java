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
 *******************************************************************************/


package org.eclipse.californium.elements.auth;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;


/**
 * A base class for implementing {@link ExtensiblePrincipal}s.
 *
 * @param <T> The type of the principal.
 */
public abstract class AbstractExtensiblePrincipal<T extends Principal> implements ExtensiblePrincipal<T> {

	private final Map<String, Principal> additionalInfo;

	/**
	 * Creates a new principal with no additional information.
	 */
	protected AbstractExtensiblePrincipal() {
		this(null);
	}

	/**
	 * Creates a new principal with additional information.
	 * 
	 * @param additionalInformation The additional information.
	 */
	protected AbstractExtensiblePrincipal(Map<String, Principal> additionalInformation) {
		if (additionalInformation == null) {
			this.additionalInfo = Collections.emptyMap();
		} else {
			this.additionalInfo = Collections.unmodifiableMap(additionalInformation);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final Map<String, Principal> getExtendedInfo() {
		return additionalInfo;
	}
}
