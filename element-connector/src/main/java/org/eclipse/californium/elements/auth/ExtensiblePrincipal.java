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

import java.security.Principal;

/**
 * A {@code Principal} that can be extended with additional information.
 *
 * @param <T> The type of the principal.
 */
public interface ExtensiblePrincipal<T extends Principal> extends Principal {

	/**
	 * Creates a shallow copy of this principal which contains additional information.
	 * <p>
	 * The additional information can be retrieved from the returned copy using the
	 * {@link #getExtendedInfo()} method.
	 * 
	 * @param additionInfo The additional information.
	 * @return The copy.
	 */
	T amend(AdditionalInfo additionInfo);

	/**
	 * Gets additional information about this principal.
	 * 
	 * @return An unmodifiable map of additional information for this principal.
	 *         The map will be empty if no additional information is available.
	 */
	AdditionalInfo getExtendedInfo();
}
