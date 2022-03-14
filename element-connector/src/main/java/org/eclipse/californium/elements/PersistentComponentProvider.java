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
package org.eclipse.californium.elements;

import java.util.Collection;

/**
 * Interface for providing persistent components.
 * 
 * @since 3.4
 */
public interface PersistentComponentProvider {

	/**
	 * Get persistent components.
	 * 
	 * @return collection with persistent components.
	 */
	Collection<PersistentComponent> getComponents();

}
