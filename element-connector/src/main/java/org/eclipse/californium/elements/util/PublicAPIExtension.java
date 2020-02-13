/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

/**
 * Mark interfaces, which are extension to public API interfaces. These
 * functions are intended to be merged into the public API interface with the
 * next major version. Migration will then be replace just the usage of this
 * interface with the public API interface.
 * @since 2.1
 */
public @interface PublicAPIExtension {

	/**
	 * Type of the public APi interface.
	 * 
	 * @return representing class of the public APi interface.
	 */
	Class<?> type();
}
