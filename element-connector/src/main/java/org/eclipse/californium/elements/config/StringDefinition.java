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
 *    Bosch IO.GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

/**
 * String definition.
 * 
 * @since 3.0
 */
public class StringDefinition extends BasicDefinition<String> {

	/**
	 * Creates string definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @throws NullPointerException if key is {@code null}
	 */
	public StringDefinition(String key, String documentation) {
		super(key, documentation, String.class, null);
	}

	/**
	 * Creates string definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	public StringDefinition(String key, String documentation, String defaultValue) {
		super(key, documentation, String.class, defaultValue);
	}

	@Override
	public String getTypeName() {
		return "String";
	}

	@Override
	public String writeValue(String value) {
		return value;
	}

	@Override
	protected boolean useTrim() {
		return false;
	}

	@Override
	protected String parseValue(String value) {
		return value;
	}

}
