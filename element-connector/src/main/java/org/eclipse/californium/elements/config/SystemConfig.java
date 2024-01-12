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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;

/**
 * Configuration definitions for basics.
 * 
 * @since 3.0
 */
public final class SystemConfig {

	public static final String MODULE = "SYS.";

	/**
	 * Default health status interval. {@code 0} for disabled.
	 */
	public static final TimeDefinition HEALTH_STATUS_INTERVAL = new TimeDefinition(
			MODULE + "HEALTH_STATUS_INTERVAL", "Health status interval. 0 to disable the health status.", 0,
			TimeUnit.SECONDS);

	public static final ModuleDefinitionsProvider DEFINITIONS = new ModuleDefinitionsProvider() {

		@Override
		public String getModule() {
			return MODULE;
		}

		@Override
		public void applyDefinitions(Configuration config) {

			// 0 for disable
			config.set(HEALTH_STATUS_INTERVAL, 0, TimeUnit.SECONDS);
			DefinitionUtils.verify(SystemConfig.class, config);
		}
	};
	
	static {
		Configuration.addDefaultModule(DEFINITIONS);
	}

	/**
	 * Register definitions of this module to the default definitions.
	 */
	public static void register() {
		// empty
	}
}
