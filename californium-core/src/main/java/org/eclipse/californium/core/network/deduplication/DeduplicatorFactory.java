/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.core.network.config.NetworkConfig;


/**
 * The deduplication factory creates the deduplicator for a {@link Matcher}. If
 * a server wants to use another deduplicator than the three standard
 * deduplicators, it can create its own factory and install it with
 * {@link #setDeduplicatorFactory(DeduplicatorFactory)}.
 */
public class DeduplicatorFactory {

	/** The logger. */
	private static final Logger LOGGER = Logger.getLogger(DeduplicatorFactory.class.getCanonicalName());

	/** The factory. */
	private static DeduplicatorFactory factory;

	/**
	 * Returns the installed deduplicator factory.
	 * @return the deduplicator factory
	 */
	public static DeduplicatorFactory getDeduplicatorFactory() {
		if (factory == null) factory = new DeduplicatorFactory();
		return factory;
	}

	/**
	 * Installs the specified deduplicator factory.
	 * @param factory the factory
	 */
	public static void setDeduplicatorFactory(DeduplicatorFactory factory) {
		DeduplicatorFactory.factory = factory;
	}

	/**
	 * Creates a new deduplicator according to the specified configuration.
	 * @param config the configuration
	 * @return the deduplicator
	 */
	public Deduplicator createDeduplicator(final NetworkConfig config) {
		String type = config.getString(NetworkConfig.Keys.DEDUPLICATOR);
		if (NetworkConfig.Keys.DEDUPLICATOR_MARK_AND_SWEEP.equals(type)) {
			return new SweepDeduplicator(config);
		} else if (NetworkConfig.Keys.DEDUPLICATOR_CROP_ROTATION.equals(type)) {
			return new CropRotation(config);
		} else if (NetworkConfig.Keys.NO_DEDUPLICATOR.equals(type)) {
			return new NoDeduplicator();
		} else {
			LOGGER.log(Level.WARNING, "Unsupported deduplicator type: {0}", type);
			return new NoDeduplicator();
		}
	}

}
