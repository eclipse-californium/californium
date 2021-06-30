/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.core.network.deduplication;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The deduplication factory creates the deduplicator for a {@link Matcher}. If
 * a server wants to use another deduplicator than the three standard
 * deduplicators, it can create its own factory and install it with
 * {@link #setDeduplicatorFactory(DeduplicatorFactory)}.
 */
public class DeduplicatorFactory {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(DeduplicatorFactory.class);

	/** The factory. */
	private static DeduplicatorFactory factory;

	/**
	 * Returns the installed deduplicator factory.
	 * @return the deduplicator factory
	 */
	public static synchronized DeduplicatorFactory getDeduplicatorFactory() {

		if (factory == null) {
			factory = new DeduplicatorFactory();
		}
		return factory;
	}

	/**
	 * Installs the specified deduplicator factory.
	 * @param factory the factory
	 */
	public static synchronized void setDeduplicatorFactory(DeduplicatorFactory factory) {
		DeduplicatorFactory.factory = factory;
	}

	/**
	 * Creates a new deduplicator based on the value of the
	 * {@link CoapConfig#DEDUPLICATOR} configuration property.
	 * 
	 * @param config The configuration properties.
	 * @return The deduplicator to use.
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public Deduplicator createDeduplicator(final Configuration config) {

		String type = config.get(CoapConfig.DEDUPLICATOR);
		switch(type) {
		case CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP:
			return new SweepPerPeerDeduplicator(config);
		case CoapConfig.DEDUPLICATOR_MARK_AND_SWEEP:
			return new SweepDeduplicator(config);
		case CoapConfig.DEDUPLICATOR_CROP_ROTATION:
			return new CropRotation(config);
		case CoapConfig.NO_DEDUPLICATOR:
			return new NoDeduplicator();
		default:
			LOGGER.warn("configuration contains unsupported deduplicator type, duplicate detection will be turned off");
			return new NoDeduplicator();
		}
	}
}
