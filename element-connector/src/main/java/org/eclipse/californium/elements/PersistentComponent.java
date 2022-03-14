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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Interface for supporting persistent components.
 * 
 * The API supports a freshness threshold for saving and a delta to adjust times
 * based on uptime-nanoseconds on loading. That is used to preserve timers based
 * on uptime, as long as the {@link System#currentTimeMillis()} reflects a
 * useful calendar time.
 * 
 * Note: the stream may contain not encrypted critical credentials. It is
 * required to protect this data before exporting it.
 * 
 * @since 3.4
 */
public interface PersistentComponent {

	/**
	 * Get label of persistent component.
	 * 
	 * Used to identify a component when loading.
	 * 
	 * If supported by a connector, then good candidate is the address of the
	 * local network interface. That only works, if the connector is restarted
	 * on the "same" machine with the same network interfaces. For other setups,
	 * e.g. k8s, where loading from a new machine may have new network
	 * interfaces, this doesn't work. Except, the "wildcard" address is used as
	 * local interface, thought that stays the same also on the new machine.
	 * Adding this label enables setups to use a more sophisticated identities
	 * (if required), as long as the setup maps the new connector in the same
	 * ip-path as the previous one.
	 * 
	 * @return identifying label of the persistent component. Must be unique for
	 *         all components serialized together.
	 */
	String getLabel();

	/**
	 * Save items of the persistent component.
	 * 
	 * Note: the stream may contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it.
	 * 
	 * @param out output stream to save items
	 * @param staleThresholdInSeconds stale threshold in seconds. e.g.
	 *            Connections without traffic for that time are skipped during
	 *            serialization.
	 * @return number of saved items.
	 * @throws IOException if an io-error occurred
	 * @throws IllegalStateException if persistent components has the wrong
	 *             state, e.g. a connector is running
	 */
	int save(OutputStream out, long staleThresholdInSeconds) throws IOException;

	/**
	 * Load items of the persistent component.
	 * 
	 * Note: the stream may contain not encrypted critical credentials. It is
	 * required to protect this data.
	 * 
	 * @param in input stream to load items
	 * @param deltaNanos adjust-delta for nano-uptime in nanoseconds. If the
	 *            stream contains timestamps based on nano-uptime, this delta
	 *            should be applied on order to adjust these timestamps
	 *            according the current nano uptime and the passed real time.
	 * @return number of loaded items.
	 * @throws IOException if an io-error occurred. Indicates, that further
	 *             loading should be aborted.
	 * @throws IllegalArgumentException if an reading error occurred. Continue
	 *             to load other item-stores may work, that may be not affected
	 *             by this error.
	 */
	int load(InputStream in, long deltaNanos) throws IOException;

}
