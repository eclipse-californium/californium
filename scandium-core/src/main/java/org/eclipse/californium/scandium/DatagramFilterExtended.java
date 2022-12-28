/*******************************************************************************
 * Copyright (c) 2022 AVSystem and others.
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
 *    Bartłomiej Wiśniewski (AVSystem) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import org.eclipse.californium.elements.util.PublicAPIExtension;
import org.eclipse.californium.scandium.dtls.Record;

import java.net.DatagramPacket;

/**
 * Extension of DatagramFilter.
 *
 * @since 3.8
 */
@PublicAPIExtension(type = DatagramFilter.class)
public interface DatagramFilterExtended {

	/**
	 * Called when a datagram packed is dropped. Allows to inject packet based action in form of callback.
	 * @param packet the dropped datagram packet
	 */
	void onDrop(DatagramPacket packet);
	/**
	 * Called when a record is dropped. Allows to inject record based action in form of callback.
	 * @param record the dropped record
	 */
	void onDrop(Record record);
}
