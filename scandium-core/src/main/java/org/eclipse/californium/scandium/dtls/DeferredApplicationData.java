/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.eclipse.californium.elements.RawData;

/**
 * Handling of deferred application data.
 * 
 * @since 3.12
 */
public final class DeferredApplicationData implements Iterable<RawData> {

	private final int maxDeferredProcessedOutgoingApplicationDataMessages;
	private final List<RawData> deferredApplicationData = new ArrayList<RawData>();

	public DeferredApplicationData(int max) {
		maxDeferredProcessedOutgoingApplicationDataMessages = max;
	}

	/**
	 * Add outgoing application data for deferred processing.
	 * 
	 * @param outgoingMessage outgoing application data
	 */
	public void add(RawData outgoingMessage) {
		if (deferredApplicationData.size() < maxDeferredProcessedOutgoingApplicationDataMessages) {
			deferredApplicationData.add(outgoingMessage);
		}
	}

	/**
	 * Take deferred outgoing application data.
	 * 
	 * @return list of application data
	 */
	public List<RawData> take() {
		List<RawData> applicationData = new ArrayList<RawData>(deferredApplicationData);
		deferredApplicationData.clear();
		return applicationData;

	}

	/**
	 * Take deferred outgoing application data from provided deferred data.
	 * 
	 * @param deferredApplicationData deferred outgoing application data to take
	 */
	public void take(DeferredApplicationData deferredApplicationData) {
		this.deferredApplicationData.addAll(deferredApplicationData.take());
	}

	@Override
	public Iterator<RawData> iterator() {
		return deferredApplicationData.iterator();
	}
}
