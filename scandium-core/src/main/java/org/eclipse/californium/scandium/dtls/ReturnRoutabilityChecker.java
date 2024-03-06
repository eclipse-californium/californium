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

import java.util.List;
import java.util.concurrent.ScheduledFuture;

import org.eclipse.californium.elements.RawData;

/**
 * Return routability check message.
 * <p>
 * See <a href= "https://tlswg.org/dtls-rrc/draft-ietf-tls-dtls-rrc.html" target
 * ="_blank">dtls-rrc/draft-ietf-tls-dtls-rrc, Return Routability Check for DTLS
 * 1.2 and DTLS 1.3</a>.
 * 
 * @since 3.12
 */
public final class ReturnRoutabilityChecker {

	private final DeferredApplicationData deferredApplicationData;
	private final ReturnRoutabilityCheckMessage challenge;

	private ScheduledFuture<?> timeoutTask;

	public ReturnRoutabilityChecker(int max) {
		deferredApplicationData = new DeferredApplicationData(max);
		challenge = new ReturnRoutabilityCheckMessage(ReturnRoutabilityCheckType.PATH_CHALLENGE, null);
	}

	public DTLSMessage getChallenge() {
		return challenge;
	}

	public void setTimeout(ScheduledFuture<?> timeout) {
		if (this.timeoutTask != null) {
			this.timeoutTask.cancel(false);
		}
		this.timeoutTask = timeout;
	}

	public boolean match(ReturnRoutabilityCheckMessage reply) {
		boolean match = challenge.equalsCookie(reply);
		if (match) {
			setTimeout(null);
		}
		return match;
	}

	/**
	 * Add outgoing application data for deferred processing.
	 * 
	 * @param outgoingMessage outgoing application data
	 */
	public void addApplicationDataForDeferredProcessing(RawData outgoingMessage) {
		deferredApplicationData.add(outgoingMessage);
	}

	/**
	 * Take deferred outgoing application data.
	 * 
	 * @return list of application data
	 */
	public List<RawData> takeDeferredApplicationData() {
		return deferredApplicationData.take();
	}

	public static ReturnRoutabilityCheckMessage createResponse(ReturnRoutabilityCheckMessage challenge) {
		return create(ReturnRoutabilityCheckType.PATH_RESPONSE, challenge);
	}

	public static ReturnRoutabilityCheckMessage createDrop(ReturnRoutabilityCheckMessage challenge) {
		return create(ReturnRoutabilityCheckType.PATH_DROP, challenge);
	}

	private static ReturnRoutabilityCheckMessage create(ReturnRoutabilityCheckType type,
			ReturnRoutabilityCheckMessage challenge) {
		if (challenge == null) {
			throw new NullPointerException("challenge must not be null!");
		}
		if (challenge.getReturnRoutabilityCheckType() != ReturnRoutabilityCheckType.PATH_CHALLENGE) {
			throw new IllegalArgumentException(
					"challenge type must be PATH_CHALLENGE, not " + challenge.getReturnRoutabilityCheckType() + "!");
		}
		return new ReturnRoutabilityCheckMessage(type, challenge.getCookie());
	}

}
