/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from DatagramReader
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * Exception while blockwise transfer.
 * 
 * @since 3.0
 */
public class BlockwiseTransferException extends Exception {

	private static final long serialVersionUID = 1357L;

	/**
	 * Indicates, if exchange is already complete by the blockwise transfer.
	 */
	private final boolean completed;

	private final ResponseCode code;

	/**
	 * Create blockwise transfer exception with not completed exchange.
	 * 
	 * @param message details message
	 */
	public BlockwiseTransferException(String message) {
		super(message);
		this.completed = false;
		this.code = null;
	}

	/**
	 * Create blockwise transfer exception with response code and not completed
	 * exchange.
	 * 
	 * @param message details message
	 * @param code response code
	 */
	public BlockwiseTransferException(String message, ResponseCode code) {
		super(message);
		this.completed = false;
		this.code = code;
	}

	/**
	 * Create blockwise transfer exception.
	 * 
	 * @param message details message
	 * @param completed {@code true}, if exchange is already completed by the
	 *            transfer, {@code false}, otherwise.
	 */
	public BlockwiseTransferException(String message, boolean completed) {
		super(message);
		this.completed = completed;
		this.code = null;
	}

	/**
	 * Indicates, if the exchange is already completed by the transfer.
	 * 
	 * @return {@code true}, if the exchange is already completed,
	 *         {@code false}, if not.
	 */
	public boolean isCompleted() {
		return completed;
	}

	/**
	 * Get response code.
	 * 
	 * @return response code, or {@code null}, if response must not be sent for
	 *         this exception.
	 */
	public ResponseCode getResponseCode() {
		return code;
	}

}
