/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * A strategy for processing DTLS records.
 *
 */
public interface RecordProcessor {

	/**
	 * Processes a DTLS record.
	 * 
	 * @param record The record to process.
	 * @param connection The DTLS connection that the record has been received on.
	 */
	void process(Record record, Connection connection);
}
