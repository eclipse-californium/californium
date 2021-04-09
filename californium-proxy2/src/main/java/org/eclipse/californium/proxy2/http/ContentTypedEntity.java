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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.proxy2.http;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.nio.AsyncEntityProducer;
import org.apache.hc.core5.http.nio.entity.AsyncEntityProducers;

/**
 * Message payload with related {@link ContentType}.
 * 
 * Based on byte array for smaller and medium sized resources.
 * 
 * @see ContentTypedEntityConsumer
 * @since 3.0
 */
public class ContentTypedEntity {

	/**
	 * Payload of message.
	 */
	private final byte[] payload;
	/**
	 * Content type.
	 */
	private final ContentType contentType;

	/**
	 * Create instance from content type and payload.
	 * 
	 * @param contentType content type
	 * @param payload payload.
	 */
	public ContentTypedEntity(ContentType contentType, byte[] payload) {
		if (contentType == null) {
			throw new NullPointerException("content type must not be null!");
		}
		this.contentType = contentType;
		this.payload = payload != null && payload.length > 0 ? payload : null;
	}

	/**
	 * Get content type.
	 * 
	 * @return content type
	 */
	public ContentType getContentType() {
		return contentType;
	}

	/**
	 * Get payload.
	 * 
	 * @return payload as byte array, or {@code null}, for no or empty payload.
	 */
	public byte[] getContent() {
		return payload;
	}

	/**
	 * Create entity producer.
	 * 
	 * @return entity producer
	 */
	public AsyncEntityProducer createProducer() {
		return AsyncEntityProducers.create(payload, contentType);
	}

	/**
	 * Create entity producer from entity.
	 * 
	 * @param entity entity for producer
	 * @return entity producer, or {@code null}, if entity is {@code null}.
	 */
	public static AsyncEntityProducer createProducer(ContentTypedEntity entity) {
		return entity != null ? entity.createProducer() : null;
	}
}
