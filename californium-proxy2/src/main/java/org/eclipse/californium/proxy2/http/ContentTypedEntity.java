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
	 * @param contentType content type. May be {@code null}, if no payload is
	 *            provided.
	 * @param payload payload. For no payload provide {@code null} or an empty
	 *            array.
	 * @throws NullPointerException if contentType is null, but payload is
	 *             provided.
	 * @deprecated use {@link #create(ContentType, byte[])} instead.
	 */
	@Deprecated
	public ContentTypedEntity(ContentType contentType, byte[] payload) {
		this.payload = payload != null && payload.length > 0 ? payload : null;
		if (contentType == null && this.payload != null) {
			throw new NullPointerException("content type must not be null, if payload is provided!");
		}
		this.contentType = contentType;
	}

	/**
	 * Get content type.
	 * 
	 * @return content type, or {@code null}, if not provided
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
	 * @return entity producer, or {@code null}, if no content type is provided.
	 */
	public AsyncEntityProducer createProducer() {
		if (contentType != null) {
			return AsyncEntityProducers.create(payload, contentType);
		} else {
			return null;
		}
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

	/**
	 * Create instance from content type and payload.
	 * 
	 * @param contentType content type. May be {@code null}, if no payload is
	 *            provided.
	 * @param payload payload. For no payload provide {@code null} or an empty
	 *            array.
	 * @return entity, if content type is provided, {@code null}, otherwise.
	 * @throws NullPointerException if contentType is null, but payload is
	 *             provided.
	 * @since 3.13
	 */
	public static ContentTypedEntity create(ContentType contentType, byte[] payload) {
		ContentTypedEntity entity = new ContentTypedEntity(contentType, payload);
		if (entity.getContentType() != null) {
			return entity;
		}
		return null;
	}
}
