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

import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.nio.entity.AbstractBinAsyncEntityConsumer;
import org.apache.hc.core5.util.ByteArrayBuffer;

/**
 * Payload consumer with related {@link ContentType}.
 * 
 * @see ContentTypedEntity
 * @since 3.0
 */
public class ContentTypedEntityConsumer extends AbstractBinAsyncEntityConsumer<ContentTypedEntity> {

	private final ByteArrayBuffer buffer;
	private ContentType contentType;

	public ContentTypedEntityConsumer() {
		super();
		this.buffer = new ByteArrayBuffer(1024);
	}

	@Override
	protected void streamStart(final ContentType contentType) throws HttpException, IOException {
		this.contentType = contentType;
	}

	@Override
	protected int capacityIncrement() {
		return Integer.MAX_VALUE;
	}

	@Override
	protected void data(final ByteBuffer src, final boolean endOfStream) throws IOException {
		if (src == null) {
			return;
		}
		if (src.hasArray()) {
			buffer.append(src.array(), src.arrayOffset() + src.position(), src.remaining());
		} else {
			while (src.hasRemaining()) {
				buffer.append(src.get());
			}
		}
	}

	@Override
	protected ContentTypedEntity generateContent() throws IOException {
		return new ContentTypedEntity(contentType, buffer.toByteArray());
	}

	@Override
	public void releaseResources() {
		buffer.clear();
	}

}
