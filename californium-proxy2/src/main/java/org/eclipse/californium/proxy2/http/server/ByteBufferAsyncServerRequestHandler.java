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
package org.eclipse.californium.proxy2.http.server;

import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.nio.AsyncRequestConsumer;
import org.apache.hc.core5.http.nio.AsyncServerRequestHandler;
import org.apache.hc.core5.http.nio.support.BasicRequestConsumer;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.eclipse.californium.proxy2.http.ContentTypedEntity;
import org.eclipse.californium.proxy2.http.ContentTypedEntityConsumer;

/**
 * Server request handler for {@link ContentTypedEntity}.
 */
public abstract class ByteBufferAsyncServerRequestHandler
		implements AsyncServerRequestHandler<Message<HttpRequest, ContentTypedEntity>> {

	@Override
	public AsyncRequestConsumer<Message<HttpRequest, ContentTypedEntity>> prepare(final HttpRequest request,
			final EntityDetails entityDetails, final HttpContext context) throws HttpException {
		ContentTypedEntityConsumer consumer = entityDetails != null ? new ContentTypedEntityConsumer() : null;
		return new BasicRequestConsumer<ContentTypedEntity>(consumer);
	}

}
