/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.core.coap.Token;

/**
 * 
 * Interface for the OSCORE context database.
 *
 */
public interface OSCoreCtxDB {

	/**
	 * @param cid the context identifier
	 * @return the OSCore context
	 */
	public OSCoreCtx getContext(byte[] cid);

	/**
	 * Retrieve a context also using the ID Context
	 * 
	 * @param cid the context identifier
	 * @param IDContext the ID context
	 * @return the OSCore context
	 * @throws CoapOSException when retrieving with RID only and multiple
	 *             matching contexts are found
	 */
	public OSCoreCtx getContext(byte[] cid, byte[] IDContext) throws CoapOSException;

	/**
	 * @param token the token of the request
	 * @return the OSCore context
	 */
	public OSCoreCtx getContextByToken(Token token);

	/**
	 * @param token the token of the request
	 * @param ctx the OSCore context
	 */
	public void addContext(Token token, OSCoreCtx ctx);

	/**
	 * @param uri the uri of the recipient
	 * @param ctx the OSCore context to use with this recipient
	 * @throws OSException error while adding context
	 */
	public void addContext(String uri, OSCoreCtx ctx) throws OSException;

	/**
	 * Save the context by cid
	 * 
	 * @param ctx the OSCore context
	 */
	public void addContext(OSCoreCtx ctx);

	/**
	 * Remove a context
	 * 
	 * @param ctx the OSCore context
	 */
	void removeContext(OSCoreCtx ctx);

	/**
	 * @param uri the recipient's uri
	 * @return the OSCore context
	 * @throws OSException error while fetching context
	 */
	public OSCoreCtx getContext(String uri) throws OSException;

	/**
	 * @param token the token
	 * @return {@code true}, if an association for this token exists,
	 *         {@code false}, otherwise
	 */
	public boolean tokenExist(Token token);

	/**
	 * purge all contexts
	 */
	public void purge();

	/**
	 * Removes associations for this token, except for the generator
	 * 
	 * @param token token to be removed
	 */
	public void removeToken(Token token);
}
