/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Tobias Andersson (RISE SICS)
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
	 * @param uri the recipient's uri
	 * @return the OSCore context
	 * @throws OSException error while fetching context
	 */
	public OSCoreCtx getContext(String uri) throws OSException;

	/**
	 * Retrieves the sequence number associated by this token or null
	 * 
	 * @param token the token
	 * @return sequence number for this token or null if not existing
	 */
	public Integer getSeqByToken(Token token);

	/**
	 * Saves the sequence number associated by this token
	 * 
	 * @param seq the sequence number
	 * @param token the token
	 * @throws OSException error while saving sequence number
	 */
	public void addSeqByToken(Token token, Integer seq);

	/**
	 * @param token the token
	 * @return true if an association for this token exists, false otherwise
	 */
	public boolean tokenExist(Token token);

	/**
	 * @param token the token
	 */
	public void removeSeqByToken(Token token);

	/**
	 * @param token the token
	 * @param seq the sequence number
	 * @throws OSException
	 */
	public void updateSeqByToken(Token token, Integer seq);

	/**
	 * purge all contexts
	 */
	public void purge();

	/**
	 * Removes associations for this token, except for the generator
	 * 
	 * @param token
	 */
	public void removeToken(Token token);
}
