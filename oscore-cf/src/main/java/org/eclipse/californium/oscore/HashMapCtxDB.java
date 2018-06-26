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
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.Token;

/**
 * 
 * Implements the OSCoreCtxDB interface with HashMaps.
 *
 */
public class HashMapCtxDB implements OSCoreCtxDB {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(HashMapCtxDB.class.getName());

	private HashMap<ByteId, OSCoreCtx> ridMap;
	private HashMap<Token, OSCoreCtx> tokenMap;
	private HashMap<String, OSCoreCtx> uriMap;
	private HashMap<Token, Integer> seqMap;

	private ArrayList<Token> allTokens;

	private static volatile HashMapCtxDB singleton = null;

	/**
	 * Create the database
	 */
	private HashMapCtxDB() {

		// Prevent form the reflection api.
		if (singleton != null) {
			throw new RuntimeException("Use getInstance() method to get the single instance of this class.");
		}

		this.tokenMap = new HashMap<>();
		this.ridMap = new HashMap<>();
		this.uriMap = new HashMap<>();
		this.seqMap = new HashMap<>();
		this.allTokens = new ArrayList<Token>();
	}

	/**
	 * @return the singleton instance of this context database
	 */
	public static HashMapCtxDB getInstance() {
		if (singleton == null) {

			synchronized (HashMapCtxDB.class) {
				if (singleton == null) {
					singleton = new HashMapCtxDB();
				}
			}
		}
		return singleton;
	}

	@Override
	public OSCoreCtx getContext(byte[] rid) {
		if (rid != null) {
			return ridMap.get(new ByteId(rid));
		} else {
			LOGGER.error(Error.BYTE_ARRAY_NULL);
			throw new NullPointerException(Error.BYTE_ARRAY_NULL);
		}
	}

	@Override
	public OSCoreCtx getContextByToken(Token token) {
		if (token != null) {
			return tokenMap.get(token);
		} else {
			LOGGER.error(Error.TOKEN_NULL);
			throw new NullPointerException(Error.TOKEN_NULL);
		}
	}

	@Override
	public OSCoreCtx getContext(String uri) throws OSException {
		if (uri != null) {
			return uriMap.get(normalizeServerUri(uri));
		} else {
			LOGGER.error(Error.STRING_NULL);
			throw new NullPointerException(Error.STRING_NULL);
		}
	}

	@Override
	public void addContext(Token token, OSCoreCtx ctx) {
		if (token != null) {
			if (!tokenExist(token)) {
				allTokens.add(token);
			}
			tokenMap.put(token, ctx);
		}
		addContext(ctx);
	}

	@Override
	public void addContext(String uri, OSCoreCtx ctx) throws OSException {
		if (uri != null) {
			uriMap.put(normalizeServerUri(uri), ctx);
		}
		addContext(ctx);
	}

	@Override
	public void addContext(OSCoreCtx ctx) {
		if (ctx != null) {
			ridMap.put(new ByteId(ctx.getRecipientId()), ctx);
		} else {
			LOGGER.error(Error.CONTEXT_NULL);
			throw new NullPointerException(Error.CONTEXT_NULL);
		}
	}

	@Override
	public Integer getSeqByToken(Token token) {
		if (token != null) {
			return seqMap.get(token);
		} else {
			LOGGER.error(Error.TOKEN_NULL);
			throw new NullPointerException(Error.TOKEN_NULL);
		}
	}

	@Override
	public void addSeqByToken(Token token, Integer seq) {
		if (seq == null || seq < 0) {
			throw new NullPointerException(Error.SEQ_NBR_INVALID);
		}
		if (token == null) {
			throw new NullPointerException(Error.TOKEN_NULL);
		}
		if (tokenExist(token)) {
			LOGGER.info("Token exists, but this could be a refresh if not there is a problem");
		} else {
			allTokens.add(token);
		}
		seqMap.put(token, seq);
	}

	@Override
	public boolean tokenExist(Token token) {
		if (token != null) {
			return allTokens.contains(token);
		} else {
			LOGGER.error(Error.TOKEN_NULL);
			throw new NullPointerException(Error.TOKEN_NULL);
		}
	}

	@Override
	public void removeSeqByToken(Token token) {
		if (token != null) {
			seqMap.remove(token);
			removeTokenIf(token);
		} else {
			LOGGER.error(Error.TOKEN_NULL);
			throw new NullPointerException(Error.TOKEN_NULL);
		}
	}

	@Override
	public synchronized void updateSeqByToken(Token token, Integer seq) {
		if (tokenExist(token)) {
			addSeqByToken(token, seq);
		}
	}

	/**
	 * Normalize the request uri.
	 * 
	 * @param uri the request uri
	 * @return the normalized uri
	 *
	 * @throws OSMyError
	 */
	private static String normalizeServerUri(String uri) throws OSException {
		String normalized = null;
		try {
			normalized = (new URI(uri)).getHost();
		} catch (URISyntaxException e) {
			LOGGER.error("Error in the request URI: " + uri + " message: " + e.getMessage());
			throw new OSException(e.getMessage());
		}
		return normalized;
	}

	private void removeTokenIf(Token token) {
		if (!tokenMap.containsKey(token) && !seqMap.containsKey(token)) {
			allTokens.remove(token);
		}
	}

	/**
	 * Removes associations for this token, except for the generator
	 * 
	 * @param token
	 */
	@Override
	public void removeToken(Token token) {
		tokenMap.remove(token);
		seqMap.remove(token);
	}

	/**
	 * Used mainly for test purpose, to purge the db of all contexts
	 */
	@Override
	public void purge() {
		ridMap.clear();
		tokenMap.clear();
		uriMap.clear();
		seqMap.clear();
		allTokens = new ArrayList<Token>();
	}
}
