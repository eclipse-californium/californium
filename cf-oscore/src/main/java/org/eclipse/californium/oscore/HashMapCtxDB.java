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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
	public synchronized OSCoreCtx getContext(byte[] rid) {
		if (rid != null) {
			return ridMap.get(new ByteId(rid));
		} else {
			LOGGER.error(ErrorDescriptions.BYTE_ARRAY_NULL);
			throw new NullPointerException(ErrorDescriptions.BYTE_ARRAY_NULL);
		}
	}

	@Override
	public synchronized OSCoreCtx getContextByToken(Token token) {
		if (token != null) {
			return tokenMap.get(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	@Override
	public synchronized OSCoreCtx getContext(String uri) throws OSException {
		if (uri != null) {
			return uriMap.get(normalizeServerUri(uri));
		} else {
			LOGGER.error(ErrorDescriptions.STRING_NULL);
			throw new NullPointerException(ErrorDescriptions.STRING_NULL);
		}
	}

	@Override
	public synchronized void addContext(Token token, OSCoreCtx ctx) {
		if (token != null) {
			if (!tokenExist(token)) {
				allTokens.add(token);
			}
			tokenMap.put(token, ctx);
		}
		addContext(ctx);
	}

	@Override
	public synchronized void addContext(String uri, OSCoreCtx ctx) throws OSException {
		if (uri != null) {
			uriMap.put(normalizeServerUri(uri), ctx);
		}
		addContext(ctx);
	}

	@Override
	public synchronized void addContext(OSCoreCtx ctx) {
		if (ctx != null) {
			ridMap.put(new ByteId(ctx.getRecipientId()), ctx);
		} else {
			LOGGER.error(ErrorDescriptions.CONTEXT_NULL);
			throw new NullPointerException(ErrorDescriptions.CONTEXT_NULL);
		}
	}

	@Override
	public synchronized Integer getSeqByToken(Token token) {
		if (token != null) {
			return seqMap.get(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	@Override
	public synchronized void addSeqByToken(Token token, Integer seq) {
		if (seq == null || seq < 0) {
			throw new NullPointerException(ErrorDescriptions.SEQ_NBR_INVALID);
		}
		if (token == null) {
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
		if (tokenExist(token)) {
			LOGGER.info("Token exists, but this could be a refresh if not there is a problem");
		} else {
			allTokens.add(token);
		}
		seqMap.put(token, seq);
	}

	@Override
	public synchronized boolean tokenExist(Token token) {
		if (token != null) {
			return allTokens.contains(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	@Override
	public synchronized void removeSeqByToken(Token token) {
		if (token != null) {
			seqMap.remove(token);
			removeTokenIf(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
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
	 * @throws OSException
	 */
	private static String normalizeServerUri(String uri) throws OSException {
		String normalized = null;

		try {
			normalized = (new URI(uri)).getHost();
		} catch (URISyntaxException e) {
			// workaround for openjdk bug JDK-8199396.
			// some characters are not supported for the ipv6 scope.
			try {
				String patternString = "(%.*)]";
				Pattern pattern = Pattern.compile(patternString);

				//Save the original scope
				Matcher matcher = pattern.matcher(uri);
				String originalScope = null;
				if(matcher.find()) {
					originalScope = matcher.group(1);
				}

				//Remove unsupported characters in scope before getting the host component
				normalized = (new URI(uri.replaceAll("[-._~]", ""))).getHost();

				//Find the modified new scope
				matcher = pattern.matcher(normalized);
				String newScope = null;
				if(matcher.find()) {
					newScope = matcher.group(1);
				}

				//Restore original scope for the IPv6 normalization
				//Otherwise getByName below will fail with "no such interface"
				//Since the scope is no longer matching the interface
				if(newScope != null && originalScope != null) {
					normalized = normalized.replace(newScope, originalScope);
				}

			} catch (URISyntaxException e2) {
				LOGGER.error("Error in the request URI: " + uri + " message: " + e.getMessage());
				throw new OSException(e.getMessage());
			}
		}

		//Further normalization for IPv6 addresses
		//Normalization above can give different results depending on structure of IPv6 address
		InetAddress ipv6Addr = null;
		try {
			ipv6Addr = InetAddress.getByName(normalized);
		} catch (UnknownHostException e) {
			LOGGER.error("Error finding host of request URI: " + uri + " message: " + e.getMessage());
		}
		if(ipv6Addr instanceof Inet6Address) {
			normalized = ipv6Addr.getHostAddress();
		}

		return normalized;
	}

	private synchronized void removeTokenIf(Token token) {
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
	public synchronized void removeToken(Token token) {
		tokenMap.remove(token);
		seqMap.remove(token);
	}

	/**
	 * Used mainly for test purpose, to purge the db of all contexts
	 */
	@Override
	public synchronized void purge() {
		ridMap.clear();
		tokenMap.clear();
		uriMap.clear();
		seqMap.clear();
		allTokens = new ArrayList<Token>();
	}
}
