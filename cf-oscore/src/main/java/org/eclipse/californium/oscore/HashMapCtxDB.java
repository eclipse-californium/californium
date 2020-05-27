/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.util.Bytes;

/**
 * 
 * Implements the OSCoreCtxDB interface with HashMaps.
 *
 */
public class HashMapCtxDB implements OSCoreCtxDB {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(HashMapCtxDB.class);

	// The outer HashMap has RID as key and the inner ID Context
	private HashMap<ByteId, HashMap<ByteId, OSCoreCtx>> contextMap;

	private HashMap<Token, OSCoreCtx> tokenMap;
	private HashMap<String, OSCoreCtx> uriMap;
	private HashMap<Token, Integer> seqMap;

	private ArrayList<Token> allTokens;

	/**
	 * Create the database
	 */
	public HashMapCtxDB() {

		this.tokenMap = new HashMap<>();
		this.contextMap = new HashMap<>();
		this.uriMap = new HashMap<>();
		this.seqMap = new HashMap<>();
		this.allTokens = new ArrayList<Token>();
	}

	/**
	 * Retrieve context using RID and ID Context. If the provided ID Context is
	 * null a result will be returned if there is only one unique context for
	 * that RID.
	 */
	@Override
	public synchronized OSCoreCtx getContext(byte[] rid, byte[] IDContext) throws CoapOSException {
		// Do not allow a null RID
		if (rid == null) {
			LOGGER.error(ErrorDescriptions.BYTE_ARRAY_NULL);
			throw new NullPointerException(ErrorDescriptions.BYTE_ARRAY_NULL);
		}

		HashMap<ByteId, OSCoreCtx> matchingRidMap = contextMap.get(new ByteId(rid));

		// No matching RID found at all
		if (matchingRidMap == null) {
			return null;
		}

		// If a RID was found get the specific context
		if (IDContext == null) {
			// If retrieving using only RID, there must be only 1 match maximum
			if (matchingRidMap.size() > 1) {
				throw new CoapOSException(ErrorDescriptions.CONTEXT_NOT_FOUND_IDCONTEXT, ResponseCode.UNAUTHORIZED);
			} else {
				// If only one entry return it
				Map.Entry<ByteId, OSCoreCtx> first = matchingRidMap.entrySet().iterator().next();
				return first.getValue();
			}

		} else {
			// If retrieving using both RID and ID Context
			return matchingRidMap.get(new ByteId(IDContext));
		}
	}

	/**
	 * Retrieve context using only RID when it is certain it is unique.
	 */
	@Override
	public synchronized OSCoreCtx getContext(byte[] rid) {
		HashMap<ByteId, OSCoreCtx> matchingRidMap = contextMap.get(new ByteId(rid));

		if (matchingRidMap == null) {
			return null;
		}

		if (matchingRidMap.size() > 1) {
			throw new RuntimeException("Attempting to retrieve context with only non-unique RID.");
		}

		Map.Entry<ByteId, OSCoreCtx> first = matchingRidMap.entrySet().iterator().next();
		return first.getValue();
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
			String normalizedUri = normalizeServerUri(uri);
			uriMap.put(normalizedUri, ctx);
			ctx.setUri(normalizedUri);
		}
		addContext(ctx);
	}

	@Override
	public synchronized void addContext(OSCoreCtx ctx) {
		if (ctx != null) {
			
			ByteId rid = new ByteId(ctx.getRecipientId());
			HashMap<ByteId, OSCoreCtx> ridMap = contextMap.get(rid);

			// If there is no existing map for this RID, create it
			if (ridMap == null) {
				ridMap = new HashMap<ByteId, OSCoreCtx>();
			}

			// Add the context to the RID map with ID context as key
			byte[] IDContext = ctx.getIdContext();
			if (IDContext == null) {
				IDContext = Bytes.EMPTY;
			}
			ridMap.put(new ByteId(IDContext), ctx);

			// Put the updated map for this RID in the context map
			contextMap.put(rid, ridMap);

		} else {
			LOGGER.error(ErrorDescriptions.CONTEXT_NULL);
			throw new NullPointerException(ErrorDescriptions.CONTEXT_NULL);
		}
	}

	@Override
	public synchronized void removeContext(OSCoreCtx ctx) {
		if (ctx != null) {

			ByteId rid = new ByteId(ctx.getRecipientId());
			HashMap<ByteId, OSCoreCtx> ridMap = contextMap.get(rid);

			// If there is no existing map for this RID return
			if (ridMap == null) {
				return;
			}

			// Remove the context from the RID map with ID context as key
			byte[] IDContext = ctx.getIdContext();
			if (IDContext == null) {
				IDContext = Bytes.EMPTY;
			}
			ridMap.remove(new ByteId(IDContext));

			if (ridMap.isEmpty()) {
				// If the RID map is now empty, remove it
				contextMap.remove(rid);
			} else {

				// Put the updated map for this RID in the context map
				contextMap.put(rid, ridMap);
			}

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
	 * @throws OSException on failure to parse the URI
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
				if (matcher.find()) {
					originalScope = matcher.group(1);
				}

				//Remove unsupported characters in scope before getting the host component
				normalized = (new URI(uri.replaceAll("[-._~]", ""))).getHost();

				//Find the modified new scope
				matcher = pattern.matcher(normalized);
				String newScope = null;
				if (matcher.find()) {
					newScope = matcher.group(1);
				}

				//Restore original scope for the IPv6 normalization
				//Otherwise getByName below will fail with "no such interface"
				//Since the scope is no longer matching the interface
				if (newScope != null && originalScope != null) {
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
		if (ipv6Addr instanceof Inet6Address) {
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
	 * @param token the token to remove
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
		contextMap.clear();
		tokenMap.clear();
		uriMap.clear();
		seqMap.clear();
		allTokens = new ArrayList<Token>();
	}
}
