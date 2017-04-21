/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - make getOthers() public.
 *                                                    issue #286
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.eclipse.californium.core.Utils;

/**
 * OptionSet is a collection of all options of a request or a response.
 * OptionSet provides methods to add, remove and modify all options defined in
 * the CoAP, blockwise CoAP, observing CoAP and supports arbitrary defined
 * options.
 * <p>
 * Notice that this class is not entirely thread-safe: hasObserve =&gt; (int) getObserve()
 */
public final class OptionSet {

	private static final int MAX_OBSERVE_NO = (1 << 24) - 1;
	/*
	 * Options defined by the CoAP protocol
	 */
	private List<byte[]> if_match_list;
	private String       uri_host;
	private List<byte[]> etag_list;
	private boolean      if_none_match; // true if option is set
	private Integer      uri_port; // null if no port is explicitly defined
	private List<String> location_path_list;
	private List<String> uri_path_list;
	private Integer      content_format;
	private Long         max_age; // (0-4 bytes)
	private List<String> uri_query_list;
	private Integer      accept;
	private List<String> location_query_list;
	private String       proxy_uri;
	private String       proxy_scheme;
	private BlockOption  block1;
	private BlockOption  block2;
	private Integer      size1;
	private Integer      size2;
	private Integer      observe;
	
	// Arbitrary options
	private List<Option> others;
	
	// TODO: When receiving, uri_host/port should be those from the sender 
	/*
	 * Once a list is touched and constructed it must never become null again.
	 * Non-lists can be null though.
	 */
	public OptionSet() {
		if_match_list       = null; // new LinkedList<byte[]>();
		uri_host            = null; // from sender
		etag_list           = null; // new LinkedList<byte[]>();
		if_none_match       = false;
		uri_port            = null; // from sender
		location_path_list  = null; // new LinkedList<String>();
		uri_path_list       = null; // new LinkedList<String>();
		content_format      = null;
		max_age             = null;
		uri_query_list      = null; // new LinkedList<String>();
		accept              = null;
		location_query_list = null; // new LinkedList<String>();
		proxy_uri           = null;
		proxy_scheme        = null;
		block1              = null;
		block2              = null;
		size1               = null;
		size2               = null;
		observe             = null;
		
		others              = null; // new LinkedList<>();
	}

	public void clear() {
		if (if_match_list != null)
			if_match_list.clear();
		uri_host = null;
		if (etag_list != null)
			etag_list.clear();
		if_none_match = false;
		uri_port = null;
		if (location_path_list != null)
			location_path_list.clear();
		if (uri_path_list != null)
			uri_path_list.clear();
		content_format = null;
		max_age = null;
		if (uri_query_list != null)
			uri_query_list.clear();
		accept = null;
		if (location_query_list != null)
			location_path_list.clear();
		proxy_uri = null;
		proxy_scheme = null;
		block1 = null;
		block2 = null;
		observe = null;
		if (others != null)
			others.clear();
	}

	/**
	 * Instantiates a new option set equal to the specified one by deep-copying it.
	 * @param origin the origin to be copied
	 */
	public OptionSet(OptionSet origin) {
		if (origin == null) throw new NullPointerException();
		if_match_list       = copyList(origin.if_match_list);
		uri_host            = origin.uri_host;
		etag_list           = copyList(origin.etag_list);
		if_none_match       = origin.if_none_match;
		uri_port            = origin.uri_port;
		location_path_list  = copyList(origin.location_path_list);
		uri_path_list       = copyList(origin.uri_path_list);
		content_format      = origin.content_format;
		max_age             = origin.max_age;
		uri_query_list      = copyList(origin.uri_query_list);
		accept              = origin.accept;
		location_query_list = copyList(origin.location_query_list);
		proxy_uri           = origin.proxy_uri;
		proxy_scheme        = origin.proxy_scheme;
		
		if (origin.block1 != null)
			block1          = new BlockOption(origin.block1);
		if (origin.block2 != null)
			block2          = new BlockOption(origin.block2);
		
		observe = origin.observe;
		
		others              = copyList(origin.others);
	}

	/**
	 * Copy the specified list.
	 * @param <T> the generic type
	 * @param list the list
	 * @return a copy of the list
	 */
	private <T> List<T> copyList(List<T> list) {
		if (list == null) return null;
		else return new LinkedList<T>(list);
	}

	/////////////////////// Getter and Setter ///////////////////////

	/**
	 * Returns the list of If-Match ETags.
	 * The OptionSet uses lazy initialization for this list.
	 * @return the list of If-Match ETags
	 */
	public List<byte[]> getIfMatch() {
		synchronized (this) {
			if (if_match_list == null)
				if_match_list = new LinkedList<byte[]>();
		}
		return if_match_list;
	}

	/**
	 * Returns the number of If-Match options.
	 * @return the count
	 */
	public int getIfMatchCount() {
		return getIfMatch().size();
	}

	/**
	 * Checks if the If-Match options contain the given ETag.
	 * This method can be used by a server to handle a conditional request.
	 * When called, the method assumes the resource does exist, so that an empty If-Match option will match.
	 * The passed ETag should be the one by the server denoting the current resource state.
	 * @param check the ETag of the current resource state
	 * @return true if ETag matches or message contains an empty If-Match option
	 */
	public boolean isIfMatch(byte[] check) {
		
		// if no If-Match option is present, conditional update is allowed
		if (if_match_list==null) return true;
		
		for (byte[] etag:if_match_list) {
			// an empty If-Match option checks for existence of the resource
			if (etag.length==0) return true;
			if (Arrays.equals(etag, check)) return true;
		}
		return false;
	}

	/**
	 * Adds an ETag to the If-Match options.
	 * A byte array of size 0 adds an empty If-Match option,
	 * which checks for existence of the targeted resource.
	 * Returns the current OptionSet object for a fluent API.
	 * @param etag the If-Match ETag to add
	 * @return this OptionSet
	 */
	public OptionSet addIfMatch(byte[] etag) {
		if (etag==null)
			throw new IllegalArgumentException("If-Match option must not be null");
		if (etag.length > 8)
			throw new IllegalArgumentException("If-Match option must be smaller or equal to 8 bytes: "+Utils.toHexString(etag));
		getIfMatch().add(etag);
		return this;
	}

	/**
	 * Removes a specific ETag from the If-Match options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param etag the If-Match ETag to remove
	 * @return this OptionSet
	 */
	public OptionSet removeIfMatch(byte[] etag) {
		getIfMatch().remove(etag);
		return this;
	}

	/**
	 * Removes all If-Match options.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet clearIfMatchs() {
		getIfMatch().clear();
		return this;
	}

	/**
	 * Returns the string value of the Uri-Host option.
	 * @return the Uri-Host or null if the option is not present
	 */
	public String getUriHost() {
		return uri_host;
	}

	/**
	 * Checks if the Uri-Host option is present.
	 * @return true if present
	 */
	public boolean hasUriHost() {
		return uri_host != null;
	}

	/**
	 * Sets the Uri-Host option.
	 * Returns the current OptionSet object for a fluent API.
	 * @param host the Uri-Host value to set.
	 * @return this OptionSet
	 */
	public OptionSet setUriHost(String host) {
		if (host==null)
			throw new NullPointerException("URI-Host must not be null");
		if (host.length() < 1 || 255 < host.length())
			throw new IllegalArgumentException("URI-Host option's length must be between 1 and 255 inclusive");
		this.uri_host = host;
		return this;
	}

	/**
	 * Removes the Uri-Host option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeUriHost() {
		this.uri_host = null;
		return this;
	}

	/**
	 * Returns the list of ETags.
	 * In a response, there MUST only be one ETag that defines the
	 * payload or the resource given through the Location-* options.
	 * In a request, there can be multiple ETags for validation.
	 * The OptionSet uses lazy initialization for this list.
	 * @return the list of ETags
	 */
	public List<byte[]> getETags() {
		synchronized (this) {
			if (etag_list == null)
				etag_list = new LinkedList<byte[]>();
		}
		return etag_list;
	}

	/**
	 * Returns the number of ETag options.
	 * @return the count
	 */
	public int getETagCount() {
		return getETags().size();
	}

	/**
	 * Checks if the ETag options contain the passed ETag.
	 * This can be used by a server to respond to a validation request.
	 * The passed ETag should be the one by the server denoting the current resource state.
	 * @param check the ETag of the current resource state
	 * @return true if ETag is included
	 */
	public boolean containsETag(byte[] check) {
		if (etag_list==null) return false;
		for (byte[] etag:etag_list) {
			if (Arrays.equals(etag, check)) return true;
		}
		return false;
	}

	/**
	 * Adds an ETag to the ETag options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param etag the ETag to add
	 * @return this OptionSet
	 */
	public OptionSet addETag(byte[] etag) {
		if (etag==null)
			throw new IllegalArgumentException("ETag option must not be null");
		// TODO: ProxyHttp uses ETags that are larger than 8 bytes (20).
//		if (opaque.length < 1 || 8 < opaque.length)
//			throw new IllegalArgumentException("ETag option's length must be between 1 and 8 inclusive but was "+opaque.length);
		getETags().add(etag);
		return this;
	}

	/**
	 * Removes a specific ETag from the ETag options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param etag the ETag to remove
	 * @return this OptionSet
	 */
	public OptionSet removeETag(byte[] etag) {
		getETags().remove(etag);
		return this;
	}

	/**
	 * Removes all ETag options.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet clearETags() {
		getETags().clear();
		return this;
	}

	/**
	 * Checks if the If-None-Match option is present.
	 * @return true if present
	 */
	public boolean hasIfNoneMatch() {
		return if_none_match;
	}

	/**
	 * Sets or unsets the If-None-Match option.
	 * @param present the presence of the option
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet setIfNoneMatch(boolean present) {
		if_none_match = present;
		return this;
	}

	/**
	 * Returns the uint value of the Uri-Port option.
	 * @return the Uri-Port value or null if the option is not present
	 */
	public Integer getUriPort() {
		return uri_port;
	}

	/**
	 * Checks if the Uri-Port option is present.
	 * @return true if present
	 */
	public boolean hasUriPort() {
		return uri_port != null;
	}

	/**
	 * Sets the Uri-Port option.
	 * Returns the current OptionSet object for a fluent API.
	 * @param port the Uri-Port value to set.
	 * @return this OptionSet
	 */
	public OptionSet setUriPort(int port) {
		if (port < 0 || (1<<16)-1 < port)
			throw new IllegalArgumentException("URI port option must be between 0 and "+((1<<16)-1)+" (2 bytes) inclusive but was "+port);
		uri_port = port;
		return this;
	}

	/**
	 * Removes the Uri-Port option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeUriPort() {
		uri_port = null;
		return this;
	}

	/**
	 * Returns the list of Location-Path segment strings.
	 * The OptionSet uses lazy initialization for this list.
	 * @return the list of Location-Path segments
	 */
	public List<String> getLocationPath() {
		synchronized (this) {
			if (location_path_list == null)
				location_path_list = new LinkedList<String>();
		}
		return location_path_list;
	}

	/**
	 * Returns the Location-Path and Location-Query options as relative URI string.
	 * @return the Location-* as string
	 */
	public String getLocationString() {
		StringBuilder builder = new StringBuilder();
		builder.append("/");
		builder.append(getLocationPathString());
		if (getLocationQueryCount()>0) {
			builder.append("?");
			builder.append(getLocationQueryString());
		}
		return builder.toString();
	}

	/**
	 * Returns the Location-Path options as relative URI string.
	 * @return the Location-Path as string
	 */
	public String getLocationPathString() {
		StringBuilder builder = new StringBuilder();
		for (String segment:getLocationPath())
			builder.append(segment).append("/");
		if (builder.length() > 0)
			builder.delete(builder.length() - 1, builder.length());
		return builder.toString();
	}

	/**
	 * Returns the number of Location-Path options (i.e., path segments).
	 * @return the count
	 */
	public int getLocationPathCount() {
		return getLocationPath().size();
	}

	/**
	 * Adds a path segment to the Location-Path options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param segment the path segment to add
	 * @return this OptionSet
	 */
	public OptionSet addLocationPath(String segment) {
		if (segment == null)
			throw new IllegalArgumentException("Location-Path option must not be null");
		if (segment.getBytes(CoAP.UTF8_CHARSET).length > 255)
			throw new IllegalArgumentException("Location-Path option must be smaller or euqal to 255 bytes (UTF-8 encoded): " + segment);
		getLocationPath().add(segment);
		return this;
	}

	/**
	 * Removes all Location-Path options.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet clearLocationPath() {
		getLocationPath().clear();
		return this;
	}

	/**
	 * Sets the complete relative Location-Path.
	 * Returns the current OptionSet object for a fluent API.
	 * @param path the Location-Path to set
	 * @return this OptionSet
	 */
	public OptionSet setLocationPath(String path) {
		final String slash = "/";
		
		// remove leading slash
		if (path.startsWith(slash)) {
			path = path.substring(slash.length());
		}
		
		clearLocationPath();
		
		for (String segment : path.split(slash)) {
			// empty path segments are allowed (e.g., /test vs /test/)
			addLocationPath(segment);
		}
		return this;
	}

	/**
	 * Returns the list of Uri-Path segment strings.
	 * The OptionSet uses lazy initialization for this list.
	 * @return the list of Uri-Path segments
	 */
	public List<String> getUriPath() {
		synchronized (this) {
			if (uri_path_list == null)
				uri_path_list = new LinkedList<String>();
		}
		return uri_path_list;
	}

	/**
	 * Returns the Uri-Path options as relative URI string.
	 * To ease splitting, it omits the leading slash.
	 * @return the Uri-Path as string
	 */
	public String getUriPathString() {
		StringBuilder buffer = new StringBuilder();
		for (String element:getUriPath())
			buffer.append(element).append("/");
		if (buffer.length()==0) return "";
		else return buffer.substring(0, buffer.length()-1);
	}
	
	/**
	 * Returns the number of Uri-Path options (i.e., path segments).
	 * @return the count
	 */
	public int getURIPathCount() {
		return getUriPath().size();
	}
	
	/**
	 * Sets the complete relative Uri-Path.
	 * Returns the current OptionSet object for a fluent API.
	 * @param path the Uri-Path to set
	 * @return this OptionSet
	 */
	public OptionSet setUriPath(String path) {
		final String slash = "/";
		
		// remove leading slash
		if (path.startsWith(slash)) {
			path = path.substring(slash.length());
		}
		
		clearUriPath();
		
		for (String segment : path.split(slash)) {
			// empty path segments are allowed (e.g., /test vs /test/)
			addUriPath(segment);
		}
		return this;
	}

	/**
	 * Adds a path segment to the Uri-Path options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param segment the path segment to add
	 * @return this OptionSet
	 */
	public OptionSet addUriPath(String segment) {
		if (segment == null)
			throw new IllegalArgumentException("URI path option must not be null");
		if (segment.getBytes(CoAP.UTF8_CHARSET).length > 255)
			throw new IllegalArgumentException("Uri-Path option must be smaller or euqal to 255 bytes (UTF-8 encoded): " + segment);
		getUriPath().add(segment);
		return this;
	}

	/**
	 * Removes all Uri-Path options.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet clearUriPath() {
		getUriPath().clear();
		return this;
	}

	/**
	 * Returns the Content-Format Identifier of the Content-Format option (see
	 * <a href="http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA Registry</a>).
	 * @return the ID as int or -1 if undefined
	 */
	public int getContentFormat() {
		return hasContentFormat() ? content_format : MediaTypeRegistry.UNDEFINED;
	}

	/**
	 * Checks if the Content-Format option is present.
	 * @return true if present
	 */
	public boolean hasContentFormat() {
		return content_format != null;
	}

	/**
	 * Compares the Content-Format option value to a given format.
	 * Can be used by a server to check the Content-Format of a request body
	 * or by a client to check the Content-Format of a response body.
	 * @param format the Content-Format ID to compare with
	 * @return true if equal
	 * @see MediaTypeRegistry
	 */
	public boolean isContentFormat(int format) {
		return content_format != null && content_format == format;
	}

	/**
	 * Sets the Content-Format ID of the Content-Format option (see
	 * <a href="http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA Registry</a>).
	 * Returns the current OptionSet object for a fluent API.
	 * @param format the Content-Format ID
	 * @return this OptionSet
	 * @see MediaTypeRegistry
	 */
	public OptionSet setContentFormat(int format) {
		if (format > MediaTypeRegistry.UNDEFINED) content_format = format;
		else content_format = null;
		return this;
	}

	/**
	 * Removes the Content-Format option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeContentFormat() {
		content_format = null;
		return this;
	}
	
	/**
	 * Returns the value of the Max-Age option in seconds.
	 * @return the Max-Age in seconds
	 */
	public Long getMaxAge() {
		Long m = max_age;
		return m != null ? m : OptionNumberRegistry.Defaults.MAX_AGE;
	}
	
	/**
	 * Checks if the Max-Age option is present.
	 * If it is not present, the default value of 60 seconds applies.
	 * @return true if present
	 */
	public boolean hasMaxAge() {
		return max_age != null;
	}
	
	/**
	 * Sets the Max-Age option.
	 * Returns the current OptionSet object for a fluent API.
	 * @param age the Max-Age value in seconds
	 * @return this OptionSet
	 */
	public OptionSet setMaxAge(long age) {
		if (age < 0 || ((1L<<32)-1) < age)
			throw new IllegalArgumentException("Max-Age option must be between 0 and "+((1L<<32)-1)+" (4 bytes) inclusive");
		max_age = age;
		return this;
	}
	
	/**
	 * Removes the Max-Age option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this Optionset
	 */
	public OptionSet removeMaxAge() {
		max_age = null;
		return this;
	}

	/**
	 * Returns the list of Uri-Query arguments.
	 * The OptionSet uses lazy initialization for this list.
	 * @return the list of query arguments
	 */
	public List<String> getUriQuery() {
		synchronized (this) {
			if (uri_query_list == null)
				uri_query_list = new LinkedList<String>();
		}
		return uri_query_list;
	}

	/**
	 * Returns the number of Uri-Query options (i.e., arguments).
	 * @return the count
	 */
	public int getURIQueryCount() {
		return getUriQuery().size();
	}

	/**
	 * Returns the Uri-Query options as &amp;-separated query string.
	 * @return the Uri-Query as string
	 */
	public String getUriQueryString() {
		StringBuilder builder = new StringBuilder();
		for (String query:getUriQuery())
			builder.append(query).append("&");
		if (builder.length() > 0)
			builder.delete(builder.length() - 1, builder.length());
		return builder.toString();
	}
	
	/**
	 * Sets the complete Uri-Query through a &amp;-separated list of arguments.
	 * Returns the current OptionSet object for a fluent API.
	 * 
	 * @param query the Query string
	 * @return this Optionset
	 */
	public OptionSet setUriQuery(String query) {
		while (query.startsWith("?")) query = query.substring(1);
		
		clearUriQuery();
		
		for (String segment : query.split("&")) {
			if (!segment.isEmpty()) {
				addUriQuery(segment);
			}
		}
		return this;
	}

	/**
	 * Adds an argument to the Uri-Query options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param argument the argument to add
	 * @return this OptionSet
	 */
	public OptionSet addUriQuery(String argument) {
		if (argument == null)
			throw new NullPointerException("Uri-Query option must not be null");
		if (argument.getBytes(CoAP.UTF8_CHARSET).length > 255)
			throw new IllegalArgumentException("Uri-Query option must be smaller or euqal to 255 bytes (UTF-8 encoded): " + argument);
		getUriQuery().add(argument);
		return this;
	}
	
	/**
	 * Removes a specific argument from the Uri-Query options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param argument the argument to remove
	 * @return this OptionSet
	 */
	public OptionSet removeUriQuery(String argument) {
		getUriQuery().remove(argument);
		return this;
	}
	
	/**
	 * Removes all Uri-Query options.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet clearUriQuery() {
		getUriQuery().clear();
		return this;
	}
	
	/**
	 * Returns the Content-Format Identifier of the Accept option (see
	 * <a href="http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA Registry</a>).
	 * @return the ID as int or -1 if undefined
	 */
	public int getAccept() {
		return hasAccept() ? accept : MediaTypeRegistry.UNDEFINED;
	}

	/**
	 * Checks if the Accept option is present.
	 * @return true if present
	 */
	public boolean hasAccept() {
		return accept != null;
	}

	/**
	 * Compares the Accept option value to a given format.
	 * @param format the Content-Format ID to compare with
	 * @return true if equal
	 */
	public boolean isAccept(int format) {
		return accept != null && accept == format;
	}

	/**
	 * Sets the Content-Format ID of the Accept option (see
	 * <a href="http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA Registry</a>).
	 * Returns the current OptionSet object for a fluent API.
	 * @param format the Content-Format ID
	 * @return this OptionSet
	 * @see MediaTypeRegistry
	 */
	public OptionSet setAccept(int format) {
		if (format < 0 || format > ((1<<16)-1))
			throw new IllegalArgumentException("Accept option must be between 0 and "+((1<<16)-1)+" (2 bytes) inclusive");
		accept = format;
		return this;
	}

	/**
	 * Removes the Accept option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeAccept() {
		accept = null;
		return this;
	}

	/**
	 * Returns the list of Location-Query arguments.
	 * The OptionSet uses lazy initialization for this list.
	 * @return the list of query arguments
	 */
	public List<String> getLocationQuery() {
		synchronized (this) {
			if (location_query_list == null)
				location_query_list = new LinkedList<String>();
		}
		return location_query_list;
	}

	/**
	 * Returns the number of Location-Query options (i.e., arguments).
	 * @return the count
	 */
	public int getLocationQueryCount() {
		return getLocationQuery().size();
	}

	/**
	 * Returns the Location-Query options as &amp;-separated list string.
	 * @return the Location-Query as string
	 */
	public String getLocationQueryString() {
		StringBuilder builder = new StringBuilder();
		for (String query:getLocationQuery())
			builder.append(query).append("&");
		if (builder.length() > 0)
			builder.delete(builder.length() - 1, builder.length());
		return builder.toString();
	}

	/**
	 * Sets the complete Location-Query through a &amp;-separated list of arguments.
	 * Returns the current OptionSet object for a fluent API.
	 * @param query the Location-Query string
	 * @return this Optionset
	 */
	public OptionSet setLocationQuery(String query) {
		while (query.startsWith("?")) query = query.substring(1);
		
		clearLocationQuery();
		
		for (String segment : query.split("&")) {
			if (!segment.isEmpty()) {
				addLocationQuery(segment);
			}
		}
		return this;
	}

	/**
	 * Adds an argument to the Location-Query options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param argument the argument to add
	 * @return this OptionSet
	 */
	public OptionSet addLocationQuery(String argument) {
		if (argument == null)
			throw new NullPointerException("Location-Query option must not be null");
		if (argument.getBytes(CoAP.UTF8_CHARSET).length > 255)
			throw new IllegalArgumentException("Location-Query option must be smaller or euqal to 255 bytes (UTF-8 encoded): " + argument);
		getLocationQuery().add(argument);
		return this;
	}
	
	/**
	 * Removes a specific argument from the Location-Query options.
	 * Returns the current OptionSet object for a fluent API.
	 * @param argument the argument to remove
	 * @return this OptionSet
	 */
	public OptionSet removeLocationQuery(String argument) {
		getLocationQuery().remove(argument);
		return this;
	}
	
	/**
	 * Removes all Location-Query options.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet clearLocationQuery() {
		getLocationQuery().clear();
		return this;
	}

	/**
	 * Returns the string value of the Proxy-Uri option.
	 * @return the Proxy-Uri or null if the option is not present
	 */
	public String getProxyUri() {
		return proxy_uri;
	}

	/**
	 * Checks if the Proxy-Uri option is present.
	 * @return true if present
	 */
	public boolean hasProxyUri() {
		return proxy_uri != null;
	}

	/**
	 * Sets the Proxy-Uri option.
	 * Returns the current OptionSet object for a fluent API.
	 * @param uri the Proxy-Uri value to set.
	 * @return this OptionSet
	 */
	public OptionSet setProxyUri(String uri) {
		if (uri == null)
			throw new NullPointerException("Proxy-Uri option must not be null");
		if (uri.getBytes(CoAP.UTF8_CHARSET).length < 1 || 1034 < uri.getBytes(CoAP.UTF8_CHARSET).length)
			throw new IllegalArgumentException("Proxy-Uri option must be between 1 and 1034 bytes inclusive (UTF-8 encoded): " + uri);
		proxy_uri = uri;
		return this;
	}

	/**
	 * Removes the Proxy-Uri option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeProxyUri() {
		proxy_uri = null;
		return this;
	}

	/**
	 * Returns the string value of the Proxy-Scheme option.
	 * @return the Proxy-Scheme or null if the option is not present
	 */
	public String getProxyScheme() {
		return proxy_scheme;
	}

	/**
	 * Checks if the Proxy-Scheme option is present.
	 * @return true if present
	 */
	public boolean hasProxyScheme() {
		return proxy_scheme != null;
	}

	/**
	 * Sets the Proxy-Scheme option.
	 * Returns the current OptionSet object for a fluent API.
	 * @param scheme the Proxy-Scheme value to set.
	 * @return this OptionSet
	 */
	public OptionSet setProxyScheme(String scheme) {
		if (scheme == null)
			throw new NullPointerException("Proxy-Scheme option must not be null");
		if (scheme.getBytes(CoAP.UTF8_CHARSET).length < 1 || 255 < scheme.getBytes(CoAP.UTF8_CHARSET).length)
			throw new IllegalArgumentException("Proxy-Scheme option must be between 1 and 255 bytes inclusive (UTF-8 encoded): " + scheme);
		proxy_scheme = scheme;
		return this;
	}

	/**
	 * Removes the Proxy-Scheme option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeProxyScheme() {
		proxy_scheme = null;
		return this;
	}

	/**
	 * Returns the Block1 option as encoded object.
	 * @return the BlockOption
	 */
	public BlockOption getBlock1() {
		return block1;
	}

	/**
	 * Checks if the Block1 option is present.
	 * @return true if present
	 */
	public boolean hasBlock1() {
		return block1 != null;
	}

	/**
	 * Sets the Block1 option based on its components.
	 * Returns the current OptionSet object for a fluent API.
	 * @param szx the block size
	 * @param m the more flag
	 * @param num the block number
	 * @return this OptionSet
	 */
	public OptionSet setBlock1(int szx, boolean m, int num) {
		this.block1 = new BlockOption(szx, m, num);
		return this;
	}

	/**
	 * Sets the Block1 option based on its encoded blob.
	 * Returns the current OptionSet object for a fluent API.
	 * @param value the encoded value
	 * @return this OptionSet
	 */
	public OptionSet setBlock1(byte[] value) {
		this.block1 = new BlockOption(value);
		return this;
	}

	/**
	 * Sets the Block1 option based on a BlockOption object.
	 * Returns the current OptionSet object for a fluent API.
	 * @param block the block object
	 * @return this OptionSet
	 */
	public OptionSet setBlock1(BlockOption block) {
		this.block1 = block;
		return this;
	}

	/**
	 * Removes the Block1 option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeBlock1() {
		this.block1 = null;
		return this;
	}

	/**
	 * Returns the Block2 option as encoded object.
	 * @return the BlockOption
	 */
	public BlockOption getBlock2() {
		return block2;
	}

	/**
	 * Checks if the Block2 option is present.
	 * @return true if present
	 */
	public boolean hasBlock2() {
		return block2 != null;
	}

	/**
	 * Sets the Block2 option based on its components.
	 * Returns the current OptionSet object for a fluent API.
	 * @param szx the block size
	 * @param m the more flag
	 * @param num the block number
	 * @return this OptionSet
	 */
	public OptionSet setBlock2(int szx, boolean m, int num) {
		this.block2 = new BlockOption(szx, m, num);
		return this;
	}

	/**
	 * Sets the Block1 option based on its encoded blob.
	 * Returns the current OptionSet object for a fluent API.
	 * 
	 * @param value the encoded value
	 * @return this OptionSet
	 */
	public OptionSet setBlock2(byte[] value) {
		this.block2 = new BlockOption(value);
		return this;
	}

	/**
	 * Sets the Block1 option based on a BlockOption object.
	 * Returns the current OptionSet object for a fluent API.
	 * @param block the block object
	 * @return this OptionSet
	 */
	public OptionSet setBlock2(BlockOption block) {
		this.block2 = block;
		return this;
	}

	/**
	 * Removes the Block2 option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeBlock2() {
		this.block2 = null;
		return this;
	}

	/**
	 * Returns the uint value of the Size1 option.
	 * @return the Size1 value or null if the option is not present
	 */
	public Integer getSize1() {
		return size1;
	}

	/**
	 * Checks if the Size1 option is present.
	 * @return true if present
	 */
	public boolean hasSize1() {
		return size1 != null;
	}

	/**
	 * Sets the Size1 option value.
	 * Returns the current OptionSet object for a fluent API.
	 * @param size the size of the request body
	 * @return this OptionSet
	 */
	public OptionSet setSize1(int size) {
		this.size1 = size;
		return this;
	}

	/**
	 * Removes the Size1 option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeSize1() {
		this.size1 = null;
		return this;
	}

	/**
	 * Returns the uint value of the Size2 option.
	 * @return the Size2 value or null if the option is not present
	 */
	public Integer getSize2() {
		return size2;
	}

	/**
	 * Checks if the Size2 option is present.
	 * @return true if present
	 */
	public boolean hasSize2() {
		return size2 != null;
	}

	/**
	 * Sets the Size2 option value.
	 * Returns the current OptionSet object for a fluent API.
	 * @param size the size of the response body
	 * @return this OptionSet
	 */
	public OptionSet setSize2(int size) {
		this.size2 = size;
		return this;
	}

	/**
	 * Removes the Size2 option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeSize2() {
		this.size2 = null;
		return this;
	}

	/**
	 * Returns the uint value of the Observe option.
	 * @return the Observe value or null if the option is not present
	 */
	public Integer getObserve() {
		return observe;
	}

	/**
	 * Checks if the Observe option is present.
	 * @return true if present
	 */
	public boolean hasObserve() {
		return observe != null;
	}

	/**
	 * Sets the Observe option value.
	 * Returns the current OptionSet object for a fluent API.
	 * 
	 * @param seqnum the sequence number
	 * @return this OptionSet
	 * @throws IllegalArgumentException if the given number is &lt; 0 or &gt; 2^24 - 1
	 */
	public OptionSet setObserve(final int seqnum) {

		if (!isValidObserveOption(seqnum)) {
			throw new IllegalArgumentException("Observe option must be between 0 and " + MAX_OBSERVE_NO + " (3 bytes) inclusive");
		} else {
			this.observe = seqnum;
			return this;
		}
	}

	/**
	 * Removes the Observe option.
	 * Returns the current OptionSet object for a fluent API.
	 * @return this OptionSet
	 */
	public OptionSet removeObserve() {
		observe = null;
		return this;
	}

	/**
	 * Checks if a given number is a valid value for the <em>Observe</em> option.
	 * 
	 * @param value The value to check.
	 * @return {@code true} if the value is &gt; 0 and &lt; 2^24 - 1.
	 */
	public static boolean isValidObserveOption(final int value) {
		return value >= 0 && value <= MAX_OBSERVE_NO;
	}

	/**
	 * Checks if an arbitrary option is present.
	 * @param number the option number
	 * @return true if present
	 */
	public boolean hasOption(int number) {
		return Collections.binarySearch(asSortedList(), new Option(number)) >= 0;
	}

	private List<Option> getOthersInternal() {
		synchronized (this) {
			if (others == null)
				others = new LinkedList<Option>();
		}
		return others;
	}

	/**
	 * Returns list of other options.
	 * 
	 * The list is unmodifiable and not sorted.
	 * 
	 * @return list of other options.
	 */
	public List<Option> getOthers() {
		List<Option> others = this.others;
		if (others == null) {
			return Collections.emptyList();
		} else {
			return Collections.unmodifiableList(others);
		}
	}

	/**
	 * Returns all options in a list sorted according to their option number.
	 * The list cannot be use to modify the OptionSet of the message, since it is a copy.
	 * @return the sorted list (a copy)
	 */
	public List<Option> asSortedList() {
		ArrayList<Option> options = new ArrayList<Option>();
		
		if (if_match_list != null) for (byte[] value:if_match_list)
			options.add(new Option(OptionNumberRegistry.IF_MATCH, value));
		if (hasUriHost())
			options.add(new Option(OptionNumberRegistry.URI_HOST, getUriHost()));
		if (etag_list != null) for (byte[] value:etag_list)
			options.add(new Option(OptionNumberRegistry.ETAG, value));
		if (hasIfNoneMatch())
			options.add(new Option(OptionNumberRegistry.IF_NONE_MATCH));
		if (hasUriPort())
			options.add(new Option(OptionNumberRegistry.URI_PORT, getUriPort()));
		if (location_path_list != null) for (String str:location_path_list)
			options.add(new Option(OptionNumberRegistry.LOCATION_PATH, str));
		if (uri_path_list != null) for (String str:uri_path_list)
			options.add(new Option(OptionNumberRegistry.URI_PATH, str));
		if (hasContentFormat())
			options.add(new Option(OptionNumberRegistry.CONTENT_FORMAT, getContentFormat()));
		if (hasMaxAge())
			options.add(new Option(OptionNumberRegistry.MAX_AGE, getMaxAge()));
		if (uri_query_list != null) for (String str:uri_query_list)
			options.add(new Option(OptionNumberRegistry.URI_QUERY, str));
		if (hasAccept())
			options.add(new Option(OptionNumberRegistry.ACCEPT, getAccept()));
		if (location_query_list != null) for (String str:location_query_list)
			options.add(new Option(OptionNumberRegistry.LOCATION_QUERY, str));
		if (hasProxyUri())
			options.add(new Option(OptionNumberRegistry.PROXY_URI, getProxyUri()));
		if (hasProxyScheme())
			options.add(new Option(OptionNumberRegistry.PROXY_SCHEME, getProxyScheme()));
		
		if (hasObserve())
			options.add(new Option(OptionNumberRegistry.OBSERVE, getObserve()));
		
		if (hasBlock1())
			options.add(new Option(OptionNumberRegistry.BLOCK1, getBlock1().getValue()));
		if (hasBlock2())
			options.add(new Option(OptionNumberRegistry.BLOCK2, getBlock2().getValue()));
		if (hasSize1())
			options.add(new Option(OptionNumberRegistry.SIZE1, getSize1()));
		if (hasSize2())
			options.add(new Option(OptionNumberRegistry.SIZE2, getSize2()));
		
		if (others != null)
			options.addAll(others);
		
		Collections.sort(options);
		return options;
	}

	/**
	 * Allows adding arbitrary options. Known options are checked if they are repeatable.
	 * @param option the Option object to add
	 * @return this OptionSet
	 */
	public OptionSet addOption(Option option) {
		switch (option.getNumber()) {
			case OptionNumberRegistry.IF_MATCH:       addIfMatch(option.getValue()); break;
			case OptionNumberRegistry.URI_HOST:       setUriHost(option.getStringValue()); break;
			case OptionNumberRegistry.ETAG:           addETag(option.getValue()); break;
			case OptionNumberRegistry.IF_NONE_MATCH:  setIfNoneMatch(true); break;
			case OptionNumberRegistry.URI_PORT:       setUriPort(option.getIntegerValue()); break;
			case OptionNumberRegistry.LOCATION_PATH:  addLocationPath(option.getStringValue()); break;
			case OptionNumberRegistry.URI_PATH:       addUriPath(option.getStringValue()); break;
			case OptionNumberRegistry.CONTENT_FORMAT: setContentFormat(option.getIntegerValue()); break;
			case OptionNumberRegistry.MAX_AGE:        setMaxAge(option.getLongValue()); break;
			case OptionNumberRegistry.URI_QUERY:      addUriQuery(option.getStringValue()); break;
			case OptionNumberRegistry.ACCEPT:         setAccept(option.getIntegerValue()); break;
			case OptionNumberRegistry.LOCATION_QUERY: addLocationQuery(option.getStringValue()); break;
			case OptionNumberRegistry.PROXY_URI:      setProxyUri(option.getStringValue()); break;
			case OptionNumberRegistry.PROXY_SCHEME:   setProxyScheme(option.getStringValue()); break;
			case OptionNumberRegistry.BLOCK1:         setBlock1(option.getValue()); break;
			case OptionNumberRegistry.BLOCK2:         setBlock2(option.getValue()); break;
			case OptionNumberRegistry.SIZE1:          setSize1(option.getIntegerValue()); break;
			case OptionNumberRegistry.SIZE2:          setSize2(option.getIntegerValue()); break;
			case OptionNumberRegistry.OBSERVE:        setObserve(option.getIntegerValue()); break;
			default: getOthersInternal().add(option);
		}
		return this;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		StringBuilder sbv = new StringBuilder();
		int oldNr = -1;
		boolean list = false;

		sb.append('{');
		
		for (Option opt : asSortedList()) {
			if (opt.getNumber()!=oldNr) {
				if (oldNr!=-1) {
					if (list) sbv.append(']');
					sb.append(sbv.toString());
					sbv = new StringBuilder();
					sb.append(", ");
				} else {
				}
				list = false;
				
				sb.append('"');
				sb.append(OptionNumberRegistry.toString(opt.getNumber()));
				sb.append('"');
				sb.append(':');
			} else {
				if (!list) sbv.insert(0, '[');
				list = true;
				sbv.append(",");
			}
			sbv.append(opt.toValueString());
			
			oldNr = opt.getNumber();
		}
		if (list) sbv.append(']');
		sb.append(sbv.toString());
		sb.append('}');
		
		return sb.toString();
	}
}
