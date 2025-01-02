/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - make getOthers() public.
 *                                                    issue #286
 *    Achim Kraus (Bosch Software Innovations GmbH) - Include size1 and size2
 *                                                    in clone and clear
 *                                                    issue #815
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.core.coap.option.BlockOption;
import org.eclipse.californium.core.coap.option.EmptyOption;
import org.eclipse.californium.core.coap.option.IntegerOption;
import org.eclipse.californium.core.coap.option.NoResponseOption;
import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.OptionNumber;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.option.StringOption;

/**
 * {@code OptionSet} is a collection of all options of a request or a response.
 * {@code OptionSet} provides methods to add, remove and modify all options
 * defined in the CoAP, blockwise CoAP, observing CoAP and supports arbitrary
 * defined options.
 * <p>
 * Native format of a {@code CoAP} options include its number and value. More
 * detailed format documentation of number and value format, see {@link Option}.
 * <p>
 * <b>NOTE:</b> {@code CoAP} defines {@code If-None-Match} option as empty, thus
 * using {@link Option} to inspect its {@code value} is meaningless. Either use
 * {@link Option} to check if this particular option exists or use method
 * {@link #hasIfNoneMatch()} in this class. Other option relationships between
 * {@code OptionSet} and {@link Option} may have little differences like
 * {@code Content-Format} and {@code Accept} whose methods
 * {@link #getContentFormat()} and {@link #getAccept()} will return
 * {@link MediaTypeRegistry#UNDEFINED} if option is not present. This generally
 * means that user may want to check if option actually exists before naively
 * trying to use these values.
 * <p>
 * This class is not thread-safe.
 * 
 * @see Option
 */
public final class OptionSet {

	/*
	 * Options defined by the CoAP protocol
	 */
	private List<OpaqueOption> if_match_list;
	private StringOption uri_host;
	private List<OpaqueOption> etag_list;
	private EmptyOption if_none_match;
	private IntegerOption uri_port; // null if no port is explicitly defined
	private List<StringOption> location_path_list;
	private List<StringOption> uri_path_list;
	private IntegerOption content_format;
	private IntegerOption max_age; // (0-4 bytes)
	private List<StringOption> uri_query_list;
	private UriQueryParameter uri_query_parameter;
	private IntegerOption accept;
	private List<StringOption> location_query_list;
	private StringOption proxy_uri;
	private StringOption proxy_scheme;
	private BlockOption block1;
	private BlockOption block2;
	private IntegerOption size1;
	private IntegerOption size2;
	private IntegerOption observe;
	private OpaqueOption oscore;
	private NoResponseOption no_response;

	// Arbitrary options
	private List<Option> others;

	/**
	 * Creates an empty set of options.
	 * <p>
	 * Once a list is touched and constructed it must never become null again.
	 * Non-lists can be null though.
	 */
	public OptionSet() {
		if_match_list = null; // new LinkedList<byte[]>();
		uri_host = null; // from sender
		etag_list = null; // new LinkedList<byte[]>();
		if_none_match = null;
		uri_port = null; // from sender
		location_path_list = null; // new LinkedList<String>();
		uri_path_list = null; // new LinkedList<String>();
		content_format = null;
		max_age = null;
		uri_query_list = null; // new LinkedList<String>();
		uri_query_parameter = null;
		accept = null;
		location_query_list = null; // new LinkedList<String>();
		proxy_uri = null;
		proxy_scheme = null;
		block1 = null;
		block2 = null;
		size1 = null;
		size2 = null;
		observe = null;
		oscore = null;
		no_response = null;

		others = null; // new LinkedList<>();
	}

	/**
	 * Creates a deep copy of existing options.
	 * 
	 * @param origin the existing options to be copied
	 */
	public OptionSet(OptionSet origin) {
		if (origin == null) {
			throw new NullPointerException("option set must not be null!");
		}
		if_match_list = copyList(origin.if_match_list);
		uri_host = origin.uri_host;
		etag_list = copyList(origin.etag_list);
		if_none_match = origin.if_none_match;
		uri_port = origin.uri_port;
		location_path_list = copyList(origin.location_path_list);
		uri_path_list = copyList(origin.uri_path_list);
		content_format = origin.content_format;
		max_age = origin.max_age;
		uri_query_list = copyList(origin.uri_query_list);
		uri_query_parameter = origin.uri_query_parameter;
		accept = origin.accept;
		location_query_list = copyList(origin.location_query_list);
		proxy_uri = origin.proxy_uri;
		proxy_scheme = origin.proxy_scheme;

		block1 = origin.block1;
		block2 = origin.block2;

		size1 = origin.size1;
		size2 = origin.size2;
		observe = origin.observe;
		oscore = origin.oscore;
		no_response = origin.no_response;
		others = copyList(origin.others);
	}

	/**
	 * Clears all options.
	 */
	public void clear() {
		clear(if_match_list);
		uri_host = null;
		clear(etag_list);
		if_none_match = null;
		uri_port = null;
		clear(location_path_list);
		clear(uri_path_list);
		content_format = null;
		max_age = null;
		clear(uri_query_list);
		uri_query_parameter = null;
		accept = null;
		clear(location_query_list);
		proxy_uri = null;
		proxy_scheme = null;
		block1 = null;
		block2 = null;
		size1 = null;
		size2 = null;
		observe = null;
		oscore = null;
		no_response = null;
		clear(others);
	}

	/**
	 * Counts items in optional list.
	 * 
	 * @param list list of items, or {@code null}.
	 * @return number of items in list, or {@code 0} if list is {@code null}.
	 * @since 4.0
	 */
	private static final int count(List<?> list) {
		return list == null ? 0 : list.size();
	}

	/**
	 * Clears optional list.
	 * 
	 * @param list list of items, or {@code null}.
	 * @since 4.0
	 */
	private static final void clear(List<?> list) {
		if (list != null) {
			list.clear();
		}
	}

	/**
	 * Copies the specified list.
	 * 
	 * @param <T> the generic type
	 * @param list the list, or {@code null}.
	 * @return a copy of the list, or {@code null}, {@code null} is provided.
	 */
	private static final <T> List<T> copyList(List<T> list) {
		if (list == null)
			return null;
		else
			return new ArrayList<T>(list);
	}

	/**
	 * Ensures existing list.
	 * 
	 * @param <T> the generic type
	 * @param list the list. If {@code null}, creates list
	 * @return the list, or the create list
	 * @since 4.0
	 */
	private static final <T> List<T> ensureList(List<T> list) {
		if (list == null) {
			list = new ArrayList<T>(4);
		}
		return list;
	}

	/**
	 * Gets string value from optional string option.
	 * 
	 * @param option the string option, or {@code null}.
	 * @return the string value, or {@code null}, {@code null} is provided.
	 * @since 4.0
	 */
	private static final String getValue(StringOption option) {
		return option == null ? null : option.getStringValue();
	}

	/**
	 * Gets integer value from optional integer option.
	 * 
	 * @param option the integer option, or {@code null}.
	 * @return the integer value, or {@code null}, {@code null} is provided.
	 * @since 4.0
	 */
	private static final Integer getValue(IntegerOption option) {
		return option == null ? null : option.getIntegerValue();
	}

	/**
	 * Add option to ordered list.
	 * <p>
	 * Uses {@link Option#isSingleValue()} to either overwrite an option or
	 * append the option at the end of a section of options with that same
	 * number.
	 * 
	 * @param list the list of options
	 * @param option the option to add
	 * @throws NullPointerException if any argument is {@code null}
	 * @since 4.0
	 */
	private static final void addOrdered(List<Option> list, Option option) {
		if (list == null) {
			throw new NullPointerException("List must not be null!");
		}
		if (option == null) {
			throw new NullPointerException("Option must not be null!");
		}
		int pos = list.size();
		while (pos > 0) {
			--pos;
			int cmp = list.get(pos).compareTo(option);
			if (cmp <= 0) {
				if (cmp == 0 && option.isSingleValue()) {
					list.remove(pos);
				} else {
					++pos;
				}
				break;
			}
		}
		list.add(pos, option);
	}

	/**
	 * Gets index of first occurrence of option.
	 * 
	 * @param list list of options
	 * @param option option number
	 * @return position of first occurrence, or {@code -1}, if not contained.
	 * @since 4.0
	 */
	private static final int indexOfFirst(List<Option> list, OptionNumber option) {
		if (list == null) {
			throw new NullPointerException("List must not be null!");
		}
		if (option == null) {
			throw new NullPointerException("Option must not be null!");
		}
		for (int index = 0; index < list.size(); ++index) {
			int cmp = list.get(index).compareTo(option);
			if (cmp == 0) {
				return index;
			} else if (cmp > 0) {
				break;
			}
		}
		return -1;
	}

	/**
	 * Checks order in list.
	 * 
	 * @param list the list to check the order
	 * @throws IllegalArgumentException if the list is not ordered
	 * @since 4.0
	 */
	private static final void assertOrder(List<Option> list) {
		Option last = null;
		for (Option option : list) {
			if (last != null && last.compareTo(option) > 0) {
				throw new IllegalArgumentException("List not sorted! " + last + " > " + option);
			}
			last = option;
		}
	}

	/////////////////////// Getter and Setter ///////////////////////

	/**
	 * Gets the list of If-Match ETags.
	 * <p>
	 * The OptionSet uses lazy initialization for this list.
	 * 
	 * @return the list of If-Match ETags
	 * @since 4.0 (adapted to List of Options)
	 */
	public List<OpaqueOption> getIfMatch() {
		synchronized (this) {
			if_match_list = ensureList(if_match_list);
		}
		return if_match_list;
	}

	/**
	 * Gets the number of If-Match options.
	 * 
	 * @return the count
	 */
	public int getIfMatchCount() {
		return count(if_match_list);
	}

	/**
	 * Checks if the If-Match options contain the given ETag.
	 * <p>
	 * This method can be used by a server to handle a conditional request. When
	 * called, the method assumes the resource does exist, so that an empty
	 * If-Match option will match. The passed ETag should be the one by the
	 * server denoting the current resource state.
	 * 
	 * @param check the ETag of the current resource state
	 * @return {@code true}, if ETag matches or message contains an empty
	 *         If-Match option
	 */
	public boolean isIfMatch(byte[] check) {
		final List<OpaqueOption> list = if_match_list;
		if (list == null) {
			// if no If-Match option is present, conditional update is allowed
			return true;
		}
		if (isIfMatchAll()) {
			return true;
		}
		return contains(list, check);
	}

	/**
	 * Checks, if empty if_match option is set.
	 * 
	 * @return {@code true} if empty if_match option is set.
	 * @since 4.0
	 */
	public boolean isIfMatchAll() {
		final List<OpaqueOption> list = if_match_list;
		return list != null && list.size() == 1 && list.get(0).getLength() == 0;
	}

	/**
	 * Adds an ETag to the If-Match options.
	 * <p>
	 * A byte array of size 0 adds an empty If-Match option, which checks for
	 * existence of the targeted resource.
	 * 
	 * @param etag the If-Match ETag to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the etag is {@code null}
	 * @throws IllegalArgumentException if the etag has more than 8 bytes.
	 */
	public OptionSet addIfMatch(byte[] etag) {
		if (!isIfMatchAll()) {
			List<OpaqueOption> list = getIfMatch();
			if (!contains(list, etag)) {
				if (etag.length == 0) {
					list.clear();
					list.add(StandardOptionRegistry.IF_MATCH.create(etag));
				} else if (!isIfMatchAll()) {
					list.add(StandardOptionRegistry.IF_MATCH.create(etag.clone()));
				}
			}
		}
		return this;
	}

	/**
	 * Removes a specific ETag from the If-Match options.
	 * 
	 * @param etag the If-Match ETag to remove
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeIfMatch(byte[] etag) {
		remove(if_match_list, etag);
		return this;
	}

	/**
	 * Removes all If-Match options.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet clearIfMatchs() {
		clear(if_match_list);
		return this;
	}

	/**
	 * Gets the string value of the Uri-Host option.
	 * 
	 * @return the Uri-Host, or {@code null}, if the option is not present
	 */
	public String getUriHost() {
		return getValue(uri_host);
	}

	/**
	 * Checks if the Uri-Host option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasUriHost() {
		return uri_host != null;
	}

	/**
	 * Sets the Uri-Host option.
	 * 
	 * @param host the Uri-Host value to set.
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the host is {@code null}
	 * @throws IllegalArgumentException if the host has less than 1 or more than
	 *             255 bytes.
	 */
	public OptionSet setUriHost(String host) {
		StringOption option = StandardOptionRegistry.URI_HOST.create(host);
		this.uri_host = option;
		return this;
	}

	/**
	 * Removes the Uri-Host option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeUriHost() {
		this.uri_host = null;
		return this;
	}

	/**
	 * Gets the list of ETags.
	 * <p>
	 * In a response, there MUST only be one ETag that defines the payload or
	 * the resource given through the Location-* options. In a request, there
	 * can be multiple ETags for validation. The OptionSet uses lazy
	 * initialization for this list.
	 * 
	 * @return the list of ETags
	 * @since 4.0 (adapted to List of Options)
	 */
	public List<OpaqueOption> getETags() {
		synchronized (this) {
			etag_list = ensureList(etag_list);
		}
		return etag_list;
	}

	/**
	 * Gets the number of ETag options.
	 * 
	 * @return the count
	 */
	public int getETagCount() {
		return count(etag_list);
	}

	/**
	 * Checks if the ETag options contain the passed ETag.
	 * <p>
	 * This can be used by a server to respond to a validation request. The
	 * passed ETag should be the one by the server denoting the current resource
	 * state.
	 * 
	 * @param check the ETag of the current resource state
	 * @return {@code true}, if ETag is included
	 */
	public boolean containsETag(byte[] check) {
		return contains(etag_list, check);
	}

	/**
	 * Adds an ETag to the ETag options.
	 * 
	 * @param etag the ETag to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the etag is {@code null}
	 * @throws IllegalArgumentException if the etag has less than 1 or more than
	 *             8 bytes.
	 */
	public OptionSet addETag(byte[] etag) {
		if (!containsETag(etag)) {
			OpaqueOption option = StandardOptionRegistry.ETAG.create(etag.clone());
			getETags().add(option);
		}
		return this;
	}

	/**
	 * Removes a specific ETag from the ETag options.
	 * 
	 * @param etag the ETag to remove
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the etag is {@code null}
	 * @throws IllegalArgumentException if the etag has less than 1 or more than
	 *             8 bytes.
	 */
	public OptionSet removeETag(byte[] etag) {
		remove(etag_list, etag);
		return this;
	}

	/**
	 * Removes all ETag options.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet clearETags() {
		clear(etag_list);
		return this;
	}

	/**
	 * Gets response etag value.
	 * 
	 * @return etag value, or {@code null}, if not available
	 * @throws IllegalStateException if more than one etag is contained.
	 * @since 4.0
	 */
	public byte[] getResponseEtag() {
		final List<OpaqueOption> list = etag_list;
		if (list != null) {
			int size = list.size();
			if (size == 1) {
				return list.get(0).getValue();
			} else if (size > 1) {
				throw new IllegalStateException(size + " etags, only 1 etag supported in responses!");
			}
		}
		return null;
	}

	/**
	 * Checks if the If-None-Match option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasIfNoneMatch() {
		return if_none_match != null;
	}

	/**
	 * Sets or unsets the If-None-Match option.
	 * 
	 * @param present the presence of the option
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet setIfNoneMatch(boolean present) {
		if_none_match = present ? StandardOptionRegistry.IF_NONE_MATCH.create() : null;
		return this;
	}

	/**
	 * Gets the uint value of the Uri-Port option.
	 * 
	 * @return the Uri-Port value or null if the option is not present
	 */
	public Integer getUriPort() {
		return getValue(uri_port);
	}

	/**
	 * Checks if the Uri-Port option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasUriPort() {
		return uri_port != null;
	}

	/**
	 * Sets the Uri-Port option.
	 * 
	 * @param port the Uri-Port value to set.
	 * @return this OptionSet for a fluent API.
	 * @throws IllegalArgumentException if port is not in valid range
	 */
	public OptionSet setUriPort(int port) {
		uri_port = StandardOptionRegistry.URI_PORT.create(port);
		return this;
	}

	/**
	 * Removes the Uri-Port option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeUriPort() {
		uri_port = null;
		return this;
	}

	/**
	 * Gets the list of Location-Path segment strings.
	 * <p>
	 * The OptionSet uses lazy initialization for this list.
	 * 
	 * @return the list of Location-Path segments
	 * @since 4.0 (adapted to List of Options)
	 */
	public List<StringOption> getLocationPath() {
		synchronized (this) {
			location_path_list = ensureList(location_path_list);
		}
		return location_path_list;
	}

	/**
	 * Gets the Location-Path and Location-Query options as relative URI string.
	 * 
	 * @return the Location-* as string
	 */
	public String getLocationString() {
		StringBuilder builder = new StringBuilder();
		builder.append('/');
		appendMultiOption(builder, getLocationPath(), '/');
		if (getLocationQueryCount() > 0) {
			builder.append('?');
			appendMultiOption(builder, getLocationQuery(), '&');
		}
		return builder.toString();
	}

	/**
	 * Gets the Location-Path options as relative URI string.
	 * <p>
	 * To ease splitting, it omits the leading slash.
	 * 
	 * @return the Location-Path as string
	 */
	public String getLocationPathString() {
		return getMultiOptionString(getLocationPath(), '/');
	}

	/**
	 * Gets the number of Location-Path options (i.e., path segments).
	 * 
	 * @return the count
	 */
	public int getLocationPathCount() {
		return count(location_path_list);
	}

	/**
	 * Adds a path segment to the Location-Path options.
	 * 
	 * @param segment the path segment to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the segment is {@code null}
	 * @throws IllegalArgumentException if the segment has more than 255 bytes.
	 */
	public OptionSet addLocationPath(String segment) {
		getLocationPath().add(StandardOptionRegistry.LOCATION_PATH.create(segment));
		return this;
	}

	/**
	 * Removes all Location-Path options.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet clearLocationPath() {
		clear(location_path_list);
		return this;
	}

	/**
	 * Sets the complete relative Location-Path.
	 * 
	 * @param path the Location-Path to set
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the path is {@code null}
	 * @throws IllegalArgumentException if one of the path's segments has more
	 *             than 255 bytes.
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
	 * Gets the URI-Path and URI-Query options as relative URI string.
	 * 
	 * @return the URI-* as string
	 */
	public String getUriString() {
		StringBuilder builder = new StringBuilder();
		builder.append('/');
		appendMultiOption(builder, getUriPath(), '/');
		if (getURIQueryCount() > 0) {
			builder.append('?');
			appendMultiOption(builder, getUriQuery(), '&');
		}
		return builder.toString();
	}

	/**
	 * Gets the list of Uri-Path segment strings.
	 * <p>
	 * The OptionSet uses lazy initialization for this list.
	 * 
	 * @return the list of Uri-Path segments
	 * @since 4.0 (adapted to List of Options)
	 */
	public List<StringOption> getUriPath() {
		synchronized (this) {
			uri_path_list = ensureList(uri_path_list);
		}
		return uri_path_list;
	}

	/**
	 * Gets the Uri-Path options as relative URI string.
	 * <p>
	 * To ease splitting, it omits the leading slash.
	 * 
	 * @return the Uri-Path as string
	 */
	public String getUriPathString() {
		return getMultiOptionString(getUriPath(), '/');
	}

	/**
	 * Returns the number of Uri-Path options (i.e., path segments).
	 * 
	 * @return the count
	 */
	public int getURIPathCount() {
		return count(uri_path_list);
	}

	/**
	 * Sets the complete relative Uri-Path.
	 * 
	 * @param path the Uri-Path to set
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the path is {@code null}
	 * @throws IllegalArgumentException if one of the path's segments has more
	 *             than 255 bytes.
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
	 * 
	 * @param segment the path segment to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the segment is {@code null}
	 * @throws IllegalArgumentException if the segment has more than 255 bytes.
	 */
	public OptionSet addUriPath(String segment) {
		getUriPath().add(StandardOptionRegistry.URI_PATH.create(segment));
		return this;
	}

	/**
	 * Removes all Uri-Path options.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet clearUriPath() {
		clear(uri_path_list);
		return this;
	}

	/**
	 * Gets the Content-Format Identifier of the Content-Format option (see
	 * <a href=
	 * "http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA
	 * Registry</a>).
	 * 
	 * @return the ID as int, or, {@code -1}, if undefined
	 */
	public int getContentFormat() {
		final IntegerOption option = content_format;
		return option == null ? MediaTypeRegistry.UNDEFINED : option.getIntegerValue();
	}

	/**
	 * Checks if the Content-Format option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasContentFormat() {
		return content_format != null;
	}

	/**
	 * Compares the Content-Format option value to a given format.
	 * <p>
	 * Can be used by a server to check the Content-Format of a request body or
	 * by a client to check the Content-Format of a response body.
	 * 
	 * @param format the Content-Format ID to compare with
	 * @return {@code true}, if equal
	 * @see MediaTypeRegistry
	 */
	public boolean isContentFormat(int format) {
		final IntegerOption option = content_format;
		return option != null && option.getIntegerValue() == format;
	}

	/**
	 * Sets the Content-Format ID of the Content-Format option (see <a href=
	 * "http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA
	 * Registry</a>).
	 * 
	 * @param format the Content-Format ID. Use value
	 *            {@link MediaTypeRegistry#UNDEFINED} to
	 *            {@link #removeContentFormat()}.
	 * @return this OptionSet for a fluent API.
	 * @throws IllegalArgumentException if value is out of range {@code 0} to
	 *             {@link MediaTypeRegistry#MAX_TYPE} and not
	 *             {@link MediaTypeRegistry#UNDEFINED} (since 3.0).
	 * @see MediaTypeRegistry
	 */
	public OptionSet setContentFormat(int format) {
		if (MediaTypeRegistry.UNDEFINED == format) {
			content_format = null;
		} else {
			content_format = StandardOptionRegistry.CONTENT_FORMAT.create(format);
		}
		return this;
	}

	/**
	 * Removes the Content-Format option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeContentFormat() {
		content_format = null;
		return this;
	}

	/**
	 * Gets the value of the Max-Age option in seconds.
	 * 
	 * @return the Max-Age in seconds
	 */
	public Long getMaxAge() {
		IntegerOption m = max_age;
		return m != null ? m.getLongValue() : OptionNumberRegistry.Defaults.MAX_AGE;
	}

	/**
	 * Checks if the Max-Age option is present.
	 * <p>
	 * If it is not present, the default value of 60 seconds applies.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasMaxAge() {
		return max_age != null;
	}

	/**
	 * Sets the Max-Age option.
	 * 
	 * @param age the Max-Age value in seconds
	 * @return this OptionSet for a fluent API.
	 * @throws IllegalArgumentException if the age has more than 4 bytes.
	 */
	public OptionSet setMaxAge(long age) {
		max_age = StandardOptionRegistry.MAX_AGE.create(age);
		return this;
	}

	/**
	 * Removes the Max-Age option. Returns the current OptionSet object for a
	 * fluent API.
	 * 
	 * @return this Optionset
	 */
	public OptionSet removeMaxAge() {
		max_age = null;
		return this;
	}

	/**
	 * Gets the list of Uri-Query arguments.
	 * <p>
	 * The OptionSet uses lazy initialization for this list.
	 * 
	 * @return the list of query arguments
	 * @since 4.0 (adapted to List of Options)
	 */
	public List<StringOption> getUriQuery() {
		synchronized (this) {
			uri_query_list = ensureList(uri_query_list);
		}
		return uri_query_list;
	}

	/**
	 * Gets the list of Uri-Query arguments as strings.
	 * <p>
	 * The OptionSet uses lazy initialization for this list.
	 * 
	 * @return the list of query arguments as strings
	 * @since 4.0
	 */
	public List<String> getUriQueryStrings() {
		return getValues(getUriQuery());
	}

	/**
	 * Gets the number of Uri-Query options (i.e., arguments).
	 * 
	 * @return the count
	 */
	public int getURIQueryCount() {
		return count(uri_query_list);
	}

	/**
	 * Gets the Uri-Query options as &amp;-separated query string.
	 * 
	 * @return the Uri-Query as string
	 */
	public String getUriQueryString() {
		return getMultiOptionString(getUriQuery(), '&');
	}

	/**
	 * Sets the complete Uri-Query through a &amp;-separated list of arguments.
	 * 
	 * @param query the Query string
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the query is {@code null}
	 * @throws IllegalArgumentException if one of the query's arguments has more
	 *             than 255 bytes.
	 */
	public OptionSet setUriQuery(String query) {
		while (query.startsWith("?"))
			query = query.substring(1);

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
	 * 
	 * @param argument the argument to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the argument is {@code null}
	 * @throws IllegalArgumentException if the argument has more than 255 bytes.
	 */
	public OptionSet addUriQuery(String argument) {
		getUriQuery().add(StandardOptionRegistry.URI_QUERY.create(argument));
		uri_query_parameter = null;
		return this;
	}

	/**
	 * Removes a specific argument from the Uri-Query options.
	 * 
	 * @param argument the argument to remove
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeUriQuery(String argument) {
		if (removeStringOption(getUriQuery(), argument)) {
			uri_query_parameter = null;
		}
		return this;
	}

	/**
	 * Removes all Uri-Query options.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet clearUriQuery() {
		clear(uri_query_list);
		uri_query_parameter = null;
		return this;
	}

	/**
	 * Gets the Uri-Query parameter.
	 * <p>
	 * The OptionSet uses lazy initialization for this map.
	 * 
	 * @return the map of Uri-Query parameter
	 * @see #getUriQueryParameter(List, List)
	 * @since 3.8
	 */
	public UriQueryParameter getUriQueryParameter() {
		if (uri_query_parameter == null) {
			return getUriQueryParameter(null, null);
		} else {
			return uri_query_parameter;
		}
	}

	/**
	 * Gets the Uri-Query parameter.
	 * 
	 * @param supportedParameterNames list of supported parameter names. May be
	 *            {@code null} or empty, if the parameter names should not be
	 *            verified.
	 * @return the map of Uri-Query parameter
	 * @throws IllegalArgumentException if a provided query parameter could not
	 *             be verified.
	 * @see #getUriQueryParameter(List, List)
	 * @since 3.8
	 */
	public UriQueryParameter getUriQueryParameter(List<String> supportedParameterNames) {
		return getUriQueryParameter(supportedParameterNames, null);
	}

	/**
	 * Gets the Uri-Query parameter.
	 * 
	 * @param supportedParameterNames list of supported parameter names. May be
	 *            {@code null} or empty, if the parameter names should not be
	 *            verified.
	 * @param unsupportedParameter list to add the unsupported parameter. May be
	 *            {@code null}, if unsupported parameter names should cause a
	 *            {@link IllegalArgumentException}.
	 * @return the map of Uri-Query parameter
	 * @throws IllegalArgumentException if a provided query parameter could not
	 *             be verified and no list for unsupported parameter is
	 *             provided.
	 * @see #getUriQueryParameter()
	 * @see #getUriQueryParameter(List)
	 * @see UriQueryParameter
	 * @since 3.8
	 */
	public UriQueryParameter getUriQueryParameter(List<String> supportedParameterNames,
			List<String> unsupportedParameter) {
		if (uri_query_list != null && !uri_query_list.isEmpty()) {
			uri_query_parameter = new UriQueryParameter(getValues(uri_query_list), supportedParameterNames,
					unsupportedParameter);
		} else {
			uri_query_parameter = UriQueryParameter.EMPTY;
		}
		return uri_query_parameter;
	}

	/**
	 * Gets the Content-Format Identifier of the Accept option (see <a href=
	 * "http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA
	 * Registry</a>).
	 * 
	 * @return the ID as int, or, {@code -1}, if undefined
	 */
	public int getAccept() {
		final IntegerOption option = accept;
		return option == null ? MediaTypeRegistry.UNDEFINED : option.getIntegerValue();
	}

	/**
	 * Checks if the Accept option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasAccept() {
		return accept != null;
	}

	/**
	 * Compares the Accept option value to a given format.
	 * 
	 * @param format the Content-Format ID to compare with
	 * @return {@code true}, if equal
	 */
	public boolean isAccept(int format) {
		final IntegerOption option = accept;
		return option != null && option.getIntegerValue() == format;
	}

	/**
	 * Sets the Content-Format ID of the Accept option (see <a href=
	 * "http://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats">IANA
	 * Registry</a>).
	 * 
	 * @param format the Content-Format ID
	 * @return this OptionSet for a fluent API.
	 * @throws IllegalArgumentException if value is out of range {@code 0} to
	 *             {@link MediaTypeRegistry#MAX_TYPE}.
	 * @see MediaTypeRegistry
	 */
	public OptionSet setAccept(int format) {
		accept = StandardOptionRegistry.ACCEPT.create(format);
		return this;
	}

	/**
	 * Removes the Accept option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeAccept() {
		accept = null;
		return this;
	}

	/**
	 * Gets the list of Location-Query arguments.
	 * <p>
	 * The OptionSet uses lazy initialization for this list.
	 * 
	 * @return the list of query arguments
	 * @since 4.0 (adapted to List of Options)
	 */
	public List<StringOption> getLocationQuery() {
		synchronized (this) {
			location_query_list = ensureList(location_query_list);
		}
		return location_query_list;
	}

	/**
	 * Gets the number of Location-Query options (i.e., arguments).
	 * 
	 * @return the count
	 */
	public int getLocationQueryCount() {
		return getLocationQuery().size();
	}

	/**
	 * Gets the Location-Query options as &amp;-separated list string.
	 * 
	 * @return the Location-Query as string
	 */
	public String getLocationQueryString() {
		return getMultiOptionString(getLocationQuery(), '&');
	}

	/**
	 * Sets the complete Location-Query through a &amp;-separated list of
	 * arguments.
	 * 
	 * @param query the Location-Query string
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the query is {@code null}
	 * @throws IllegalArgumentException if one of the query's arguments has more
	 *             than 255 bytes.
	 */
	public OptionSet setLocationQuery(String query) {
		while (query.startsWith("?"))
			query = query.substring(1);

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
	 * 
	 * @param argument the argument to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the argument is {@code null}
	 * @throws IllegalArgumentException if the argument has more than 255 bytes.
	 */
	public OptionSet addLocationQuery(String argument) {
		getLocationQuery().add(StandardOptionRegistry.LOCATION_QUERY.create(argument));
		return this;
	}

	/**
	 * Removes a specific argument from the Location-Query options.
	 * 
	 * @param argument the argument to remove
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeLocationQuery(String argument) {
		removeStringOption(getLocationQuery(), argument);
		return this;
	}

	/**
	 * Gets all Location-Query options.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet clearLocationQuery() {
		clear(location_query_list);
		return this;
	}

	/**
	 * Gets the string value of the Proxy-Uri option.
	 * 
	 * @return the Proxy-Uri or null if the option is not present
	 */
	public String getProxyUri() {
		return getValue(proxy_uri);
	}

	/**
	 * Checks if the Proxy-Uri option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasProxyUri() {
		return proxy_uri != null;
	}

	/**
	 * Sets the Proxy-Uri option.
	 * 
	 * @param uri the Proxy-Uri value to set.
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the uri is {@code null}
	 * @throws IllegalArgumentException if the uri has less than 1 or more than
	 *             1034 bytes.
	 */
	public OptionSet setProxyUri(String uri) {
		proxy_uri = StandardOptionRegistry.PROXY_URI.create(uri);
		return this;
	}

	/**
	 * Removes the Proxy-Uri option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeProxyUri() {
		proxy_uri = null;
		return this;
	}

	/**
	 * Gets the string value of the Proxy-Scheme option.
	 * 
	 * @return the Proxy-Scheme or null if the option is not present
	 */
	public String getProxyScheme() {
		return getValue(proxy_scheme);
	}

	/**
	 * Checks if the Proxy-Scheme option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasProxyScheme() {
		return proxy_scheme != null;
	}

	/**
	 * Sets the Proxy-Scheme option.
	 * 
	 * @param scheme the Proxy-Scheme value to set.
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the scheme is {@code null}
	 * @throws IllegalArgumentException if the scheme has less than 1 or more
	 *             than 255 bytes.
	 */
	public OptionSet setProxyScheme(String scheme) {
		proxy_scheme = StandardOptionRegistry.PROXY_SCHEME.create(scheme);
		return this;
	}

	/**
	 * Removes the Proxy-Scheme option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeProxyScheme() {
		proxy_scheme = null;
		return this;
	}

	/**
	 * Gets the Block1 option.
	 * 
	 * @return the BlockOption
	 */
	public BlockOption getBlock1() {
		return block1;
	}

	/**
	 * Checks if the Block1 option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasBlock1() {
		return block1 != null;
	}

	/**
	 * Sets the Block1 option.
	 * 
	 * @param szx the block size
	 * @param m the more flag
	 * @param num the block number
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet setBlock1(int szx, boolean m, int num) {
		this.block1 = StandardOptionRegistry.BLOCK1.create(szx, m, num);
		return this;
	}

	/**
	 * Sets the Block1 option.
	 * 
	 * @param block the block object
	 * @return this OptionSet for a fluent API.
	 * @throws IllegalArgumentException if block-option is no BLOCK1 option
	 */
	public OptionSet setBlock1(BlockOption block) {
		if (block != null && StandardOptionRegistry.BLOCK1 != block.getDefinition()) {
			throw new IllegalArgumentException("Block option is not BLOCK1!");
		}
		this.block1 = block;
		return this;
	}

	/**
	 * Removes the Block1 option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeBlock1() {
		this.block1 = null;
		return this;
	}

	/**
	 * Gets the Block2 option.
	 * 
	 * @return the BlockOption
	 */
	public BlockOption getBlock2() {
		return block2;
	}

	/**
	 * Checks if the Block2 option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasBlock2() {
		return block2 != null;
	}

	/**
	 * Sets the Block2 option.
	 * 
	 * @param szx the block size
	 * @param m the more flag
	 * @param num the block number
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet setBlock2(int szx, boolean m, int num) {
		this.block2 = StandardOptionRegistry.BLOCK2.create(szx, m, num);
		return this;
	}

	/**
	 * Sets the Block2 option.
	 * 
	 * @param block the block object
	 * @return this OptionSet for a fluent API.
	 * @throws IllegalArgumentException if block-option is no BLOCK2 option
	 */
	public OptionSet setBlock2(BlockOption block) {
		if (block != null && StandardOptionRegistry.BLOCK2 != block.getDefinition()) {
			throw new IllegalArgumentException("Block option is not BLOCK2!");
		}
		this.block2 = block;
		return this;
	}

	/**
	 * Removes the Block2 option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeBlock2() {
		this.block2 = null;
		return this;
	}

	/**
	 * Gets the uint value of the Size1 option.
	 * 
	 * @return the Size1 value, or, {@code null}, if the option is not present
	 */
	public Integer getSize1() {
		return getValue(size1);
	}

	/**
	 * Checks if the Size1 option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasSize1() {
		return size1 != null;
	}

	/**
	 * Sets the Size1 option value.
	 * 
	 * @param size the size of the request body
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet setSize1(int size) {
		this.size1 = StandardOptionRegistry.SIZE1.create(size);
		return this;
	}

	/**
	 * Removes the Size1 option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeSize1() {
		this.size1 = null;
		return this;
	}

	/**
	 * Gets the uint value of the Size2 option.
	 * 
	 * @return the Size2 value, or, {@code null}, if the option is not present
	 */
	public Integer getSize2() {
		return getValue(size2);
	}

	/**
	 * Checks if the Size2 option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasSize2() {
		return size2 != null;
	}

	/**
	 * Sets the Size2 option value.
	 * 
	 * @param size the size of the response body
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet setSize2(int size) {
		this.size2 = StandardOptionRegistry.SIZE2.create(size);
		return this;
	}

	/**
	 * Removes the Size2 option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeSize2() {
		this.size2 = null;
		return this;
	}

	/**
	 * Gets the uint value of the Observe option.
	 * 
	 * @return the Observe value, or, {@code null}, if the option is not present
	 */
	public Integer getObserve() {
		return getValue(observe);
	}

	/**
	 * Checks if the Observe option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasObserve() {
		return observe != null;
	}

	/**
	 * Sets the Observe option value.
	 * 
	 * @param seqnum the sequence number
	 * @return this OptionSet for a fluent API.
	 * @throws IllegalArgumentException if the given number is &lt; 0 or &gt;
	 *             2^24 - 1
	 */
	public OptionSet setObserve(final int seqnum) {
		this.observe = StandardOptionRegistry.OBSERVE.create(seqnum);
		return this;
	}

	/**
	 * Removes the Observe option.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeObserve() {
		observe = null;
		return this;
	}

	/**
	 * Gets the byte array value of the OSCore option.
	 * 
	 * @return the OSCore value or {@code null} if the option is not present
	 */
	public byte[] getOscore() {
		OpaqueOption option = oscore;
		return option == null ? null : option.getValue();
	}

	/**
	 * Checks if the OSCore option is present.
	 * 
	 * @return {@code true}, if present
	 */
	public boolean hasOscore() {
		return oscore != null;
	}

	/**
	 * Replaces the Oscore option with oscore.
	 * 
	 * @param oscore the new Oscore value
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if the oscore is {@code null}
	 * @throws IllegalArgumentException if the oscore has more than 255 bytes.
	 */
	public OptionSet setOscore(byte[] oscore) {
		this.oscore = StandardOptionRegistry.OSCORE.create(oscore.clone());
		return this;
	}

	/**
	 * Removes the OSCore options.
	 * 
	 * @return this OptionSet for a fluent API.
	 */
	public OptionSet removeOscore() {
		oscore = null;
		return this;
	}

	/**
	 * Gets the NoResponse option.
	 * 
	 * @return the NoResponse option, or, {@code null}, if the option is not
	 *         present
	 * @since 3.0
	 */
	public NoResponseOption getNoResponse() {
		return no_response;
	}

	/**
	 * Checks, if the NoResponse option is present.
	 * 
	 * @return {@code true}, if present
	 * @since 3.0
	 */
	public boolean hasNoResponse() {
		return no_response != null;
	}

	/**
	 * Sets the NoResponse option value.
	 * 
	 * @param noResponse the NoResponse pattern
	 * @return this OptionSet for a fluent API.
	 * @since 3.0
	 */
	public OptionSet setNoResponse(int noResponse) {
		this.no_response = new NoResponseOption(noResponse);
		return this;
	}

	/**
	 * Sets the NoResponse option value.
	 * 
	 * @param noResponse the NoResponse option
	 * @return this OptionSet for a fluent API.
	 * @since 3.0
	 */
	public OptionSet setNoResponse(NoResponseOption noResponse) {
		this.no_response = noResponse;
		return this;
	}

	/**
	 * Removes the NoResponse option.
	 * 
	 * @return this OptionSet for a fluent API.
	 * @since 3.0
	 */
	public OptionSet removeNoResponse() {
		this.no_response = null;
		return this;
	}

	/**
	 * Checks, if an arbitrary option is present.
	 * <p>
	 * <b>Note:</b> implementation uses {@link #asSortedList()} and is therefore
	 * not recommended to be called too frequently.
	 * 
	 * @param definition the option definition
	 * @return {@code true}, if present
	 */
	public boolean hasOption(OptionDefinition definition) {
		return Collections.binarySearch(asSortedList(), definition) >= 0;
	}

	/**
	 * Gets list of other options.
	 * <p>
	 * If not available, creates a new list.
	 * 
	 * @return list of other options
	 */
	private List<Option> getOthersInternal() {
		synchronized (this) {
			others = ensureList(others);
		}
		return others;
	}

	/**
	 * Gets list of other options.
	 * 
	 * @return an unmodifiable and unsorted list of other options.
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
	 * Gets list of other options.
	 * 
	 * @param definition other option definition
	 * @return an unmodifiable list of other options with the provided
	 *         definition. order is defined by the order of adding this options.
	 * @since 3.8
	 */
	public List<Option> getOthers(OptionDefinition definition) {
		List<Option> options = null;
		List<Option> others = this.others;
		if (others != null) {
			int pos = indexOfFirst(others, definition);
			if (pos >= 0) {
				while (pos < others.size()) {
					Option option = others.get(pos);
					if (!definition.equals(option.getDefinition())) {
						break;
					}
					if (options == null) {
						options = new ArrayList<>();
					}
					options.add(option);
					if (option.isSingleValue()) {
						break;
					}
					++pos;
				}
			}
		}
		if (options == null) {
			return Collections.emptyList();
		} else {
			return Collections.unmodifiableList(options);
		}
	}

	/**
	 * Gets other option.
	 * <p>
	 * If the other option is contained more than once, return the first.
	 * 
	 * @param <T> option type
	 * @param definition other option definition
	 * @return other option, or {@code null}, if not available.
	 * @since 3.8
	 */
	@SuppressWarnings("unchecked")
	public <T extends Option> T getOtherOption(OptionDefinition definition) {
		List<Option> others = this.others;
		if (others != null) {
			int pos = indexOfFirst(others, definition);
			if (pos >= 0) {
				return (T) others.get(pos);
			}
		}
		return null;
	}

	/**
	 * Gets all options in a list sorted according to their option number.
	 * <p>
	 * The list cannot be use to modify the OptionSet of the message, since it
	 * is a copy.
	 * 
	 * @return the sorted list (a copy)
	 */
	public List<Option> asSortedList() {
		ArrayList<Option> options = new ArrayList<>();

		// add options in order!
		if (if_match_list != null)
			options.addAll(if_match_list);
		if (hasUriHost())
			options.add(uri_host);
		if (etag_list != null)
			options.addAll(etag_list);
		if (hasIfNoneMatch())
			options.add(if_none_match);
		if (hasObserve())
			options.add(observe);
		if (hasUriPort())
			options.add(uri_port);
		if (location_path_list != null)
			options.addAll(location_path_list);
		if (hasOscore())
			options.add(oscore);
		if (uri_path_list != null)
			options.addAll(uri_path_list);
		if (hasContentFormat())
			options.add(content_format);
		if (hasMaxAge())
			options.add(max_age);
		if (uri_query_list != null)
			options.addAll(uri_query_list);
		if (hasAccept())
			options.add(accept);
		if (location_query_list != null)
			options.addAll(location_query_list);
		if (hasBlock2())
			options.add(block2);
		if (hasBlock1())
			options.add(block1);
		if (hasSize2())
			options.add(size2);
		if (hasProxyUri())
			options.add(proxy_uri);
		if (hasProxyScheme())
			options.add(proxy_scheme);

		if (hasSize1())
			options.add(size1);
		if (hasNoResponse())
			options.add(no_response);

		List<Option> others = this.others;
		if (others != null) {
			Option last = options.isEmpty() ? null : options.get(options.size() - 1);
			for (Option other : others) {
				if (last == null || last.compareTo(other) <= 0) {
					options.add(other);
					last = other;
				} else {
					addOrdered(options, other);
				}
			}
		}
		assertOrder(options);
		return options;
	}

	/**
	 * Add options.
	 * 
	 * @param options list with options to add
	 * @return this OptionSet for a fluent API.
	 * @since 3.0
	 */
	public OptionSet addOptions(Option... options) {
		if (options != null) {
			for (Option option : options) {
				addOption(option);
			}
		}
		return this;
	}

	/**
	 * Add options.
	 * 
	 * @param options list with options to add
	 * @return this OptionSet for a fluent API.
	 * @since 3.0
	 */
	public OptionSet addOptions(List<Option> options) {
		if (options != null) {
			for (Option option : options) {
				addOption(option);
			}
		}
		return this;
	}

	/**
	 * Adds an arbitrary option.
	 * <p>
	 * Single value options are replaced, repeated options are appended.
	 * 
	 * @param option the Option object to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if option is {@code null}.
	 */
	public OptionSet addOption(Option option) {
		if (option == null) {
			throw new NullPointerException("Option must not be null!");
		}
		switch (option.getNumber()) {
		case OptionNumberRegistry.IF_MATCH:
			getIfMatch().add((OpaqueOption) option);
			break;
		case OptionNumberRegistry.URI_HOST:
			uri_host = (StringOption) option;
			break;
		case OptionNumberRegistry.ETAG:
			getETags().add((OpaqueOption) option);
			break;
		case OptionNumberRegistry.IF_NONE_MATCH:
			if_none_match = (EmptyOption) option;
			break;
		case OptionNumberRegistry.URI_PORT:
			uri_port = (IntegerOption) option;
			break;
		case OptionNumberRegistry.LOCATION_PATH:
			getLocationPath().add((StringOption) option);
			break;
		case OptionNumberRegistry.URI_PATH:
			getUriPath().add((StringOption) option);
			break;
		case OptionNumberRegistry.CONTENT_FORMAT:
			content_format = (IntegerOption) option;
			break;
		case OptionNumberRegistry.MAX_AGE:
			max_age = (IntegerOption) option;
			break;
		case OptionNumberRegistry.URI_QUERY:
			getUriQuery().add((StringOption) option);
			break;
		case OptionNumberRegistry.ACCEPT:
			accept = (IntegerOption) option;
			break;
		case OptionNumberRegistry.LOCATION_QUERY:
			getLocationQuery().add((StringOption) option);
			break;
		case OptionNumberRegistry.PROXY_URI:
			proxy_uri = (StringOption) option;
			break;
		case OptionNumberRegistry.PROXY_SCHEME:
			proxy_scheme = (StringOption) option;
			break;
		case OptionNumberRegistry.BLOCK1:
			block1 = (BlockOption) option;
			break;
		case OptionNumberRegistry.BLOCK2:
			block2 = (BlockOption) option;
			break;
		case OptionNumberRegistry.SIZE1:
			size1 = (IntegerOption) option;
			break;
		case OptionNumberRegistry.SIZE2:
			size2 = (IntegerOption) option;
			break;
		case OptionNumberRegistry.OBSERVE:
			observe = (IntegerOption) option;
			break;
		case OptionNumberRegistry.OSCORE:
			oscore = (OpaqueOption) option;
			break;
		case OptionNumberRegistry.NO_RESPONSE:
			no_response = (NoResponseOption) option;
			break;
		default:
			addOrdered(getOthersInternal(), option);
		}
		return this;
	}

	/**
	 * Add other option.
	 * 
	 * @param option the Option object to add
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if option is {@code null}.
	 */
	public OptionSet addOtherOption(Option option) {
		if (option == null) {
			throw new NullPointerException("Option must not be null!");
		}
		addOrdered(getOthersInternal(), option);
		return this;
	}

	/**
	 * Clear other option by value.
	 * <p>
	 * <b>Note:</b> the removing is based on {@link Option#equals(Object)},
	 * which includes the value as well. For repeatable options all are removed,
	 * if the options are equal.
	 * 
	 * @param option other option
	 * @return this OptionSet for a fluent API.
	 * @throws NullPointerException if option is {@code null}.
	 * @since 3.7
	 */
	public OptionSet clearOtherOption(Option option) {
		if (option == null) {
			throw new NullPointerException("Option must not be null!");
		}
		List<Option> others = this.others;
		if (others != null) {
			OptionDefinition definition = option.getDefinition();
			int pos = indexOfFirst(others, definition);
			if (pos >= 0) {
				while (pos < others.size()) {
					Option optionToRemove = others.get(pos);
					if (!optionToRemove.getDefinition().equals(definition)) {
						break;
					}
					if (optionToRemove.equals(option)) {
						others.remove(pos);
					} else {
						++pos;
					}
				}
			}
		}
		return this;
	}

	/**
	 * Clear other option by number.
	 * <p>
	 * <b>Note:</b> the removing is based on {@link Option#getNumber()}. For
	 * repeatable options all are removed, if the number is matching.
	 * 
	 * @param definition other option definition
	 * @return this OptionSet for a fluent API.
	 * @see #clearOtherOption(Option)
	 * @since 3.8
	 */
	public OptionSet clearOtherOption(OptionDefinition definition) {
		if (definition == null) {
			throw new NullPointerException("OptionDefinition must not be null!");
		}
		List<Option> others = this.others;
		if (others != null) {
			final int pos = indexOfFirst(others, definition);
			if (pos >= 0) {
				while (pos < others.size()) {
					Option optionToRemove = others.get(pos);
					if (!optionToRemove.getDefinition().equals(definition)) {
						break;
					}
					others.remove(pos);
					if (definition.isSingleValue()) {
						break;
					}
				}
			}
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
			if (opt.getNumber() != oldNr) {
				if (oldNr != -1) {
					if (list)
						sbv.append(']');
					sb.append(sbv).append(", ");
					sbv.setLength(0);
				}
				list = false;

				sb.append('"');
				sb.append(opt.getDefinition().getName());
				sb.append('"');
				sb.append(':');
			} else {
				if (!list)
					sbv.insert(0, '[');
				list = true;
				sbv.append(",");
			}
			sbv.append(opt.toValueString());

			oldNr = opt.getNumber();
		}
		if (list)
			sbv.append(']');
		sb.append(sbv);
		sb.append('}');

		return sb.toString();
	}

	/**
	 * Gets list of option values.
	 * 
	 * @param options list of {@link StringOption}s
	 * @return list of {@link String}s, or {@code null} if provided list is
	 *         {@code null}.
	 * @since 4.0
	 */
	public static List<String> getValues(final List<StringOption> options) {
		List<String> result = null;
		if (options != null) {
			result = new AbstractList<String>() {

				@Override
				public int size() {
					return options.size();
				}

				@Override
				public String get(int index) {
					return options.get(index).getStringValue();
				}
			};
		}
		return result;
	}

	/**
	 * Gets multiple option as string.
	 * 
	 * @param multiOption multiple option as list of strings
	 * @param separator separator for options
	 * @return multiple option as string
	 */
	private static String getMultiOptionString(List<StringOption> multiOption, char separator) {
		StringBuilder builder = new StringBuilder();
		appendMultiOption(builder, multiOption, separator);
		return builder.toString();
	}

	/**
	 * Appends multiple option to string builder.
	 * 
	 * @param builder builder to append the multiple options.
	 * @param multiOption multiple option as list of strings
	 * @param separator separator for options
	 */
	private static void appendMultiOption(StringBuilder builder, List<StringOption> multiOption, char separator) {
		if (!multiOption.isEmpty()) {
			for (StringOption optionText : multiOption) {
				builder.append(optionText.getStringValue()).append(separator);
			}
			builder.setLength(builder.length() - 1);
		}
	}

	private final static boolean removeStringOption(List<StringOption> options, String value) {
		for (StringOption option : options) {
			if (option.getStringValue().equals(value)) {
				options.remove(option);
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks, if one of the {@link OpaqueOption} contains the provided
	 * byte-array.
	 * 
	 * @param options list of {@link OpaqueOption}s. May be {@code null}.
	 * @param value byte-array to search
	 * @return {@code true} if byte-array is contained.
	 * @since 4.0
	 */
	private static final boolean contains(List<OpaqueOption> options, byte[] value) {
		if (options != null) {
			for (OpaqueOption option : options) {
				if (Arrays.equals(option.getValue(), value)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Removes provided byte-array from the list of {@link OpaqueOption}s.
	 * 
	 * @param options list of {@link OpaqueOption}s. May be {@code null}.
	 * @param value byte-array to remove
	 * @return {@code true} if byte-array is removed.
	 * @since 4.0
	 */
	private static final boolean remove(List<OpaqueOption> options, byte[] value) {
		if (options != null) {
			int max = options.size();
			for (int index = 0; index < max; ++index) {
				if (Arrays.equals(options.get(index).getValue(), value)) {
					options.remove(index);
					return true;
				}
			}
		}
		return false;
	}

}
