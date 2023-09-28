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
 ******************************************************************************/
package org.eclipse.californium.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * The WebLink class can be used to programmatically browse a remote CoAP
 * endoint. It uses the {@link ResourceAttributes} class to hold the CoRE Link
 * Format attributes. The {@link CoapClient#discover()} method returns a list of
 * WebLinks for this.
 * 
 * TODO: Add support for absolute URIs and URI checking.
 */
public class WebLink implements Comparable<WebLink> {

	/**
	 * List of standard attribute names. Defines order in {@link #toString()}.
	 * 
	 * @since 3.7
	 */
	private static final List<String> STANDARD_ATTRIBUTE_NAMES = Arrays.asList(LinkFormat.RESOURCE_TYPE,
			LinkFormat.INTERFACE_DESCRIPTION, LinkFormat.CONTENT_TYPE, LinkFormat.MAX_SIZE_ESTIMATE,
			LinkFormat.OBSERVABLE);

	private String uri;
	private final ResourceAttributes attributes;

	public WebLink(String uri) {
		this.uri = uri;
		this.attributes = new ResourceAttributes();
	}

	public String getURI() {
		return this.uri;
	}

	public ResourceAttributes getAttributes() {
		return attributes;
	}

	/**
	 * Renders the Web link information as a multi-line string, which can be
	 * displayed in console clients.
	 * 
	 * @return a string representation of the Web link
	 */
	public String toString() {
		StringBuilder builder = new StringBuilder();

		builder.append('<');
		builder.append(this.uri);
		builder.append('>');

		/// list of other attribute names
		List<String> allOtherAttributeNames = new ArrayList<>(this.attributes.getAttributeKeySet());
		// remove standard ordered attribute names
		allOtherAttributeNames.removeAll(STANDARD_ATTRIBUTE_NAMES);

		// start with title
		if (this.attributes.containsAttribute(LinkFormat.TITLE)) {
			builder.append(' ').append(this.attributes.getTitle());
			allOtherAttributeNames.remove(LinkFormat.TITLE);
		}
		// standard ordered attributes
		append(builder, STANDARD_ATTRIBUTE_NAMES);

		// other attributes sorted by name
		Collections.sort(allOtherAttributeNames);
		append(builder, allOtherAttributeNames);

		return builder.toString();
	}

	private void append(StringBuilder builder, List<String> attributes) {
		for (String attribute : attributes) {
			append(builder, attribute);
		}
	}

	private void append(StringBuilder builder, String attributeName) {
		List<String> values = this.attributes.getAttributeValues(attributeName);
		int size = values.size();
		if (size > 0) {
			builder.append(StringUtil.lineSeparator()).append("\t").append(attributeName);
			if (size == 1) {
				builder.append(":\t").append(values.get(0));
			} else {
				builder.append(":\t").append(values);
			}
		}
	}

	@Override
	public int compareTo(WebLink other) {
		return this.uri.compareTo(other.getURI());
	}

	/**
	 * Find {@link WebLink} by URI.
	 * 
	 * @param links collection of links
	 * @param uri URI
	 * @return web-link matching the URI
	 * @since 3.3
	 */
	public static WebLink findByUri(Collection<WebLink> links, String uri) {
		for (WebLink link : links) {
			if (link.getURI().equals(uri)) {
				return link;
			}
		}
		return null;
	}

}
