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

import java.util.List;

import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * The WebLink class can be used to programmatically browse a remote CoAP endoint.
 * It uses the {@link ResourceAttributes} class to hold the CoRE Link Format attributes.
 * The {@link CoapClient#discover()} method returns a list of WebLinks for this.
 * 
 * TODO: Add support for absolute URIs and URI checking.
 */
public class WebLink implements Comparable<WebLink> {
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
		if (this.attributes.containsAttribute(LinkFormat.TITLE)) {
			builder.append(' ').append(this.attributes.getTitle());
		}
		append(builder, LinkFormat.RESOURCE_TYPE);
		append(builder, LinkFormat.INTERFACE_DESCRIPTION);
		append(builder, LinkFormat.CONTENT_TYPE);
		append(builder, LinkFormat.MAX_SIZE_ESTIMATE);
		append(builder, LinkFormat.OBSERVABLE);
		return builder.toString();
	}

	private void append(StringBuilder builder, String attributeName) {
		if (this.attributes.containsAttribute(attributeName)) {
			builder.append(StringUtil.lineSeparator()).append("\t").append(attributeName);
			List<String> values = this.attributes.getAttributeValues(attributeName);
			if (!values.isEmpty()) {
				builder.append(":\t").append(values);
			}
		}
	}
	
	@Override
	public int compareTo(WebLink other) {
		return this.uri.compareTo(other.getURI());
	}
}
