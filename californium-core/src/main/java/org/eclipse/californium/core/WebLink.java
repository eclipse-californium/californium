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
 ******************************************************************************/
package org.eclipse.californium.core;

import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.server.resources.ResourceAttributes;

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
		builder.append(' ').append(this.attributes.getTitle());
		if (this.attributes.containsAttribute(LinkFormat.RESOURCE_TYPE)) {
			builder.append(System.lineSeparator()).append("\t").append(LinkFormat.RESOURCE_TYPE).append(":\t").append(this.attributes.getResourceTypes());
		}
		if (this.attributes.containsAttribute(LinkFormat.INTERFACE_DESCRIPTION)) {
			builder.append(System.lineSeparator()).append("\t").append(LinkFormat.INTERFACE_DESCRIPTION).append(":\t").append(this.attributes.getInterfaceDescriptions());
		}
		if (this.attributes.containsAttribute(LinkFormat.CONTENT_TYPE)) {
			builder.append(System.lineSeparator()).append("\t").append(LinkFormat.CONTENT_TYPE).append(":\t").append(this.attributes.getContentTypes());
		}
		if (this.attributes.containsAttribute(LinkFormat.MAX_SIZE_ESTIMATE)) {
			builder.append(System.lineSeparator()).append("\t").append(LinkFormat.MAX_SIZE_ESTIMATE).append(":\t").append(this.attributes.getMaximumSizeEstimate());
		}
		if (this.attributes.hasObservable()) {
			builder.append(System.lineSeparator()).append("\t").append(LinkFormat.OBSERVABLE);
		}
		return builder.toString();
	}

	@Override
	public int compareTo(WebLink other) {
		return this.uri.compareTo(other.getURI());
	}
}
