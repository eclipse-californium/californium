/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - use LinkFormat to parse 
 *                                                    payload into WebLinks.
 *                                                    Fixes parsing for attribute
 *                                                    with multiple values.
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.server.resources.Resource;

/**
 * This class implements attributes of the CoRE Link Format.
 */
public class LinkParser {

	protected static final Logger LOG = LoggerFactory.getLogger(LinkParser.class);
	
	public static Resource parseTree(String linkFormat) {

		Resource root = new CoapResource("");
		
		if (linkFormat!=null) {
			Set<WebLink> links = LinkFormat.parse(linkFormat);
			
			for (WebLink link : links) {
				String path = link.getURI();
				if (path.startsWith("/")) {
					path = path.substring(1);
				}
				LOG.debug("Parsing link resource: {}", path);
				Resource resource = new CoapResource(path);
				for (String attrName : link.getAttributes().getAttributeKeySet()) {
					for (String attrValue : link.getAttributes().getAttributeValues(attrName)) {
						resource.getAttributes().addAttribute(attrName, attrValue);
					}
				}
				
				root.add(resource);
			}
		}
		return root;
	}
}
