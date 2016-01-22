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
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.util.Scanner;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.server.resources.Resource;


/**
 * This class implements attributes of the CoRE Link Format.
 */
public class LinkParser {

	protected static final Logger LOG = Logger.getLogger(LinkParser.class.getName());
	
	public static Resource parseTree(String linkFormat) {
		Pattern DELIMITER = Pattern.compile("\\s*,+\\s*");

		Resource root = new CoapResource("");
		
		if (linkFormat!=null) {
			Scanner scanner = new Scanner(linkFormat);
			
			String path = null;
			while ((path = scanner.findInLine("</[^>]*>")) != null) {
				
				// Trim </...>
				path = path.substring(2, path.length() - 1);
				
				LOG.finer(String.format("Parsing link resource: %s", path));
	
				// Retrieve specified resource, create if necessary
				Resource resource = new CoapResource(path);
				
				// Read link format attributes
				LinkAttribute attr = null;
				while (scanner.findWithinHorizon(DELIMITER, 1)==null && (attr = LinkAttribute.parse(scanner))!=null) {
					resource.getAttributes().addAttribute(attr.getName(), attr.getValue());
				}
				
				root.add(resource);
			}
		}
		return root;
	}
}
