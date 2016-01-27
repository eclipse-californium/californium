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


/**
 * This class implements attributes of the CoRE Link Format.
 */
public class LinkAttribute {

// Logging /////////////////////////////////////////////////////////////////////
	
	protected static final Logger LOG = Logger.getLogger(LinkAttribute.class.getName());

// Constants ///////////////////////////////////////////////////////////////////

	public static final Pattern SEPARATOR      = Pattern.compile("\\s*;+\\s*");
	public static final Pattern WORD           = Pattern.compile("\\w+");
	public static final Pattern QUOTED_STRING  = Pattern.compile("\\G\".*?\"");
	public static final Pattern CARDINAL       = Pattern.compile("\\G\\d+");
	
// Members /////////////////////////////////////////////////////////////////////
	
	private String name;
	private String value;

// Constructors ////////////////////////////////////////////////////////////////
	
	public LinkAttribute() {
		
	}
	
	public LinkAttribute(String name, String value) {
		this.name = name;
		this.value = value;
	}
	public LinkAttribute(String name, int value) {
		this.name = name;
		this.value = Integer.valueOf(value).toString();
	}
	public LinkAttribute(String name) {
		this.name = name;
		this.value = "";
	}

// Serialization ///////////////////////////////////////////////////////////////
	
	public static LinkAttribute parse(String str) {
		return parse(new Scanner(str));
	}
	
	public static LinkAttribute parse(Scanner scanner) {
		
		String name = scanner.findInLine(WORD);
		if (name != null) {
			
			LOG.finest(String.format("Parsed link attribute: %s", name));
			
			LinkAttribute attr = new LinkAttribute();
			attr.name = name;
			
			// check for name-value-pair
			if (scanner.findWithinHorizon("=", 1) != null) {
				
				String value = null;
				if ((value = scanner.findInLine(QUOTED_STRING)) != null) {
					attr.value = value.substring(1, value.length()-1); // trim " "
				} else if ((value = scanner.findInLine(WORD)) != null) {
					attr.value = value;
				} else if ((value = scanner.findInLine(CARDINAL)) != null) {
					attr.value = value;
				} else if (scanner.hasNext()) {
					attr.value = scanner.next();
					throw new RuntimeException("LinkAttribute scanner.next()");
				}
				
			} else {
				// flag attribute
				attr.value = "";
			}
			
			return attr;
		}
		return null;
	}
	
	public String getName() {
		return name;
	}
	
	public String getValue() {
		return value;
	}
	
	public int getIntValue() {
		return Integer.parseInt(value);
	}

}
