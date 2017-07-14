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
package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceAttributes;

import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.regex.Pattern;


public class LinkFormat {
	
	public static final String RESOURCE_TYPE         = "rt";
	public static final String INTERFACE_DESCRIPTION = "if";
	public static final String CONTENT_TYPE          = "ct";
	public static final String MAX_SIZE_ESTIMATE     = "sz";
	public static final String TITLE                 = "title";
	public static final String OBSERVABLE            = "obs";
	public static final String LINK                  = "href";

	// for Resource Directory
	public static final String HOST		     		 = "h";
	public static final String LIFE_TIME     		 = "lt";
	public static final String INSTANCE		   		 = "ins";
	public static final String DOMAIN	     		 = "d";
	public static final String CONTEXT		   		 = "con";
	public static final String END_POINT     		 = "ep";
	public static final String END_POINT_TYPE		 = "et";

	// for parsing
	public static final Pattern DELIMITER      = Pattern.compile("\\s*,+\\s*");
	public static final Pattern SEPARATOR      = Pattern.compile("\\s*;+\\s*");
	public static final Pattern WORD           = Pattern.compile("\\w+");
	public static final Pattern QUOTED_STRING  = Pattern.compile("\\G\".*?\"");
	public static final Pattern CARDINAL       = Pattern.compile("\\G\\d+");
	
	public static String serializeTree(Resource resource) {
		StringBuilder buffer = new StringBuilder();
		List<String> noQueries = Collections.emptyList();
		
		// only include children, not the entry point itself
		for (Resource child:resource.getChildren()) {
			serializeTree(child, noQueries, buffer);
		}
		
		if (buffer.length()>1)
			buffer.delete(buffer.length()-1, buffer.length());
		return buffer.toString();
	}

	public static void serializeTree(Resource resource, List<String> queries, StringBuilder buffer) {
		// add the current resource to the buffer
		if (resource.isVisible()
				&& LinkFormat.matches(resource, queries)) {
			buffer.append(LinkFormat.serializeResource(resource));
		}
		
		// sort by resource name
		List<Resource> childs = new ArrayList<Resource>(resource.getChildren());
		Collections.sort(childs, new Comparator<Resource>() {
		    @Override
		    public int compare(Resource o1, Resource o2) {
		        return o1.getName().compareTo(o2.getName());
		    }
		});
		
		for (Resource child:childs) {
			serializeTree(child, queries, buffer);
		}
	}

	public static StringBuilder serializeResource(Resource resource) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("<")
			.append(resource.getPath())
			.append(resource.getName())
			.append(">")
			.append(LinkFormat.serializeAttributes(resource.getAttributes()))
			.append(",");
		return buffer;
	}
	
	public static StringBuilder serializeAttributes(ResourceAttributes attributes) {
		StringBuilder buffer = new StringBuilder();
		

		List<String> attributesList = new ArrayList<String>(attributes.getAttributeKeySet());
		Collections.sort(attributesList);
		for (String attr : attributesList) {
			List<String> values = attributes.getAttributeValues(attr);
			if (values == null) continue;
			buffer.append(";");
			
			// Make a copy to not  depend on thread-safety
			buffer.append(serializeAttribute(attr, new LinkedList<String>(values)));
		}
		return buffer;
	}
	
	public static StringBuilder serializeAttribute(String key, List<String> values) {
		
		String delimiter = "=";
		
		StringBuilder linkFormat = new StringBuilder();
		boolean quotes = false;
		
		linkFormat.append(key);
		
		if (values==null) {
			throw new RuntimeException("Values null");
		}
		
		if (values.isEmpty() || values.get(0).equals("")) 
			return linkFormat;
		
		linkFormat.append(delimiter);
		
		if (values.size()>1 || !values.get(0).matches("^[0-9]+$")) {
			linkFormat.append('"');
			quotes = true;
		}
		
		Iterator<String> it = values.iterator();
		while (it.hasNext()) {
			linkFormat.append(it.next());
			
			if (it.hasNext()) {
				linkFormat.append(' ');
			}
		}
		
		if (quotes) {
			linkFormat.append('"');
		}
		
		return linkFormat;
	}

	/**
	 * Check whether the given resource matches the given list of queries.
	 *
	 * Queries are interpreted according to <a href="https://tools.ietf.org/html/rfc6690#section-4.1">RFC 6690</a>,
	 * section 4.1, with the important difference that more than one query can be passed to the function. The
	 * resource only matches the list of queries if the resource matches every query in the list. This functionality
	 * is required to implement resource directory filtering according to the
	 * <a href="https://tools.ietf.org/html/draft-ietf-core-resource-directory-11#section-7">Resource directory</a>
	 * draft, which requires support for matching multiple attributes.
	 *
	 * @param resource The resource to match.
	 * @param queries The list of queries to match the resource with.
	 * @return True if the resource matches all queries, false otherwise.
	 */
	public static boolean matches(Resource resource, List<String> queries) {

		if (resource == null)
			return false;
		if (queries == null || queries.size() == 0)
			return true;

		ResourceAttributes attributes = resource.getAttributes();
		String path = resource.getPath() + resource.getName();

		for (String s : queries) {
			int delim = s.indexOf("=");
			if (delim != -1) {
				// split name-value-pair
				String attrName = s.substring(0, delim);
				String expected = s.substring(delim + 1);
				if (attrName.equals(LinkFormat.LINK)) {
					if (expected.endsWith("*")) {
						if (!path.startsWith(expected.substring(0, expected.length() - 1)))
							return false;
					} else {
						if (!path.equals(expected))
							return false;
					}
				} else if (attributes.containsAttribute(attrName)) {
					// lookup attribute value
					boolean matched = false;
					for (String actual : attributes.getAttributeValues(attrName)) {
						// get prefix length according to "*"
						int prefixLength = expected.indexOf('*');
						if (prefixLength >= 0 && prefixLength < actual.length()) {
							// reduce to prefixes
							String shortened = expected.substring(0, prefixLength);
							actual = actual.substring(0, prefixLength);
							// Wildcard query
							if (actual.equals(shortened)) {
								matched = true;
								break;
							}
						} else if (actual.equals(expected)) {
							// Regular query
							matched = true;
							break;
						}
					}
					if (!matched) {
						return false;
					}
				} else if (!attributes.containsAttribute(attrName)) {
					return false;
				}
			} else {
				// flag attribute
				if (attributes.getAttributeValues(s).size() == 0) {
					return false;
				}
			}
		}
		return true;
	}
	
	public static Set<WebLink> parse(String linkFormat) {
		Pattern DELIMITER = Pattern.compile("\\s*,+\\s*");

		Set<WebLink> links = new ConcurrentSkipListSet<WebLink>();
		
		if (linkFormat!=null) {
			Scanner scanner = new Scanner(linkFormat);
			String path = null;
			while ((path = scanner.findInLine("<[^>]*>")) != null) {
				
				// Trim <...>
				path = path.substring(1, path.length() - 1);
				
				WebLink link = new WebLink(path);
				
				// Read link format attributes
				String attr = null;
				while (scanner.findWithinHorizon(DELIMITER, 1)==null && (attr = scanner.findInLine(WORD))!=null) {
					if (scanner.findWithinHorizon("=", 1) != null) {
						String value = null;
						if ((value = scanner.findInLine(QUOTED_STRING)) != null) {
							value = value.substring(1, value.length()-1); // trim " "
							if (attr.equals(TITLE)) {
								link.getAttributes().addAttribute(attr, value);
							} else {
								for (String part : value.split("\\s", 0)) {
									link.getAttributes().addAttribute(attr, part);
								}
							}
						} else if ((value = scanner.findInLine(WORD)) != null) {
							link.getAttributes().setAttribute(attr, value);
						} else if ((value = scanner.findInLine(CARDINAL)) != null) {
							link.getAttributes().setAttribute(attr, value);
						} else if (scanner.hasNext()) {
							value = scanner.next();
						}
						
					} else {
						// flag attribute without value
						link.getAttributes().addAttribute(attr);
					}
				}
				
				links.add(link);
			}
			scanner.close();
		}
		return links;
	}
}
