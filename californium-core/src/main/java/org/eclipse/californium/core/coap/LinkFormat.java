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
package org.eclipse.californium.core.coap;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.regex.Pattern;

import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Link format utility class.
 *
 * Serialize and parse web-links.
 */
public class LinkFormat {

	public static final String RESOURCE_TYPE = "rt";
	public static final String INTERFACE_DESCRIPTION = "if";
	public static final String CONTENT_TYPE = "ct";
	public static final String MAX_SIZE_ESTIMATE = "sz";
	public static final String TITLE = "title";
	public static final String OBSERVABLE = "obs";
	public static final String LINK = "href";
	public static final String OSCOREONLY = "osc"; // RFC 8613

	// for Resource Directory
	public static final String LIFE_TIME = "lt";
	public static final String SECTOR = "d";
	public static final String CONTEXT = "anchor";
	public static final String BASE = "base";
	public static final String RELATION = "rel";
	public static final String END_POINT = "ep";
	public static final String END_POINT_TYPE = "et";
	public static final String COUNT = "count";
	public static final String PAGE = "page";

	// for parsing
	public static final Pattern DELIMITER = Pattern.compile("\\s*,+\\s*");
	public static final Pattern TAG = Pattern.compile("<[^>]*>");
	public static final Pattern SEPARATOR = Pattern.compile("\\s*;+\\s*");
	public static final Pattern WORD = Pattern.compile("\\w+");
	public static final Pattern QUOTED_STRING = Pattern.compile("\\G\".*?\"");
	public static final Pattern CARDINAL = Pattern.compile("\\G\\d+");
	public static final Pattern EQUAL = Pattern.compile("=");

	public static final Pattern SPACE = Pattern.compile("\\s");
	public static final Pattern NUMBER = Pattern.compile("^\\d+$");

	/**
	 * Sort collection of resources by name.
	 * 
	 * @param resources collection of resources
	 * @return list of resources sorted by name
	 * @since 3.3
	 */
	public static List<Resource> sort(Collection<Resource> resources) {
		// sort by resource name
		List<Resource> sortedResources = new ArrayList<Resource>(resources);
		Collections.sort(sortedResources, new Comparator<Resource>() {

			@Override
			public int compare(Resource o1, Resource o2) {
				return o1.getName().compareTo(o2.getName());
			}
		});
		return sortedResources;
	}

	/**
	 * Get sub tree as {@link WebLink}.
	 * 
	 * The sub tree contains all child resources, but not the provided resource
	 * itself.
	 * 
	 * @param resource to get the sub tree
	 * @return the sub tree
	 * @since 3.7
	 */
	public static Set<WebLink> getSubTree(Resource resource) {
		return getSubTree(resource, null);
	}

	/**
	 * Get sub tree as {@link WebLink}.
	 * 
	 * The sub tree contains all child resources, but not the provided resource
	 * itself.
	 * 
	 * @param resource to get the sub tree
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @return the sub tree
	 * @since 3.7
	 */
	public static Set<WebLink> getSubTree(Resource resource, List<String> queries) {
		Set<WebLink> links = new ConcurrentSkipListSet<>();
		addSubTree(resource, queries, links);
		return links;
	}

	/**
	 * Add sub tree as {@link WebLink}.
	 * 
	 * The sub tree contains all child resources, but not the provided resource
	 * itself.
	 * 
	 * @param resource to get sub tree
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @param links set to add the sub tree
	 * @since 3.7
	 */
	public static void addSubTree(Resource resource, List<String> queries, Set<WebLink> links) {
		for (Resource child : sort(resource.getChildren())) {
			addTree(child, queries, links);
		}
	}

	/**
	 * Get tree as {@link WebLink}.
	 * 
	 * The tree contains the provided resource itself and all child resources.
	 * 
	 * @param resource to get the tree
	 * @return the tree
	 * @since 3.7
	 */
	public static Set<WebLink> getTree(Resource resource) {
		return getTree(resource, null);
	}

	/**
	 * Get tree as {@link WebLink}.
	 * 
	 * The tree contains the provided resource itself and all child resources.
	 * 
	 * @param resource to get the tree
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @return the tree
	 * @since 3.7
	 */
	public static Set<WebLink> getTree(Resource resource, List<String> queries) {
		Set<WebLink> links = new ConcurrentSkipListSet<>();
		addTree(resource, queries, links);
		return links;
	}

	/**
	 * Add tree as {@link WebLink}.
	 * 
	 * The tree contains the provided resource itself and all child resources.
	 * 
	 * @param resource to get sub tree
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @param links set to add the tree
	 * @since 3.7
	 */
	public static void addTree(Resource resource, List<String> queries, Set<WebLink> links) {
		// add the current resource to the buffer
		if (resource.isVisible()) {
			WebLink link = createWebLink(resource);
			if (matches(link, queries)) {
				links.add(link);
			}
		}
		addSubTree(resource, queries, links);
	}

	/**
	 * Serialize set of web-links.
	 * 
	 * @param links set of web-links
	 * @return serialized web-links
	 * @since 3.7
	 */
	public static String serialize(Set<WebLink> links) {
		StringBuilder builder = new StringBuilder();
		serialize(links, builder);
		return builder.toString();
	}

	/**
	 * Serialize set of web-links.
	 * 
	 * @param links set of web-links
	 * @param builder string builder to serialize web-links
	 * @since 3.7
	 */
	public static void serialize(Set<WebLink> links, StringBuilder builder) {
		for (WebLink link : links) {
			serialize(link, builder);
			builder.append(',');
		}
		// remove last comma ',' of the builder
		StringUtil.truncateTail(builder, ",");
	}

	/**
	 * Serialize web-link.
	 * 
	 * @param link web-link
	 * @return serialized web-link
	 * @since 3.7
	 */
	public static String serialize(WebLink link) {
		StringBuilder builder = new StringBuilder();
		serialize(link, builder);
		return builder.toString();
	}

	/**
	 * Serialize web-link.
	 * 
	 * @param link web-link
	 * @param builder string builder to serialize web-link
	 * @since 3.7
	 */
	public static void serialize(WebLink link, StringBuilder builder) {
		builder.append("<").append(link.getURI()).append(">");
		serializeAttributes(link.getAttributes(), builder);
	}

	/**
	 * Serialize sub-tree of provided resource.
	 * 
	 * The provided resource itself is not serialized. The children are listed
	 * ordered by their name.
	 * 
	 * @param resource resource to serialize
	 * @return serialized (sub-)tree
	 */
	public static String serializeTree(Resource resource) {
		return serializeTree(resource, null);
	}

	/**
	 * Serialize sub-tree of provided resource.
	 * 
	 * The provided resource itself is not serialized. The children are listed
	 * ordered by their name.
	 * 
	 * @param resource resource to serialize
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @return serialized (sub-)tree
	 * @since 3.3
	 */
	public static String serializeTree(Resource resource, List<String> queries) {
		Set<WebLink> subTree = getSubTree(resource, queries);
		return serialize(subTree);
	}

	/**
	 * Serialize tree of provided resource into the buffer.
	 * 
	 * The provided resource and all children are serialized. The children are
	 * listed ordered by their name.
	 * 
	 * @param resource resource to serialize
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @param buffer buffer to serialize the (sub-)tree of the provided
	 *            resource. Ends with {@code ","}.
	 * @deprecated use {@link #getSubTree(Resource, List)} and
	 *             {@link #serialize(Set, StringBuilder)} instead. The
	 *             {@code ","} at the end must be added, if required.
	 */
	@Deprecated
	public static void serializeTree(Resource resource, List<String> queries, StringBuilder buffer) {
		// add the current resource to the buffer
		Set<WebLink> subTree = getSubTree(resource, queries);
		serialize(subTree, buffer);
		buffer.append(',');
	}

	/**
	 * Serialize provided resource.
	 * 
	 * @param resource resource to serialize
	 * @return serialized resource. Ends with {@code ","}.
	 * @deprecated use {@link #createWebLink(Resource)} and
	 *             {@link #serialize(WebLink)} instead. The {@code ","} at the
	 *             end must be added, if required.
	 */
	@Deprecated
	public static StringBuilder serializeResource(Resource resource) {
		WebLink webLink = createWebLink(resource);
		StringBuilder builder = new StringBuilder();
		serialize(webLink, builder);
		builder.append(",");
		return builder;
	}

	/**
	 * Serialize resource path into provided builder.
	 * 
	 * Apply URL encoding for the single elements.
	 * 
	 * @param resource Resource to serialize the path
	 * @return builder with serialized resource path
	 */
	public static StringBuilder serializePath(Resource resource) {
		StringBuilder builder = new StringBuilder();
		serializePath(resource, builder);
		StringUtil.truncateTail(builder, "/");
		return builder;
	}

	/**
	 * Serialize resource path into provided builder.
	 * 
	 * Apply URL encoding for the single elements.
	 * 
	 * @param resource Resource to serialize the path
	 * @param builder builder to serialize the resource path
	 */
	private static void serializePath(Resource resource, StringBuilder builder) {
		if (resource == null) {
			return;
		}
		serializePath(resource.getParent(), builder);
		String path = serializePathName(resource.getName());
		builder.append(path).append("/");
	}

	/**
	 * Serialize name in path.
	 * 
	 * Apply URL encoding.
	 * 
	 * @param name name to encode.
	 * @return URL encoded name
	 * @since 3.3
	 */
	public static String serializePathName(String name) {
		try {
			return URLEncoder.encode(name, CoAP.UTF8_CHARSET.name());
		} catch (UnsupportedEncodingException e) {
			// UTF-8 must be supported, otherwise many functions will fail
			return "";
		}
	}

	/**
	 * Serialize attributes.
	 * 
	 * The attributes are listed ordered by their name.
	 * 
	 * @param attributes attributes to serialize
	 * @return serialized attributes
	 */
	public static StringBuilder serializeAttributes(ResourceAttributes attributes) {
		StringBuilder builder = new StringBuilder();
		serializeAttributes(attributes, builder);
		return builder;
	}

	/**
	 * Serialize attributes.
	 * 
	 * The attributes are listed ordered by their name.
	 * 
	 * @param attributes attributes to serialize
	 * @param builder string builder to serialize attributes.
	 * @since 3.7
	 */
	public static void serializeAttributes(ResourceAttributes attributes, StringBuilder builder) {

		List<String> attributesList = new ArrayList<String>(attributes.getAttributeKeySet());
		Collections.sort(attributesList);
		for (String attr : attributesList) {
			List<String> values = attributes.getAttributeValues(attr);
			if (values.isEmpty())
				continue;
			builder.append(";");

			serializeAttribute(attr, values, builder);
		}
	}

	/**
	 * Serialize attribute.
	 * 
	 * @param key attribute name
	 * @param values list of attribute values
	 * @return serialized attribute
	 */
	public static StringBuilder serializeAttribute(String key, List<String> values) {

		StringBuilder linkFormat = new StringBuilder();
		serializeAttribute(key, values, linkFormat);
		return linkFormat;
	}

	/**
	 * Serialize attribute.
	 * 
	 * @param key attribute name
	 * @param values list of attribute values
	 * @param linkFormat string builder to serialize attribute.
	 * @since 3.7
	 */
	public static void serializeAttribute(String key, List<String> values, StringBuilder linkFormat) {
		boolean quotes = false;

		linkFormat.append(key);

		if (values == null) {
			throw new RuntimeException("Values must not be null!");
		}

		if (values.isEmpty() || (values.size() == 1 && values.get(0).isEmpty())) {
			return;
		}

		linkFormat.append('=');

		if (values.size() > 1 || !NUMBER.matcher(values.get(0)).matches()) {
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
	}

	/**
	 * Check whether the given resource matches the given list of queries.
	 *
	 * Queries are interpreted according to
	 * <a href="https://tools.ietf.org/html/rfc6690#section-4.1" target=
	 * "_blank">RFC 6690</a>, section 4.1, with the important difference that
	 * more than one query can be passed to the function. The resource only
	 * matches the list of queries if the resource matches every query in the
	 * list. This functionality is required to implement resource directory
	 * filtering according to the <a href=
	 * "https://tools.ietf.org/html/draft-ietf-core-resource-directory-11#section-7"
	 * target="_blank">Resource directory</a> draft, which requires support for
	 * matching multiple attributes.
	 *
	 * @param resource The resource to match.
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @return {@code true}, if the resource matches all queries, {@code false}
	 *         otherwise.
	 * @see #matches(WebLink, List)
	 * @deprecated use {@link #createWebLink(Resource)} and
	 *             {@link #matches(WebLink, List)} instead.
	 */
	@Deprecated
	public static boolean matches(Resource resource, List<String> queries) {

		if (resource == null) {
			return false;
		}
		if (queries == null || queries.isEmpty()) {
			return true;
		}

		return matches(createWebLink(resource), queries);
	}

	/**
	 * Check whether the given web-link matches the given list of queries.
	 *
	 * Queries are interpreted according to
	 * <a href="https://tools.ietf.org/html/rfc6690#section-4.1" target=
	 * "_blank">RFC 6690</a>, section 4.1, with the important difference that
	 * more than one query can be passed to the function. The resource only
	 * matches the list of queries if the resource matches every query in the
	 * list. This functionality is required to implement resource directory
	 * filtering according to the <a href=
	 * "https://tools.ietf.org/html/draft-ietf-core-resource-directory-11#section-7"
	 * target="_blank">Resource directory</a> draft, which requires support for
	 * matching multiple attributes.
	 *
	 * @param link The web-link to match.
	 * @param queries The list of queries to match the resource with. A empty
	 *            list or {@code null} matches all resources.
	 * @return {@code true}, if the web-link matches all queries, {@code false}
	 *         otherwise.
	 * @see #matches(Resource, List)
	 * @since 3.3
	 */
	public static boolean matches(WebLink link, List<String> queries) {

		if (link == null) {
			return false;
		}
		if (queries == null || queries.isEmpty()) {
			return true;
		}

		ResourceAttributes attributes = link.getAttributes();

		for (String s : queries) {
			String attrName = s;
			String expected = null;
			boolean prefix = false;
			int delim = s.indexOf('=');
			if (delim != -1) {
				// split name-value-pair
				attrName = s.substring(0, delim);
				prefix = s.endsWith("*");
				int end = s.length();
				if (prefix) {
					--end;
				}
				expected = s.substring(delim + 1, end);
				if (attrName.equals(LinkFormat.LINK)) {
					if (!matches(prefix, expected, link.getURI())) {
						return false;
					}
					continue;
				}
			}
			List<String> values = attributes.getAttributeValues(attrName);
			if (values.isEmpty()) {
				// no attribute of that name found
				return false;
			}
			if (expected != null) {
				// lookup attribute value
				boolean matched = false;
				for (String actual : values) {
					if (matches(prefix, expected, actual)) {
						matched = true;
						break;
					}
				}
				if (!matched) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Matches two {@link String} values supporting to match the prefix only.
	 * 
	 * @param prefix {@code true}, if expected is the prefix to match the value,
	 *            {@code false}, if expected must fully match the value.
	 * @param expected expected value or prefix
	 * @param value actual value
	 * @return {@code true}, if expected matches the value, {@code false}, if
	 *         not.
	 * @since 3.3
	 */
	private static boolean matches(boolean prefix, String expected, String value) {
		if (!value.startsWith(expected)) {
			return false;
		}
		return prefix || expected.length() == value.length();
	}

	/**
	 * Create web-link from resource.
	 * 
	 * @param resource resource
	 * @return created web-link
	 * @throws NullPointerException if provided resource was {@code null}
	 * @since 3.7
	 */
	public static WebLink createWebLink(Resource resource) {
		if (resource == null) {
			throw new NullPointerException("Resource must not be null!");
		}
		WebLink link = new WebLink(serializePath(resource).toString());
		link.getAttributes().copy(resource.getAttributes());
		return link;
	}

	/**
	 * Parse formated links.
	 * 
	 * @param linkFormat formated links
	 * @return set of parsed {@link WebLink}s
	 */
	public static Set<WebLink> parse(String linkFormat) {

		Set<WebLink> links = new ConcurrentSkipListSet<WebLink>();

		if (linkFormat != null) {
			Scanner scanner = new Scanner(linkFormat);
			String path = null;
			while ((path = scanner.findInLine(TAG)) != null) {

				// Trim <...>
				path = path.substring(1, path.length() - 1);

				WebLink link = new WebLink(path);

				// Read link format attributes
				String attr = null;
				while (scanner.findWithinHorizon(SEPARATOR, 1) != null && (attr = scanner.findInLine(WORD)) != null) {
					if (scanner.findWithinHorizon(EQUAL, 1) != null) {
						String value = null;
						if ((value = scanner.findInLine(QUOTED_STRING)) != null) {
							// trim " "
							value = value.substring(1, value.length() - 1);
							if (attr.equals(TITLE)) {
								link.getAttributes().addAttribute(attr, value);
							} else {
								for (String part : SPACE.split(value)) {
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

				if (scanner.findWithinHorizon(DELIMITER, 1) == null) {
					break;
				}
			}
			scanner.close();
		}
		return links;
	}
}
