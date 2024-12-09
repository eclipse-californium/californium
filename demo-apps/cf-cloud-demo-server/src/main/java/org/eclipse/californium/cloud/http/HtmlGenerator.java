/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.http;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generator for HTML pages.
 * <p>
 * Create forward, device-list, and single page application pages.
 * 
 * @since 3.12
 */
public class HtmlGenerator {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(HtmlGenerator.class);

	/**
	 * Create forwarding page.
	 * 
	 * @param link link to forward
	 * @param title title of forwarding page.
	 * @return forwarding page.
	 */
	public static String createForwardPage(String link, String title) {
		StringBuilder page = new StringBuilder();
		page.append("<!DOCTYPE html>\n");
		page.append("<html>\n");
		page.append("<head>\n");
		page.append("<meta charset=\"utf-8\"/>\n");
		page.append("<meta http-equiv=\"refresh\" content=\"0; url=").append(link).append("\" >");
		page.append("<title>Cloudcoap To S3 proxy</title>\n");
		page.append("<title>").append(title).append("</title>\n");
		page.append("</head>\n");
		page.append("<body>\n");
		page.append("<h2>").append(title).append("</h2>\n");
		page.append("<a href=\"").append(link).append("\">");
		page.append(link);
		page.append("</a>:");
		page.append("</body>\n");
		page.append("</html>\n");
		return page.toString();
	}

	/**
	 * Create page from {@link WebLink}s.
	 * <p>
	 * The links are prepared as relative links, if possible.
	 * 
	 * @param pagePath path to this page. Required to create relative links.
	 * @param base base for all created links
	 * @param title title of page and list
	 * @param links set of links
	 * @param linkAttribute attribute for external-link. If {@code null}, if no
	 *            external-link is used.
	 * @param attributes attributes to include in the overview.
	 * @return create page with list of links.
	 */
	public static String createListPage(String pagePath, String base, String title, Set<WebLink> links,
			String linkAttribute, String... attributes) {
		if (title.isEmpty()) {
			title = "List";
		} else if (Character.isLowerCase(title.charAt(0))) {
			title = Character.toUpperCase(title.charAt(0)) + title.substring(1).toLowerCase();
		}
		StringBuilder page = new StringBuilder();
		page.append("<!DOCTYPE html>\n");
		page.append("<html>\n");
		page.append("<head>\n");
		page.append("<meta charset=\"utf-8\"/>\n");
		page.append("<title>");
		page.append(title);
		page.append("</title>\n");
		page.append("</head>\n");
		page.append("<body>\n");
		page.append("<h2>");
		page.append(title + ":");
		page.append("</h2>\n");
		if (!links.isEmpty()) {
			String[] root = null;
			for (WebLink link : links) {
				String uri = link.getURI();
				String[] path = uri.split("/");
				if (root == null) {
					root = Arrays.copyOf(path, path.length - 1);
				} else {
					int last = path.length - 1;
					if (last > root.length) {
						last = root.length;
					}
					for (int index = 0; index < last; ++index) {
						if (!root[index].equals(path[index])) {
							last = index;
							break;
						}
					}
					if (last < root.length) {
						root = Arrays.copyOf(root, last);
					}
				}
			}
			int offset = 0;
			if (root != null) {
				for (String path : root) {
					offset += 1 + path.length();
				}
			}
			for (WebLink link : links) {
				String uri = link.getURI();
				String name = link.getAttributes().getTitle();
				if (name == null) {
					name = uri.substring(offset);
					name = decodeURL(name);
				}
				uri = link(pagePath, uri);
				if (linkAttribute != null) {
					String externalLink = link.getAttributes().getFirstAttributeValue(linkAttribute);
					if (externalLink != null) {
						if (externalLink.startsWith("/")) {
							// sub link
							uri += "/";
							externalLink = externalLink.substring(1);
						}
						// append to uri
						uri += encodeURL(externalLink);
					}
				}
				LOGGER.debug("add '{}'#'{}': '{}'", base, uri, name);
				page.append("<a href=\"").append(base).append(uri).append("\">");
				page.append(encodeHtml(name));
				page.append("</a>");
				page.append(": ");
				for (String attribute : attributes) {
					List<String> values = link.getAttributes().getAttributeValues(attribute);
					if (!values.isEmpty()) {
						for (String value : values) {
							page.append(encodeHtml(value)).append(", ");
						}
					}
				}
				page.setLength(page.length() - 2);
				page.append("<br>\n");
			}
		}
		page.append("</body>\n");
		page.append("</html>\n");
		return page.toString();
	}

	/**
	 * Create link.
	 * <p>
	 * If provided link starts with pagePath, reduce the link to a relative
	 * link.
	 * 
	 * @param pagePath path to page.
	 * @param link link to be included in page.
	 * @return resulting link, relative, if possible.
	 */
	public static String link(String pagePath, String link) {
		if (link.startsWith(pagePath)) {
			return link.substring(pagePath.length());
		} else {
			return link;
		}
	}

	/**
	 * URL decode the link.
	 * 
	 * @param link link to decode
	 * @return decoded link
	 */
	public static String decodeURL(String link) {
		try {
			return URLDecoder.decode(link, CoAP.UTF8_CHARSET.name());
		} catch (UnsupportedEncodingException e) {
			// UTF-8 must be supported,
			// otherwise many functions will fail
			return link;
		}
	}

	/**
	 * URL encode the link.
	 * 
	 * @param link link to encode
	 * @return encoded link
	 */
	public static String encodeURL(String link) {
		try {
			return URLEncoder.encode(link, CoAP.UTF8_CHARSET.name());
		} catch (UnsupportedEncodingException e) {
			// UTF-8 must be supported,
			// otherwise many functions will fail
			return link;
		}
	}

	private static final char[] ESCAPE;

	static {
		ESCAPE = "\"'<>&".toCharArray();
		Arrays.sort(ESCAPE);
	}

	/**
	 * Encode text for HTML.
	 * 
	 * @param text text to encode
	 * @return encoded text
	 */
	public static String encodeHtml(String text) {
		StringBuilder out = new StringBuilder();
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c > 127 || Arrays.binarySearch(ESCAPE, c) >= 0) {
				out.append("&#").append((int) c).append(';');
			} else {
				out.append(c);
			}
		}
		return out.toString();
	}

}
