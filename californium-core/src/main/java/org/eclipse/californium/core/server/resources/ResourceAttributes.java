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
package org.eclipse.californium.core.server.resources;

import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.eclipse.californium.core.coap.LinkFormat;

/**
 * ResourceAttributes wraps different attributes that the CoAP protocol defines
 * such as title, resource type or interface description. These attributes will
 * also be included in the link description of the resource they belong to. For
 * example, if a title was specified, the link description for a sensor resource
 * might look like this {@code </sensors>;title="Sensor Index"}.
 * 
 * Note: The synchronization before version 3.7 is unclear and the outcome of
 * simultaneous use of read and write operations was undefined. In some case
 * traversing a list of attribute values may have failed with a
 * {@link ConcurrentModificationException}. With 3.7, the value lists are
 * changed to use {@link CopyOnWriteArrayList} but using this collection of
 * attributes may still be not "atomic". {@link Resource}s, which are intended
 * to change their {@link ResourceAttributes} and requires that change to be
 * "atomic", must clone the current {@link ResourceAttributes}, modify the clone
 * and then replace the original {@link ResourceAttributes} by the modified
 * {@link ResourceAttributes} and content.
 * 
 * @since 3.7 adapted value lists to unmodifiable lists based on a
 *        {@link ConcurrentModificationException} in order traverse them safely.
 */
public class ResourceAttributes {

	/** Contains the resource's attributes specified in the CoRE Link Format. */
	private final ConcurrentMap<String, AttributeValues> attributes;

	/**
	 * Instantiates a new resource attributes.
	 */
	public ResourceAttributes() {
		attributes = new ConcurrentHashMap<String, AttributeValues>();
	}

	/**
	 * Instantiates a deep copy of the provided resource attributes.
	 * 
	 * @param attributes resource attributes to be copied.
	 * @since 3.7
	 */
	public ResourceAttributes(ResourceAttributes attributes) {
		this.attributes = new ConcurrentHashMap<String, AttributeValues>();
		copy(attributes);
	}

	/**
	 * Gets the number of attributes.
	 *
	 * @return the number of attributes
	 */
	public int getCount() {
		return attributes.size();
	}

	/**
	 * Gets the resource title.
	 *
	 * @return the title. {@code null}, if not available.
	 */
	public String getTitle() {
		return getFirstAttributeValue(LinkFormat.TITLE);
	}

	/**
	 * Sets the resource title.
	 *
	 * @param title the new title
	 */
	public void setTitle(String title) {
		findAttributeValues(LinkFormat.TITLE).setOnly(title);
	}

	/**
	 * Clear the resource title.
	 * 
	 * @since 3.8
	 */
	public void clearTitle() {
		attributes.remove(LinkFormat.TITLE);
	}

	/**
	 * Adds a resource type.
	 *
	 * @param type the type
	 */
	public void addResourceType(String type) {
		findAttributeValues(LinkFormat.RESOURCE_TYPE).add(type);
	}

	/**
	 * Gets all resource types.
	 *
	 * @return the resource types
	 */
	public List<String> getResourceTypes() {
		return getAttributeValues(LinkFormat.RESOURCE_TYPE);
	}

	/**
	 * Clear all resource types.
	 */
	public void clearResourceType() {
		attributes.remove(LinkFormat.RESOURCE_TYPE);
	}

	/**
	 * Adds an interface description.
	 *
	 * @param description the description
	 */
	public void addInterfaceDescription(String description) {
		findAttributeValues(LinkFormat.INTERFACE_DESCRIPTION).add(description);
	}

	/**
	 * Gets all interface descriptions.
	 *
	 * @return the interface descriptions
	 */
	public List<String> getInterfaceDescriptions() {
		return getAttributeValues(LinkFormat.INTERFACE_DESCRIPTION);
	}

	/**
	 * Clear all interface descriptions.
	 * 
	 * @since 3.3
	 */
	public void clearInterfaceDescriptions() {
		attributes.remove(LinkFormat.INTERFACE_DESCRIPTION);
	}

	/**
	 * Sets the maximum size estimate.
	 *
	 * @param size the new maximum size estimate
	 */
	public void setMaximumSizeEstimate(String size) {
		findAttributeValues(LinkFormat.MAX_SIZE_ESTIMATE).setOnly(size);
	}

	/**
	 * Sets the maximum size estimate.
	 *
	 * @param size the new maximum size estimate
	 */
	public void setMaximumSizeEstimate(int size) {
		findAttributeValues(LinkFormat.MAX_SIZE_ESTIMATE).setOnly(Integer.toString(size));
	}

	/**
	 * Gets the maximum size estimate.
	 *
	 * @return the maximum size estimate
	 */
	public String getMaximumSizeEstimate() {
		return getFirstAttributeValue(LinkFormat.MAX_SIZE_ESTIMATE);
	}

	/**
	 * Adds a content type specified by an integer.
	 *
	 * @param type the type
	 */
	public void addContentType(int type) {
		findAttributeValues(LinkFormat.CONTENT_TYPE).add(Integer.toString(type));
	}

	/**
	 * Adds a content types specified by an array of integers.
	 *
	 * @param types the array of types
	 * @since 3.7
	 */
	public void addContentTypes(int... types) {
		AttributeValues attributeValues = findAttributeValues(LinkFormat.CONTENT_TYPE);
		for (int type : types) {
			attributeValues.add(Integer.toString(type));
		}
	}

	/**
	 * Gets all content types as list.
	 *
	 * @return the content types
	 */
	public List<String> getContentTypes() {
		return getAttributeValues(LinkFormat.CONTENT_TYPE);
	}

	/**
	 * Clear all content types.
	 */
	public void clearContentType() {
		attributes.remove(LinkFormat.CONTENT_TYPE);
	}

	/**
	 * Marks the resource as observable.
	 */
	public void setObservable() {
		findAttributeValues(LinkFormat.OBSERVABLE).setOnly("");
	}

	/**
	 * Checks if the resource is observable.
	 *
	 * @return true, if observable
	 */
	public boolean hasObservable() {
		return hasAttribute(LinkFormat.OBSERVABLE);
	}

	/**
	 * Marks the resource as not observable.
	 * 
	 * @since 3.6
	 */
	public void clearObservable() {
		attributes.remove(LinkFormat.OBSERVABLE);
	}

	/**
	 * Marks the resource as only accessible using OSCORE.
	 *
	 * @since 3.10
	 */
	public void setOscoreOnly() {
		findAttributeValues(LinkFormat.OSCOREONLY).setOnly("");
	}

	/**
	 * Checks if the resource is only accessible using OSCORE.
	 *
	 * @return {@code true}, if only accessible using OSCORE
	 * @since 3.10
	 */
	public boolean hasOscoreOnly() {
		return hasAttribute(LinkFormat.OSCOREONLY);
	}

	/**
	 * Marks the resource as not only accessible using OSCORE.
	 *
	 * @since 3.10
	 */
	public void clearOscoreOnly() {
		attributes.remove(LinkFormat.OSCOREONLY);
	}

	/**
	 * Replaces the value for the specified attribute with the specified value.
	 * If another value has been set for the attribute name, it will be removed.
	 * 
	 * @param attr the attribute name
	 * @param value the value
	 */
	public void setAttribute(String attr, String value) {
		findAttributeValues(attr).setOnly(value);
	}

	/**
	 * Checks if the resource has attribute.
	 *
	 * @param attr attribute name.
	 * @return true, if resource has attribute
	 * @since 3.7
	 */
	public boolean hasAttribute(String attr) {
		return !getAttributeValues(attr).isEmpty();
	}

	/**
	 * Adds an arbitrary attribute with no value.
	 *
	 * @param attr the attribute name
	 */
	public void addAttribute(String attr) {
		addAttribute(attr, "");
	}

	/**
	 * Adds the specified value to the other values of the specified attribute
	 * name.
	 * 
	 * @param attr the attribute
	 * @param value the value
	 * @see #addAttribute(String, List)
	 */
	public void addAttribute(String attr, String value) {
		findAttributeValues(attr).add(value);
	}

	/**
	 * Adds the specified values to the other values of the specified attribute
	 * name.
	 * 
	 * @param attr the attribute
	 * @param values the values
	 * @see #addAttribute(String, String)
	 * @since 3.7
	 */
	public void addAttribute(String attr, List<String> values) {
		findAttributeValues(attr).addAll(values);
	}

	/**
	 * Checks, if the specified attribute is available.
	 *
	 * @param attr the attribute
	 * @return {@code true}, if available, {@code false}, otherwise.
	 */
	public boolean containsAttribute(String attr) {
		return attributes.containsKey(attr);
	}

	/**
	 * Removes all values for the specified attribute
	 *
	 * @param attr the attribute
	 */
	public void clearAttribute(String attr) {
		attributes.remove(attr);
	}

	/**
	 * Returns a {@link Set} view of the attribute names.
	 * 
	 * If the map is modified while an iteration over the set is in progress
	 * (except through the iterator's own <tt>remove</tt> operation), the
	 * results of the iteration are undefined. The set supports element removal,
	 * which removes the corresponding mapping from the map, via the
	 * <tt>Iterator.remove</tt>, <tt>Set.remove</tt>, <tt>removeAll</tt>,
	 * <tt>retainAll</tt>, and <tt>clear</tt> operations. It does not support
	 * the <tt>add</tt> or <tt>addAll</tt> operations.
	 * 
	 * @return a set view of the attribute names
	 */
	public Set<String> getAttributeKeySet() {
		return attributes.keySet();
	}

	/**
	 * Gets all values for the specified attribute.
	 *
	 * @param attr the attribute
	 * @return the attribute values (unmodifiable list). If no values available,
	 *         return a empty list.
	 * @since 3.7 returns unmodifiable list
	 */
	public List<String> getAttributeValues(String attr) {
		AttributeValues list = attributes.get(attr);
		if (list != null)
			return list.getAll();
		else
			return Collections.emptyList();
	}

	/**
	 * Gets first value for the specified attribute.
	 *
	 * @param attr the attribute
	 * @return the first attribute value. {@code null}, if no values available
	 * @since 3.7
	 */
	public String getFirstAttributeValue(String attr) {
		AttributeValues list = attributes.get(attr);
		if (list != null)
			return list.getFirst();
		else
			return null;
	}

	/**
	 * Copy provided resource attributes.
	 * 
	 * Note: if the provided resource is changing during this copy, the outcome
	 * is undefined. {@link Resource}s, which are intended to change their
	 * {@link ResourceAttributes} should therefore clone the current
	 * {@link ResourceAttributes}, modify the clone and then replace the
	 * original {@link ResourceAttributes} by the modified
	 * {@link ResourceAttributes} one.
	 * 
	 * @param other other resource attributes
	 * @since 3.3
	 */
	public void copy(ResourceAttributes other) {
		if (this == other) {
			return;
		}
		attributes.clear();
		for (String attrName : other.getAttributeKeySet()) {
			AttributeValues attributeValues = other.attributes.get(attrName);
			if (attributeValues != null) {
				attributes.put(attrName, attributeValues.clone());
			}
		}
	}

	/**
	 * Find the attribute values for the specified attribute.
	 *
	 * If not available, create new attribute values using the provided
	 * attribute name.
	 * 
	 * @param attr the attribute
	 * @return the attribute values
	 */
	private AttributeValues findAttributeValues(String attr) {
		AttributeValues list = attributes.get(attr);
		if (list == null) {
			list = new AttributeValues();
			AttributeValues prev = attributes.putIfAbsent(attr, list);
			if (prev != null) {
				return prev;
			}
		}
		return list;
	}

	/**
	 * The class AttributeValues contains a list of all values for a specific
	 * attribute.
	 * 
	 * @since 3.7 uses a {@link CopyOnWriteArrayList} in order to have a defined
	 *        behavior for {@link #getAll()}.
	 */
	private final static class AttributeValues {

		/** The list. */
		private final List<String> list = new CopyOnWriteArrayList<>();

		/**
		 * Gets all values.
		 *
		 * @return all values (unmodifiable list)
		 * @since 3.7 returns unmodifiable list
		 */
		private List<String> getAll() {
			return Collections.unmodifiableList(list);
		}

		/**
		 * Adds the specified value to the list.
		 *
		 * @param value the value
		 */
		private synchronized void add(String value) {
			list.add(value);
		}

		/**
		 * Adds the specified values to the list.
		 *
		 * @param values the values
		 */
		private synchronized void addAll(List<String> values) {
			list.addAll(values);
		}

		/**
		 * Gets the first value of the list.
		 *
		 * @return the first value
		 */
		private synchronized String getFirst() {
			if (list.isEmpty())
				return "";
			else
				return list.get(0);
		}

		/**
		 * Adds the specified value but removes all others.
		 *
		 * @param value the value
		 */
		private synchronized void setOnly(String value) {
			list.clear();
			if (value != null)
				list.add(value);
		}

		/**
		 * Clone values.
		 * 
		 * @return cloned values
		 * @since 3.7
		 */
		protected synchronized AttributeValues clone() {
			AttributeValues values = new AttributeValues();
			values.addAll(getAll());
			return values;
		}
	}
}
