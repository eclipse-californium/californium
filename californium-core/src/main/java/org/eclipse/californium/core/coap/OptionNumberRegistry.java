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

import java.util.Map;
import java.util.TreeMap;

/**
 * This class describes the CoAP Option Number Registry as defined in RFC 7252,
 * Section 12.2 and other CoAP extensions.
 */
public enum OptionNumberRegistry {
    IF_MATCH(       1, true,  false, optionFormats.OPAQUE,  "If-Match"), 
    URI_HOST(       3, false, true,  optionFormats.STRING,  "Uri-Host"), 
    ETAG(           4, true,  false, optionFormats.OPAQUE,  "ETag"), 
    IF_NONE_MATCH(  5, false, false, optionFormats.INTEGER, "If-None-Match"), 
    OBSERVE(        6, false, false, optionFormats.INTEGER, "Observe"), 
    URI_PORT(       7, false, true,  optionFormats.INTEGER, "Uri-Port"), 
    LOCATION_PATH(  8, true,  false, optionFormats.STRING,  "Location-Path"), 
    URI_PATH(      11, true,  true,  optionFormats.STRING,  "Uri-Path"), 
    CONTENT_FORMAT(12, false, false, optionFormats.INTEGER, "Content-Format"), 
    MAX_AGE(       14, false, false, optionFormats.INTEGER, "Max-Age"), 
    URI_QUERY(     15, true,  true,  optionFormats.STRING,  "Uri-Query"),
    ACCEPT(        17, false, false, optionFormats.INTEGER, "Accept"),
    LOCATION_QUERY(20, true,  false, optionFormats.STRING,  "Location-Query"),
    BLOCK2(        23, false, false, optionFormats.INTEGER, "Block2"),
    BLOCK1(        27, false, false, optionFormats.INTEGER, "Block1"),
    SIZE2(         28, false, false, optionFormats.INTEGER, "Size2"),
    PROXY_URI(     35, false, false, optionFormats.STRING,  "Proxy-Uri"),
    PROXY_SCHEME(  39, false, false, optionFormats.STRING,  "Proxy-Scheme"),
    SIZE1(         60, false, false, optionFormats.INTEGER, "Size1"),
    ;

    private static Map<String, OptionNumberRegistry> m_mapByName;
    private static Map<Integer, OptionNumberRegistry> m_mapByNumber;
    
    private int m_protocolValue;
    private boolean m_repeatable;
    private boolean m_uriPart;
    private String m_name;
    private optionFormats m_format;

    OptionNumberRegistry(
            int protocolValue,
            boolean isRepeatable,
            boolean isUriPart,
            optionFormats format,
            String name)
    {
        m_protocolValue = protocolValue;
        m_repeatable = isRepeatable;
        m_uriPart = isUriPart;
        m_name = name;
        m_format = format;
    }

    
     /**
      * Option default values.
      */
    public static class Defaults {

        /** The default Max-Age. */
        public static final long MAX_AGE = 60L;
    }

    /**
     * The format types of CoAP options.
     */
    public static enum optionFormats {
        INTEGER, STRING, OPAQUE, UNKNOWN
    }

    /**
     * Returns the option format based on the option number.
     * 
     * @return The option format corresponding to the option number
     */
    public optionFormats getFormat() {
        return m_format;
    }
    
    /**
     * Gets the protocol value for this {@link OptionNumberRegistry}.
     * @return the protocol value.
     */
    public int getProtocolValue() {
        return m_protocolValue;
    }

    /**
     * Checks whether an option is critical.
     * 
     * @return {@code true} if the option is critical
     */
    public boolean isCritical() {
        return (m_protocolValue & 0x01) != 0;
    }

    /**
     * Checks whether an option is elective.
     * 
     * @return {@code true} if the option is elective
     */
    public boolean isElective() {
        return !isCritical();
    }

    /**
     * Checks whether an option is unsafe.
     * 
     * @return {@code true} if the option is unsafe
     */
    public boolean isUnsafe() {
        return (m_protocolValue & 0x02) != 0;
    }

    /**
     * Checks whether an option is safe.
     * 
     * @return {@code true} if the option is safe
     */
    public boolean isSafe() {
        return !isUnsafe();
    }

    /**
     * Checks whether an option is not a cache-key.
     * 
     * @return {@code true} if the option is not a cache-key
     */
    public boolean isNoCacheKey() {
        /*
         * When an option is not Unsafe, it is not a Cache-Key (NoCacheKey) if
         * and only if bits 3-5 are all set to 1; all other bit combinations
         * mean that it indeed is a Cache-Key
         */
        return (m_protocolValue & 0x1E) == 0x1C;
    }

    /**
     * Checks whether an option is a cache-key.
     * 
     * @param optionNumber
     *            The option number to check
     * @return {@code true} if the option is a cache-key
     */
    public boolean isCacheKey() {
        return !isNoCacheKey();
    }

    /**
     * Checks if this option is repeatable.
     * @return {@code true} if is repeatable.
     */
    public boolean isRepeatable() {
        return m_repeatable;
    }
    
    /**
     * Checks if is single value.
     * 
     * @param optionNumber
     *            the option number
     * @return {@code true} if is single value
     */
    public boolean isSingleValue() {
        return !m_repeatable;
    }

    /**
     * Checks if is uri option.
     * 
     * @return {@code true} if is uri option
     */
    public boolean isUriOption() {
        return m_uriPart;
    }

    /**
     * Returns a string representation of the option number.
     * 
     * @param optionNumber
     *            the option number to describe
     * @return a string describing the option number
     */
    @Override
    public String toString() {
        return m_name;
    }

    public static OptionNumberRegistry parse(String name) {
        if (m_mapByName == null) {
            m_mapByName = new TreeMap<String, OptionNumberRegistry>();
            for (OptionNumberRegistry v: OptionNumberRegistry.values()) {
                m_mapByName.put(v.toString(), v);
            }
        }
        return m_mapByName.get(name);
    }
    
    public static OptionNumberRegistry parse(int protocolValue) {
        if (m_mapByNumber == null) {
            m_mapByNumber = new TreeMap<Integer, OptionNumberRegistry>();
            for (OptionNumberRegistry v: OptionNumberRegistry.values()) {
                m_mapByNumber.put(v.getProtocolValue(), v);
            }
        }
        return m_mapByNumber.get(protocolValue);
    }
}
