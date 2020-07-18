/*******************************************************************************
 * Copyright (c) 2019 Wajd Tohme, Ahmad Hussaein, Petr Kocián, Matias Carlander-Reuterfelt, 
 *                    Ismail Hilal, Tuna Gersil, and Zainab Alsaadi and others.
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
 *    Wajd Tohme
 *    Ahmad Hussaein
 *    Petr Kocián
 *    Matias Carlander-Reuterfelt
 *    Ismail Hilal
 *    Tuna Gersil
 *    Zainab Alsaadi
 *
 ******************************************************************************/

package org.eclipse.californium.pubsub;

import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

/**
 * The Converter class is a collection of helper functions that make using Californium {@link WebLink}
 * and {@link CoapResponse} easier to use. It also holds various uri linting functions
 * The {@link PubSub} methods return CoapResponse and this helps with using them
 */
public class Converter {

    /*helper functions for  CoapResponse */

    /**
     * creates a Set of WebLinks from the ResponseText of a given CoapResponse
     *
     * @param response CoapResponse
     * @return a Set of WebLink
     */
    public static Set<WebLink> getWebLinks(CoapResponse response){
        return LinkFormat.parse(response.getResponseText());
    }

    /**
     * renders a WebLink for each available topic in the ResponseText of a given CoapResponse
     * This would include the node topics that have child/leaf topics in the returned Set
     *
     * @param response CoapResponse
     * @return a Set of WebLink
     */
    public static Set<WebLink> getAllWebLinks(CoapResponse response) {
        return extractAllWebLinks(getWebLinks(response));
    }

    /*helper functions for Set<WebLink>*/

    /**
     * renders an array out of a given Set of WebLinks
     * useful if you want to access a specific WebLink without casting to an ArrayList
     *
     * @param webLinks Set of  WebLinks
     * @return an array of WebLinks
     */
    public static WebLink[] getArray(Set<WebLink> webLinks) {
        return webLinks.toArray(new WebLink[0]);
    }


    /**
     * renders a WebLink for each available topic in the uris of the WebLinks in the given Set
     * This would include the node topics that have child/leaf topics in the returned Set
     *
     * @param webLinks Set of WebLinks
     * @return a Set of WebLink
     */
    public static Set<WebLink> extractAllWebLinks(Set<WebLink> webLinks) {
        Set<WebLink> topics = new ConcurrentSkipListSet<WebLink>();
        WebLink p;
        for(WebLink w: webLinks) {
            p = w;
            while (!cleanUri(p.getURI()).equals("ps")) {
                topics.add(p);
                p = getParent(p);
            }
        }
        return topics;
    }

    /*helper functions for WebLink*/

    /**
     * renders a WebLink using the given uri and sets its Content type
     *
     * @param uri String
     * @param ct int
     * @return a WebLink
     */
    public static WebLink makeWebLink(String uri, int ct) {
        WebLink webLink = new WebLink('/' + cleanUri(uri));
        setContentType(webLink, ct);
        return webLink;
    }

    /**
     * gets a uri usable with the {@link PubSub} functions
     * it uses {@link #cleanUri(String)} to trim slashes from the
     * beginning and ending of the WebLink's uri
     *
     * @param webLink WebLink
     * @return a String uri
     */
    public static String getUri(WebLink webLink) {
        return cleanUri(webLink.getURI());
    }

    /**
     * returns an int of the ContentType of the given WebLink
     * it parses the ContentType returned to ensure it does not contain extra letters
     * due to issues faced with the testing broker we used
     *
     * @param webLink WebLink
     * @return an int ContentType
     */
    public static int getContentType(WebLink webLink) {

        return Integer.parseInt(webLink.getAttributes().getContentTypes().get(0));
    }

    /**
     * clears then sets the content type of the given weblink
     *
     * @param webLink WebLink
     * @param ct int
     */
    public static void setContentType(WebLink webLink, int ct) {
        webLink.getAttributes().clearContentType();
        webLink.getAttributes().addContentType(ct);
    }

    /**
     * renders the text description of the given content type integer
     * uses {@link MediaTypeRegistry}
     *
     * @param ct int
     * @return String Content Type
     */
    public static String getContentTypeString (int ct) {
        return MediaTypeRegistry.toString(ct);
    }

    /**
     * gets the name of the topic in the given WebLink
     * i.e. it parses the uri of the WebLink and returns the
     * part after the last part
     *
     * @param webLink WebLink
     * @return String name
     */
    public static String getName (WebLink webLink) {
        return getName(webLink.getURI());
    }

    /**
     * renders a WebLink that is the direct parent of the given WebLink
     * extrapolated from the uri of the WebLink.
     * its content type is assumed to be 40
     *
     * @param webLink WebLink
     * @return String parent's uri
     */
    public static String getParentUri (WebLink webLink) {
        return getParentUri(webLink.getURI());
    }

    /**
     * renders a WebLink that is the direct parent of the given WebLink
     * extrapolated from the uri of the WebLink.
     * its content type is assumed to be 40
     *
     * @param webLink WebLink
     * @return WebLink
     */
    public static WebLink getParent (WebLink webLink) {
        return makeWebLink(getParentUri(webLink), 40);
    }

    /**
     * Searches given Set for WebLinks which are children/grand-children of given WebLinks
     *
     * @param webLink WebLink
     * @param webLinks Set of WebLinks
     * @return a Set of WebLinks
     */
    public static Set<WebLink> getSubTopics(WebLink webLink, Set<WebLink> webLinks) {
        return getSubTopics(webLink.getURI(), webLinks);
    }

    /*helper functions for uri*/

    /**
     * parses given uri string for the substring after the last slash
     *
     * @param uri String
     * @return a String name
     */
    public static String getName (String uri) {
        return cleanUri(uri).substring(uri.lastIndexOf('/'));
    }

    /**
     * parses given uri string for the substring before the last slash
     * this is the uri of the direct parent
     *
     * @param uri String
     * @return a String parent uri
     */
    public static String getParentUri (String uri) {
        return cleanUri(uri).substring(0, uri.lastIndexOf('/'));
    }


    /**
     * trims unnecessary slashes at the start and end of given uri string
     * prevents unexpected behaviour
     *
     * @param uri String
     * @return a String uri
     */
    public static String cleanUri (String uri) {
        if(uri.startsWith("/"))
            uri = uri.substring(1);
        if (uri.endsWith("/"))
            uri = uri.substring(0, uri.length()-1);
        return uri;
    }

    /**
     * Searches given Set for WebLinks which have the given uri in their uri
     *
     * @param uri String
     * @param webLinks Set of WebLinks
     * @return a Set of WebLinks
     */
    public static Set<WebLink> getSubTopics(String uri, Set<WebLink> webLinks) {
        uri = cleanUri(uri);
        Set<WebLink> subtopics = new ConcurrentSkipListSet<WebLink>();
        for (WebLink w: webLinks) {
            if(cleanUri(w.getURI()).contains(uri) && !cleanUri(w.getURI()).equals(uri)) {
                subtopics.add(w);
            }
        }
        return subtopics;
    }

}
