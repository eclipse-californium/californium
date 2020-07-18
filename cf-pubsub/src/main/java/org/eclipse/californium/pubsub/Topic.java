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

import org.eclipse.californium.core.WebLink;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Set;


/**
 * The Topic class is a collection of functions that aims to make it easier to handle
 * the results of a discover() function, by making sparse use of the Californium library
 * through turning {@link WebLink} into Topic objects, that then can be stored in a
 * sorted ArrayList. Topic objects have the extracted name, URI and Content Type of the
 * Weblinks which you can then get individually.
 */
public class Topic {

    String name;
    String[] uri;
    int ct;

    /**
     * Creates an instance of Topic given a WebLink from which it
     * extracts the name, URI and Content Type
     *
     * @param wl WebLink
     */
    public Topic(WebLink wl) {
        this.uri = wl.getURI().substring(1).split("(/)");
        this.name = this.uri[this.uri.length - 1];
        String corchete = wl.toString().substring(wl.toString().indexOf('[') + 1);
        try {
            this.ct = Integer.parseInt(corchete.substring(0, 1));
        } catch (NullPointerException | NumberFormatException | ArrayIndexOutOfBoundsException e) {
            this.ct = Integer.parseInt(corchete.substring(0, 0));
        }
    }

    /**
     * Creates an instance of Topic given a name
     *
     * @param uri uri of Topic
     * @param ct  Content Type of Topic
     */
    public Topic(String[] uri, int ct) {
        this.uri = uri;
        this.name = uri[uri.length - 1];
        this.ct = ct;
    }

    /**
     * Creates a sorted ArrayList of object Topic that includes all of
     * the parent Topics out of a given Set of WebLinks
     *
     * @param swl Set of WebLinks
     * @return a sorted ArrayList of Topics
     */
    public static ArrayList<Topic> makeArrayList(Set<WebLink> swl) {
        ArrayList<Topic> at = new ArrayList<>();
        for (WebLink wl : swl) {
            Topic t = new Topic(wl);
            t.getTopics(t, at);
        }
        Collections.sort(at, new TopicComparator());
        return at;
    }

    /**
     * Adds to a given ArrayList of Topics all of the topics and subtopics as individuals
     *
     * @param topic a Topic which you want to get the subtopics and parent Topics from
     * @param at    an already existing ArrayList of Topics where you want all the Topics to be
     */
    public void getTopics(Topic topic, ArrayList<Topic> at) {

        if (topic == null) {
            return;
        }
        boolean flag = false;
        for (Topic x :
                at) {
            if (topic.equals(x)) {
                flag = true;
            }
        }
        if (!flag) {
            at.add(topic);
        }
        getTopics(topic.getParent(), at);
    }

    /**
     * Prints a representation of a Topic
     *
     * @return String representation of Topic
     */
    public String toString() {
        return this.getURIString() + "\t\t\t\t\t\t |ct: " + this.ct;
    }

    /**
     * Returns the parent Topic of the instance Topic as an individual
     *
     * @return the parent topic Topic
     */
    public Topic getParent() {
        String[] ps = new String[this.uri.length - 1];
        for (int i = 0; i < this.uri.length - 1; i++) {
            ps[i] = this.uri[i];
        }
        if (ps.length != 0) {
            Topic parent = new Topic(ps, 40);
            return parent;
        }
        return null;
    }

    /**
     * @return Content Type as an int
     */
    public int getCt() {
        return ct;
    }

    /**
     * @return name of Topic as String
     */
    public String getName() {
        return name;
    }

    /**
     * @return URI of Topic as String[]
     */
    public String[] getURI() {
        return uri;
    }

    /**
     * @return URI of Topic as String
     */
    public String getURIString() {
        StringBuilder sb = new StringBuilder();
        for (String s : this.getURI()) {
            sb.append(s).append("/");
        }
        String p = sb.toString();
        return p = p.substring(0, p.length() - 1);
    }

    /**
     * @param topic that you want to compare
     * @return true if given Topic has same URI as instance Topic
     */
    public boolean equals(Topic topic) {
        return (this.getName().equals(topic.getName()) && this.getURIString().equals(topic.getURIString()));
    }

}

/**
 * The TopicComparator class is used for sorting purposes whenever it is needed
 * to compare and sort Topics. It sorts in terms of alphabetical order and URI length
 */
class TopicComparator implements Comparator<Topic> {
    public int compare(Topic o1, Topic o2) {
        boolean value1 = o1.getURI().length >= (o2.getURI().length);
        if (!value1) {
            int value2 = o1.getURIString().compareTo(o2.getURIString());
            return value2;
        }
        if (value1) {
            return 1;
        } else {
            return 0;
        }
    }
}
