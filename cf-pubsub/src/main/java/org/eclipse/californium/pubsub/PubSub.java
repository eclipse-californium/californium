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

import java.io.IOException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.RandomTokenGenerator;
import org.eclipse.californium.core.network.TokenGenerator.Scope;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.exception.ConnectorException;
/**
 * A PubsSub instance can be used to establish a Publish Subscribe client
 * according to the IETF Publish-Subscribe Model for the Constrained Application
 * Protocol (CoAP) RFC draft
 *
 * it allows you to connect to a broker that supports the model so that you:
 * Discover available topics,
 * Create new topics,
 * Publish to available topics,
 * Read from available topics
 * Remove topics,
 * Subscribe to available topics
 *
 * TODO: add support for querying within specific topics
 */
public class PubSub {

    private static final String SCHEME = "coap";
    private String host;
    private int port;
    private long timeout;
    private Configuration config = Configuration.createStandardWithoutFile();

    /**
     * Creates an instance of PubSub with the port set to 5683 (CoAP default port) and timeout 5000 milliseconds
     * @param host ip address of the broker
     */
    public PubSub(String host) {
        this.host = host;
        this.port = 5683;
        this.timeout = 5000;
    }

    /**
     * Creates an instance of PubSub with specified parameters
     * @param host ip address of the broker as a String
     * @param port number of the broker
     * @param timeout time the client waits for response (timeout = 0 -&gt; waits indefinitely)
     */
    public PubSub(String host, int port, long timeout) {
        this.host = host;
        this.port = port;
        this.timeout = timeout;
    }

    /**
     * @return an empty configuration of the PubSub instance
     * which can be changed and then set with the setter function
     */
    public Configuration getConfig() {
        return config;
    }

    /**
     * Sets the configuration of the PubSub instance
     * @param config configuration
     */
    public void setConfig(Configuration config) {
        this.config = config;
    }

    /**
     * @return port number
     */
    public int getPort() {
        return this.port;
    }

    /**
     * Sets port number
     * @param port number of the broker
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * @return host ip as a String
     */
    public String getHost() {
        return this.host;
    }

    /**
     * Sets the host of the PubSub instance
     * @param host ip address of the broker as a String
     */
    public void setHost(String host) {
        this.host = host;
    }

    /**
     * @return timeout - time the client waits for response
     */
    public long getTimeout() {
        return timeout;
    }

    /**
     * Sets the timeout of the PubSub instance
     * Setting this property to 0 will result in methods waiting infinitely
     * @param timeout time the client waits for response
     */
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    /**
     * Sends a synchronous GET request to the broker without a query
     * @return CoapResponse which contains all the topics from the broker
     * @throws ConnectorException if an issue specific to the connector occurred
     * @throws IOException if any other issue (not specific to the connector) occurred
     */
    public CoapResponse discover() throws ConnectorException, IOException {
        return discover("");
    }

    /**
     * Sends a synchronous GET request to the broker with a specified
     * To discover whether the broker supports CoAP PubSub protocol "rt=core.ps" query can be sent
     * @param query String e.g. ct=40
     * @return CoapResponse which contains the topics with the attributes specified by the query
     * @throws ConnectorException if an issue specific to the connector occurred
     * @throws IOException if any other issue (not specific to the connector) occurred
     */
    public CoapResponse discover(String query) throws ConnectorException, IOException {
        Request discover = Request.newGet();
        discover.getOptions().setUriPath(".well-known/core?" + query);

        CoapClient client = new CoapClient(SCHEME, this.getHost(), this.getPort());
        client.setTimeout(this.timeout);

        CoapResponse response = client.advanced(discover);

        return response;
    }

    /**
     * Sends a synchronous POST request to the broker which creates a topic at the broker
     * The topic has to be specified by name, ct and path uri
     * @param name String is the name of the topic
     * @param ct int is the content type of the topic (ct=40 for parent folder, ct=0 for plain text)
     * @param uri String or String[] is the path where the topic should be created (e.g. ps/t1/t2 or {[ps],[t1],[t2]})
     * @return CoapResponse which contains the broker's response to our request i.e. response code,...
     * @throws ConnectorException if an issue specific to the connector occurred
     * @throws IOException if any other issue (not specific to the connector) occurred
     */
    public CoapResponse create(String name, int ct, String... uri) throws ConnectorException, IOException {

        CoapClient client = new CoapClient(SCHEME, this.getHost(), this.getPort(), uri);
        client.setTimeout(this.timeout);

        StringBuilder sb = new StringBuilder().append("<").append(name).append(">;ct=").append(ct);
        String payload = sb.toString();

        Request req = Request.newPost();
        req.setPayload(payload);
        req.getOptions().setContentFormat(ct);

        CoapResponse res = client.advanced(req);

        return res;
    }

    /**
     * Sends a synchronous PUT request to the broker which publishes data to a topic
     * The topic is specified by path uri and ct
     * ct of the topic and the request has to match for data to be published
     * @param payload String is data to be published
     * @param ct int is the content type of the data (has to match ct of the topic)
     * @param uri String or String[] is the path of the topic to which data should be published
     * @return CoapResponse which contains the broker's response to our request i.e. response code,...
     * @throws ConnectorException if an issue specific to the connector occurred
     * @throws IOException if any other issue (not specific to the connector) occurred
     */
    public CoapResponse publish(String payload, int ct, String... uri) throws ConnectorException, IOException {
        CoapClient client = new CoapClient(SCHEME, this.getHost(), this.getPort(), uri);
        client.setTimeout(this.timeout);

        CoapResponse res = client.put(payload, ct);

        return res;
    }

    /**
     * Sends a synchronous GET request to the broker which retrieves data from the topic
     * @param uri String or String[] is the path of the topic from which the data should be read
     * @return CoapResponse which contains the broker's response to our request i.e. content, response code...
     * @throws ConnectorException if an issue specific to the connector occurred
     * @throws IOException if any other issue (not specific to the connector) occurred
     */
    public CoapResponse read(String... uri) throws ConnectorException, IOException {
        CoapClient client = new CoapClient(SCHEME, this.getHost(), this.getPort(), uri);
        client.setTimeout(this.timeout);

        CoapResponse res = client.get();

        return res;
    }

    /**
     * Sends a synchronous DELETE request to the broker which removes the specified topic from the broker
     * If the topic is a parent topic, the broker removes all of its children
     * @param uri String or String[] is the path of the topic which should be removed
     * @return response
     * @throws ConnectorException if an issue specific to the connector occurred
     * @throws IOException if any other issue (not specific to the connector) occurred
     */
    public CoapResponse remove(String... uri) throws ConnectorException, IOException {

        CoapClient client = new CoapClient(SCHEME, this.getHost(), this.getPort(), uri);
        client.setTimeout(this.timeout);
        CoapResponse res = client.delete();

        return res;
    }


    /**
     * The Subscription class can be used to asynchronously subscribe to a given topic uri
     * It can be reused for the same uri while also giving it a new {@link CoapHandler} to handle the
     * asynchronous CoapResponse returned from the broker
     *
     * The uri cannot be changed once set, but the CoapHanlder can be.
     */
    public class Subscription {
        /** the client */
        private CoapClient client;
        /** the observe relation */
        private CoapObserveRelation relation;
        /** the uri of subscribed topic */
        private String[] uri;
        /** the listener for returned CoapResponse */
        private CoapHandler handler;

        /**
         * Constructs a A Subscription instance that allows subscription to a given
         * topic uri string and takes a a CoapHandler to handle the returned response
         *
         * A Constructed Susbcription instance does not automatically subscribe
         * you must call #subscribe().
         *
         * @param handler CoapHandler
         * @param uri String or String[]
         */
        public Subscription(CoapHandler handler, String... uri) {
            this.uri = uri;
            this.handler = handler;
            this.relation = null;
            this.client = null;
        }

        /**
         * Gets the current handler assigned to Subscription instance
         *
         * @return a CoapHandler
         */
        public CoapHandler getHandler() {
            return handler;
        }

        /**
         * Sets a new CoapHandler for the Subscription instance
         *
         * @param handler CoapHandler
         */
        public void setHandler(CoapHandler handler) {
            this.handler = handler;
        }

        /**
         * subscribes to the uri of the Subscription instance and runs
         * the CoapHandler #onLoad when it gets a CoapResponse
         *
         */
        public void subscribe() {

            Request req = new Request(CoAP.Code.GET);

            client = new CoapClient(SCHEME, getHost(), getPort(), uri);
            client.useExecutor();
            client.setTimeout(timeout);

            req.setURI(client.getURI());
            req.setObserve();

            config.set(CoapConfig.TOKEN_SIZE_LIMIT, 4);
            RandomTokenGenerator rand = new RandomTokenGenerator(config);
            Token token = rand.createToken(Scope.SHORT_TERM_CLIENT_LOCAL);
            req.setToken(token);

            relation = client.observe(req, handler);
        }

        /**
         * Unsubscribes from the uri of the Subscription instance
         * and shuts down the client
         */
        public void unsubscribe() {
            if (this.relation != null) {
                relation.proactiveCancel();
                int mid = relation.getCurrent().advanced().getMID();
                while (relation.getCurrent().advanced().getMID() == mid) ;
            }
            if (this.client != null)
                client.shutdown();
        }
    }
}
