/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
package org.eclipse.californium.examples;

import java.net.InetSocketAddress;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoAPEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaults;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;

public class SecureServer {

    // allows configuration via Californium.properties
    public static final int DTLS_PORT = NetworkConfig.getStandard().getInt(NetworkConfigDefaults.DEFAULT_COAP_PORT);

    static {
        ScandiumLogger.initialize();
        ScandiumLogger.setLevel(Level.FINER);
    }

    public static void main(String[] args) {

        CoapServer server = new CoapServer();
        server.add(new CoapResource("secure") {
            @Override
            public void handleGET(CoapExchange exchange) {
                exchange.respond(ResponseCode.CONTENT, "hello security");
            }
        });
        // ETSI Plugtest environment
        // server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("::1", DTLS_PORT)),
        // NetworkConfig.getStandard()));
        // server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("127.0.0.1", DTLS_PORT)),
        // NetworkConfig.getStandard()));
        // server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("2a01:c911:0:2010::10",
        // DTLS_PORT)), NetworkConfig.getStandard()));
        // server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("10.200.1.2", DTLS_PORT)),
        // NetworkConfig.getStandard()));
        InMemoryPskStore pskStore = new InMemoryPskStore();
        pskStore.setKey("My_Identity", "TheSecretKey".getBytes());

        DTLSConnector connector = new DTLSConnector(new InetSocketAddress(DTLS_PORT), null);
        connector.getConfig().setPskStore(pskStore);
        server.addEndpoint(new CoAPEndpoint(connector, NetworkConfig.getStandard()));
        server.start();

        // add special interceptor for message traces
        for (Endpoint ep : server.getEndpoints()) {
            ep.addInterceptor(new MessageTracer());
        }

        System.out.println("Secure CoAP server powered by Scandium (Sc) is listening on port " + DTLS_PORT);
    }

}
