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
 *    Vikram            - added Dtls server
 ******************************************************************************/
package org.eclipse.californium.examples;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

import java.net.InetSocketAddress;

public class ServerService extends Service {

    CoapServer server;
    private static final int DTLS_PORT = 5684;
    private static final int CoAP_PORT = 5683;
    public static final String SERVER_NAME = "server";

    @Override
    public void onCreate() {
        this.server = new CoapServer(CoAP_PORT);
        DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
        dtlsConfig.setAddress(new InetSocketAddress(DTLS_PORT));
        ConfigureDtls.loadCredentials(dtlsConfig, SERVER_NAME);
        DTLSConnector connector = new DTLSConnector(dtlsConfig.build());
        CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
        builder.setConnector(connector);
        server.addEndpoint(builder.build());
        server.add(new HelloWorldResource());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        server.start();

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        server.destroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        // TODO: Return the communication channel to the service.
        throw new UnsupportedOperationException("Not yet implemented");
    }

    class HelloWorldResource extends CoapResource {

        public HelloWorldResource() {

            // set resource identifier
            super("hello");

            // set display name
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {

            // respond to the request
            exchange.respond("Hello Android!");
        }
    }
}
