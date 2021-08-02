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
 *    Vikram            - added Dtls server
 ******************************************************************************/
package org.eclipse.californium.examples;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.MyIpResource;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Local server service.
 * <p>
 * Offers coap and coaps server endpoint.
 * Supports also multicast for coap, but depends on Android implementation!
 */
public class ServerService extends Service {

    public static final String SERVER_NAME = "server";

    private static final Executor executor = Executors.newSingleThreadExecutor();
    private static final int DTLS_PORT = 5684;
    private static final int CoAP_PORT = 5683;

    private static volatile boolean running;

    private CoapServer server;
    private boolean stop;

    public static boolean isRunning() {
        return running;
    }

    @Override
    public void onCreate() {
        Log.i("coap", "onCreate service");
        running = true;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i("coap", "onStartCommand service");
        executor.execute(new Runnable() {
            @Override
            public void run() {
                Configuration config = Configuration.createStandardWithoutFile();
                CoapServer server = new CoapServer(config);
                NetworkInterface multicast = NetworkInterfacesUtil.getMulticastInterface();
                if (multicast == null) {
                    setupUdp(server, config);
                } else {
                    setupUdpIpv4(server, config);
                    setupUdpIpv6(server, config);
                }
                setupDtls(server, config);
                server.add(new HelloWorldResource());
                server.add(new MyIpResource(MyIpResource.RESOURCE_NAME, true));
                startServer(server);
            }
        });

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.i("coap", "onDestroy service");
        stopServer();
        running = false;
    }

    @Override
    public IBinder onBind(Intent intent) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    private synchronized void startServer(CoapServer server) {
        if (!stop) {
            server.start();
            this.server = server;
        }
    }

    private synchronized void stopServer() {
        stop = true;
        final CoapServer coapServer = this.server;
        if (coapServer != null) {
            this.server = null;
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    coapServer.destroy();
                }
            });
        }
    }

    private void setupUdp(CoapServer server, Configuration config) {
        UDPConnector connector = new UDPConnector(new InetSocketAddress(CoAP_PORT), config);
        setupUdp(server, config, connector);
    }

    private void setupUdpIpv4(CoapServer server, Configuration config) {
        NetworkInterface multicast = NetworkInterfacesUtil.getMulticastInterface();
        Inet4Address address4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();

        // listen on the same port requires to enable address reuse
        UDPConnector connector = new UDPConnector(new InetSocketAddress(address4, CoAP_PORT), config);
        connector.setReuseAddress(true);

        UdpMulticastConnector.Builder builder = new UdpMulticastConnector.Builder();
        builder.setLocalAddress(CoAP.MULTICAST_IPV4, CoAP_PORT);
        builder.setMulticastReceiver(true);
        builder.addMulticastGroup(CoAP.MULTICAST_IPV4, multicast);
        builder.setConfiguration(config);
        UdpMulticastConnector multicastConnector = builder.build();
        connector.addMulticastReceiver(multicastConnector);
        Log.i("coap", "multicast receiver " + CoAP.MULTICAST_IPV4 +
                " started on " + address4);
        setupUdp(server, config, connector);
    }

    private void setupUdpIpv6(CoapServer server, Configuration config) {
        NetworkInterface multicast = NetworkInterfacesUtil.getMulticastInterface();
        Inet6Address address6 = NetworkInterfacesUtil.getMulticastInterfaceIpv6();

        // listen on the same port requires to enable address reuse
        UDPConnector connector = new UDPConnector(new InetSocketAddress(address6, CoAP_PORT), config);
        connector.setReuseAddress(true);

        UdpMulticastConnector.Builder builder = new UdpMulticastConnector.Builder();
        builder.setLocalAddress(CoAP.MULTICAST_IPV6_SITELOCAL, CoAP_PORT);
        builder.setMulticastReceiver(true);
        builder.addMulticastGroup(CoAP.MULTICAST_IPV6_SITELOCAL, multicast);
        builder.setConfiguration(config);
        UdpMulticastConnector multicastConnector = builder.build();
        connector.addMulticastReceiver(multicastConnector);
        Log.i("coap", "multicast receiver " + CoAP.MULTICAST_IPV6_SITELOCAL +
                " started on " + address6);

        setupUdp(server, config, connector);
    }

    private void setupUdp(CoapServer server, Configuration config, UDPConnector connector) {
        CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
        builder.setConfiguration(config);
        builder.setConnector(connector);
        server.addEndpoint(builder.build());
    }

    private void setupDtls(CoapServer server, Configuration config) {
        DtlsConnectorConfig.Builder dtlsConfig = DtlsConnectorConfig.builder(config);
        dtlsConfig.setAddress(new InetSocketAddress(DTLS_PORT));
        ConfigureDtls.loadCredentials(dtlsConfig, SERVER_NAME);
        DTLSConnector connector = new DTLSConnector(dtlsConfig.build());
        CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
        builder.setConfiguration(config);
        builder.setConnector(connector);
        server.addEndpoint(builder.build());
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
