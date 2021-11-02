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
 *    Vikram - added dtls client
 ******************************************************************************/
package org.eclipse.californium.examples;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MainActivity extends Activity {

    public static final String CLIENT_NAME = "client";

    private static final Executor executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initCoapEndpoint();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        MenuItem item = menu.findItem(R.id.action_start);
        if (item != null) {
            item.setChecked(ServerService.isRunning());
        }
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        //noinspection SimplifiableIfStatement
        switch (id) {
            case R.id.action_sandbox:
                ((EditText) findViewById(R.id.editUri)).setText(R.string.uri_sandbox);
                return true;
            case R.id.action_sandbox_dtls:
                ((EditText) findViewById(R.id.editUri)).setText(R.string.uri_dtls_sandbox);
                return true;
            case R.id.action_local:
                ((EditText) findViewById(R.id.editUri)).setText(R.string.uri_local);
                return true;
            case R.id.action_local_dtls:
                ((EditText) findViewById(R.id.editUri)).setText(R.string.uri_dtls_local);
                return true;
            case R.id.action_start:
                if (!item.isChecked()) {
                    startService(new Intent(this, ServerService.class));
                    item.setChecked(true);
                } else {
                    stopService(new Intent(this, ServerService.class));
                    item.setChecked(false);
                }
                return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private final Handler handler = new Handler(Looper.getMainLooper());

    public void clickGet(View view) {
        final String uri = ((EditText) findViewById(R.id.editUri)).getText().toString();

        // reset text fields
        ((TextView) findViewById(R.id.textCode)).setText("");
        ((TextView) findViewById(R.id.textCodeName)).setText("Loading...");
        ((TextView) findViewById(R.id.textRtt)).setText("");
        ((TextView) findViewById(R.id.textContent)).setText("");

        executor.execute(new Runnable() {
            @Override
            public void run() {
                CoapResponse response;
                try {
                    CoapClient client = new CoapClient(uri);
                    response = client.get();
                } catch (Exception ex) {
                    Log.e("coap", ex.getMessage(), ex);
                    response = null;
                }

                final CoapResponse finalResponse = response;
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (finalResponse != null) {
                            ((TextView) findViewById(R.id.textCode)).setText(finalResponse.getCode().toString());
                            ((TextView) findViewById(R.id.textCodeName)).setText(finalResponse.getCode().name());
                            Long rtt = finalResponse.advanced().getApplicationRttNanos();
                            if (rtt != null) {
                                ((TextView) findViewById(R.id.textRtt)).setText(TimeUnit.NANOSECONDS.toMillis(rtt) + " ms");
                            }
                            ((TextView) findViewById(R.id.textContent)).setText(finalResponse.getResponseText());
                        } else {
                            ((TextView) findViewById(R.id.textCodeName)).setText("No response");
                        }
                    }
                });
            }
        });
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopService(new Intent(this, ServerService.class));
    }

    /**
     * method initCoapEndpoint.
     * This method is used to setup EndpointpointManager with both plain
     * and dtls connector.
     */
    private void initCoapEndpoint() {
        CoapConfig.register();
        UdpConfig.register();
        DtlsConfig.register();
        Configuration config = Configuration.createStandardWithoutFile();
        // setup coap EndpointManager to dtls connector
        DtlsConnectorConfig.Builder dtlsConfig = DtlsConnectorConfig.builder(config);
        dtlsConfig.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
        dtlsConfig.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
        ConfigureDtls.loadCredentials(dtlsConfig, CLIENT_NAME);
        DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig.build());

        CoapEndpoint.Builder dtlsEndpointBuilder = new CoapEndpoint.Builder();
        dtlsEndpointBuilder.setConfiguration(config);
        dtlsEndpointBuilder.setConnector(dtlsConnector);
        EndpointManager.getEndpointManager().setDefaultEndpoint(dtlsEndpointBuilder.build());
        // setup coap EndpointManager to udp connector
        CoapEndpoint.Builder udpEndpointBuilder = new CoapEndpoint.Builder();
        UDPConnector udpConnector = new UDPConnector(null, config);
        udpEndpointBuilder.setConfiguration(config);
        udpEndpointBuilder.setConnector(udpConnector);
        EndpointManager.getEndpointManager().setDefaultEndpoint(udpEndpointBuilder.build());
    }
}
