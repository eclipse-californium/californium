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
 ******************************************************************************/
package org.eclipse.californium.examples;

import android.content.Intent;
import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import org.eclipse.californium.examples.R;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_sandbox) {
            ((EditText)findViewById(R.id.editUri)).setText(R.string.uri_sandbox);
            return true;
        } else if (id == R.id.action_local) {
            ((EditText)findViewById(R.id.editUri)).setText(R.string.uri_local);
            return true;
        } else if (id == R.id.action_start) {
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

    public void clickGet(View view) {
        String uri = ((EditText)findViewById(R.id.editUri)).getText().toString();
        new CoapGetTask().execute(uri);
    }

    class CoapGetTask extends AsyncTask<String, String, CoapResponse> {

        protected void onPreExecute() {
            // reset text fields
            ((TextView)findViewById(R.id.textCode)).setText("");
            ((TextView)findViewById(R.id.textCodeName)).setText("Loading...");
            ((TextView)findViewById(R.id.textRtt)).setText("");
            ((TextView)findViewById(R.id.textContent)).setText("");
        }

        protected CoapResponse doInBackground(String... args) {
            CoapClient client = new CoapClient(args[0]);
            return client.get();
        }

        protected void onPostExecute(CoapResponse response) {
            if (response!=null) {
                ((TextView)findViewById(R.id.textCode)).setText(response.getCode().toString());
                ((TextView)findViewById(R.id.textCodeName)).setText(response.getCode().name());
                ((TextView)findViewById(R.id.textRtt)).setText(response.advanced().getRTT()+" ms");
                ((TextView)findViewById(R.id.textContent)).setText(response.getResponseText());
            } else {
                ((TextView)findViewById(R.id.textCodeName)).setText("No response");
            }
        }
    }
}
