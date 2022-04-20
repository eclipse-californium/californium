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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP and encryption support.
 *    Achim Kraus (Bosch Software Innovations GmbH) - split creating connectors into
 *                                                    ClientInitializer.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 *    Rikard Höglund (RISE)                         - OSCORE support     
 ******************************************************************************/
/**
 * 
 */
package org.eclipse.californium.plugtests;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cli.ClientBaseConfig;
import org.eclipse.californium.cli.ClientInitializer;
import org.eclipse.californium.cli.decoder.CborDecoder;
import org.eclipse.californium.cli.decoder.JsonDecoder;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.scandium.config.DtlsConfig;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * The PlugtestClient uses the developer API of Californium to test if the test
 * cases can be implemented successfully. This client does not implement the
 * tests that are meant to check the server functionality (e.g., stop Observe on
 * DELETE).
 * 
 * Use this flag to customize logging output:
 * {@code -Dlogback.configurationFile=./logback.xml}
 */
public class PlugtestClient {
	private static final File CONFIG_FILE = new File("CaliforniumPlugtest3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Plugtest Client";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 64;

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			// adjust defaults for plugtest
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 300, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_COUNT, 4);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_TIME, 30, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 10);
			config.set(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS, 1);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0); // support it, but don't use it
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 10);
		}

	};

	@Command(name = "PlugtestClient", version = "(c) 2014, Institute for Pervasive Computing, ETH Zurich.")
	private static class Config extends ClientBaseConfig {

		@Option(names = "--no-ping", negatable = true, description = "use ping.")
		public boolean ping = true;

		@Option(names = "--no-oscore", negatable = true, description = "use OSCORE.")
		public boolean oscore = true;

	}

	/**
	 * Main entry point.
	 * 
	 * @param args the arguments
	 * @throws IOException an i/o error occurred
	 * @throws ConnectorException an issue specific to the connector occurred
	 */
	public static void main(String[] args) throws ConnectorException, IOException {

		Config clientConfig = new Config();
		clientConfig.configurationHeader = CONFIG_HEADER;
		clientConfig.customConfigurationDefaultsProvider = DEFAULTS;
		clientConfig.configurationFile = CONFIG_FILE;
		ClientInitializer.init(args, clientConfig, false);
		if (clientConfig.helpRequested) {
			System.exit(0);
		}
		if (clientConfig.oscore) {
			HashMapCtxDB db = new HashMapCtxDB();
			initOscore(clientConfig, db);
			OSCoreCoapStackFactory.useAsDefault(db);
		}
		ClientInitializer.registerEndpoint(clientConfig, null);

		if (clientConfig.tcp) {
			clientConfig.ping = false;
		} else if (clientConfig.secure
				&& clientConfig.configuration.get(CoapConfig.RESPONSE_MATCHING) == MatcherMode.PRINCIPAL_IDENTITY) {
			clientConfig.ping = true;
		}

		try {
			EndpointContext context = null;

			if (clientConfig.ping) {
				CoapClient clientPing = new CoapClient(clientConfig.uri);
				System.out.println("===============\nCC31\n---------------");
				if (!clientPing.ping(2000)) {
					System.out.println(clientConfig.uri + " does not respond to ping, exiting...");
					System.exit(-1);
				} else {
					System.out.println(clientConfig.uri + " reponds to ping");
				}
				context = clientPing.getDestinationContext();
				if (context != null) {
					System.out.println(Utils.prettyPrint(context));
				}
			}

			testCC(clientConfig.uri, context);
			testCB(clientConfig.uri, context);
			testCO(clientConfig.uri, context);
			testCL(clientConfig.uri, context);

			if (clientConfig.oscore) {
				testOscore(clientConfig.uri, context);
			}
		} catch (IOException ex) {
			System.err.println("IO-Error: " + ex.getMessage());
		} catch (ConnectorException ex) {
			System.err.println("Error: " + ex.getMessage());
		}
		System.exit(0);
	}

	public static void testCC(String uri, EndpointContext context) throws ConnectorException, IOException {

		// re-usable response object
		CoapResponse response;

		CoapClient client = new CoapClient(uri + "/test");
		client.setDestinationContext(context);

		System.out.println("===============\nCC01+10");
		System.out.println("---------------\nGET /test\n---------------");
		response = client.get();
		context = client.getDestinationContext();
		if (context != null) {
			System.out.println(Utils.prettyPrint(context));
		}
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nCC02");
		System.out.println("---------------\nDELETE /test\n---------------");
		response = client.delete();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nCC03");
		System.out.println("---------------\nPUT /test\n---------------");
		response = client.put("", MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nCC04");
		System.out.println("---------------\nPOST /test\n---------------");
		response = client.post("non-empty", MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.useNONs();

		System.out.println("===============\nCC05");
		System.out.println("---------------\nNON-GET /test\n---------------");
		response = client.get();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nCC06");
		System.out.println("---------------\nNON-DELETE /test\n---------------");
		response = client.delete();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nCC07");
		System.out.println("---------------\nNON-PUT /test\n---------------");
		response = client.put("", MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nCC08");
		System.out.println("---------------\nNON-POST /test\n---------------");
		response = client.post("non-empty", MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/separate");
		client.useCONs();

		System.out.println("===============\nCC09+11");
		System.out.println("---------------\nGET /separate\n---------------");
		response = client.get();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/test");

		System.out.println("===============\nCC12");
		System.out.println("---------------\nGET /test w/o Token\n---------------");
		Request req12 = Request.newGet(); // never re-use a Request object
		req12.setToken(Token.EMPTY);
		response = client.advanced(req12);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/seg1/seg2/seg3");

		System.out.println("===============\nCC13");
		System.out.println("---------------\nGET /seg1/seg2/seg3\n---------------");
		response = client.get();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/query?first=1&second=2");

		System.out.println("===============\nCC14");
		System.out.println("---------------\nGET /query?first=1&second=2\n---------------");
		response = client.get();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/separate");
		client.setTimeout(10000L);
		client.useNONs();

		System.out.println("===============\nCC17");
		System.out.println("---------------\nNON-GET /separate\n---------------");
		response = client.get();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/test");
		client.setTimeout(0L);
		client.useCONs();

		System.out.println("===============\nCC18");
		System.out.println("---------------\nPOST /test for Location-Path\n---------------");
		response = client.post("TD_COAP_CORE_18", MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.getCode() + "-" + response.getOptions().getLocationString());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/location-query");

		System.out.println("===============\nCC19");
		System.out.println("---------------\nGET /location-query\n---------------");
		response = client.post("query", MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.getCode() + "-" + response.getOptions().getLocationString());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/multi-format");

		System.out.println("===============\nCC20");
		System.out.println("---------------\nGET /multi-format text/plain\n---------------");
		response = client.get(MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(
				response.getCode() + "-" + MediaTypeRegistry.toString(response.getOptions().getContentFormat()));
		System.out.println(response.getResponseText());
		System.out.println("---------------\nGET /multi-format application/xml\n---------------");
		response = client.get(MediaTypeRegistry.APPLICATION_XML);
		System.out.println(
				response.getCode() + "-" + MediaTypeRegistry.toString(response.getOptions().getContentFormat()));
		System.out.println(response.getResponseText());
		System.out.println("---------------\nGET /multi-format application/json\n---------------");
		response = client.get(MediaTypeRegistry.APPLICATION_JSON);
		System.out.println(
				response.getCode() + "-" + MediaTypeRegistry.toString(response.getOptions().getContentFormat()));
		System.out.println(response.getResponseText());
		System.out.println(new JsonDecoder().decode(response.getPayload()));
		System.out.println("---------------\nGET /multi-format application/cbor\n---------------");
		response = client.get(MediaTypeRegistry.APPLICATION_CBOR);
		System.out.println(
				response.getCode() + "-" + MediaTypeRegistry.toString(response.getOptions().getContentFormat()));
		System.out.println(StringUtil.byteArray2Hex(response.getPayload()));
		System.out.println(new CborDecoder().decode(response.getPayload()));
		client.setURI(uri + "/validate");
		byte[] etag;

		System.out.println("===============\nCC21");
		System.out.println("---------------\nGET /validate\n---------------");
		response = client.get();
		if (response.getOptions().getETagCount() == 1) {
			etag = response.getOptions().getETags().get(0);
			System.out.println(response.getCode() + " - ETag [" + Utils.toHexString(etag) + "]");
			System.out.println(response.getResponseText());

			System.out.println("---------------\nGET /validate with ETag\n---------------");
			response = client.validate(etag);
			etag = response.getOptions().getETags().get(0);
			System.out.println(response.getCode() + " - ETag [" + Utils.toHexString(etag) + "]");
			System.out.println(response.getResponseText());

			System.out.println("---------------\nPUT /validate stimulus\n---------------");
			CoapClient clientStimulus = new CoapClient(uri + "/validate");
			clientStimulus.setDestinationContext(context);
			response = clientStimulus.put("CC21 at " + new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()),
					MediaTypeRegistry.TEXT_PLAIN);
			System.out.println(response.getCode());

			System.out.println("---------------\nGET /validate with ETag\n---------------");
			response = client.validate(etag);
			etag = response.getOptions().getETags().get(0);
			System.out.println(response.getCode() + " - ETag [" + Utils.toHexString(etag) + "]");
			System.out.println(response.getResponseText());

		} else {
			System.out.println("Error - no ETag");
		}

		System.out.println("===============\nCC22");
		System.out.println("---------------\nGET /validate with If-Match\n---------------");
		response = client.get();
		if (response.getOptions().getETagCount() == 1) {
			etag = response.getOptions().getETags().get(0);
			System.out.println(response.getCode() + " - ETag [" + Utils.toHexString(etag) + "]");
			System.out.println(response.getResponseText());

			System.out.println(
					"---------------\nPUT /validate If-Match [" + Utils.toHexString(etag) + "]\n---------------");
			response = client.putIfMatch("CC22 at " + new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()),
					MediaTypeRegistry.TEXT_PLAIN, etag);
			System.out.println(response.getCode());

			System.out.println("---------------\nGET /validate\n---------------");
			response = client.get();
			etag = response.getOptions().getETags().get(0);
			System.out.println(response.getCode() + " - ETag [" + Utils.toHexString(etag) + "]");
			System.out.println(response.getResponseText());

			System.out.println("---------------\nPUT /validate stimulus\n---------------");
			CoapClient clientStimulus = new CoapClient(uri + "/validate");
			clientStimulus.setDestinationContext(context);
			response = clientStimulus.put("CC22 at " + new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()),
					MediaTypeRegistry.TEXT_PLAIN);
			System.out.println(response.getCode());

			System.out.println(
					"---------------\nPUT /validate If-Match [" + Utils.toHexString(etag) + "]\n---------------");
			response = client.putIfMatch("CC22 at " + new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()),
					MediaTypeRegistry.TEXT_PLAIN, etag);
			System.out.println(response.getCode());

		} else {
			System.out.println("Error - no ETag");
		}

		client.setURI(uri + "/create1");

		System.out.println("===============\nCC23");
		System.out.println("---------------\nPUT /create1 with If-None-Match\n---------------");
		response = client.putIfNoneMatch("CC23 at " + new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()),
				MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.getCode());
		System.out.println("---------------\nPUT /create1 with If-None-Match\n---------------");
		response = client.putIfNoneMatch("CC23 at " + new SimpleDateFormat("HH:mm:ss.SSS").format(new Date()),
				MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.getCode());

		client.shutdown();
	}

	public static void testCB(String uri, EndpointContext context) throws ConnectorException, IOException {

		CoapClient client = new CoapClient(uri + "/large");
		client.setDestinationContext(context);
		CoapResponse response;

		client.useEarlyNegotiation(64);

		System.out.println("===============\nCB01");
		System.out.println("---------------\nGET /large\n---------------");
		response = client.get();
		context = client.getDestinationContext();
		if (context != null) {
			System.out.println(Utils.prettyPrint(context));
		}
		System.out.println(response.getCode());
		System.out.println(response.getResponseText());

		client.useLateNegotiation();

		System.out.println("===============\nCB02");
		System.out.println("---------------\nGET /large\n---------------");
		response = client.get();
		System.out.println(response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/large-update");

		System.out.println("===============\nCB03");
		System.out.println("---------------\nPUT /large-update\n---------------");
		response = client.put(getLargeRequestPayload(), MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/large-create");

		System.out.println("===============\nCB04");
		System.out.println("---------------\nPOST /large-create\n---------------");
		response = client.post(getLargeRequestPayload(), MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.getCode() + " - " + response.getOptions().getLocationString());
		System.out.println(response.getResponseText());

		client.setURI(uri + response.getOptions().getLocationString());

		System.out.println("---------------\nGET " + response.getOptions().getLocationString() + "\n---------------");
		response = client.get();
		System.out.println(response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/large-post");

		System.out.println("===============\nCB05");
		System.out.println("---------------\nPOST /large-post\n---------------");
		response = client.post(getLargeRequestPayload(), MediaTypeRegistry.TEXT_PLAIN);
		System.out.println(response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/large");
		client.useEarlyNegotiation(16);

		System.out.println("===============\nCB06");
		System.out.println("---------------\nGET /large\n---------------");
		response = client.get();
		System.out.println(response.getCode());
		System.out.println(response.getResponseText());

		client.shutdown();
	}

	public static void testCO(String uri, EndpointContext context) throws ConnectorException, IOException {

		CoapClient client = new CoapClient(uri + "/obs");
		client.setDestinationContext(context);

		System.out.println("===============\nCO01+06");
		System.out.println("---------------\nGET /obs with Observe");
		CoapObserveRelation relation1 = client.observe(new CoapHandler() {

			@Override
			public void onLoad(CoapResponse response) {
				String content = response.getResponseText();
				System.out.println("-CO01----------");
				System.out.println(content);
			}

			@Override
			public void onError() {
				System.err.println("-Failed--------");
			}
		});
		try {
			Thread.sleep(6 * 1000);
		} catch (InterruptedException e) {
		}
		System.out.println("---------------\nCancel Observe");
		relation1.reactiveCancel();
		try {
			Thread.sleep(6 * 1000);
		} catch (InterruptedException e) {
		}

		client.setURI(uri + "/obs-non").useNONs();

		System.out.println("===============\nCO02+06");
		System.out.println("---------------\nNON-GET /obs-non with Observe");
		CoapObserveRelation relation2 = client.observe(new CoapHandler() {

			@Override
			public void onLoad(CoapResponse response) {
				String content = response.getResponseText();
				System.out.println("-CO02----------");
				System.out.println(content);
			}

			@Override
			public void onError() {
				System.err.println("-Failed--------");
			}
		});
		try {
			Thread.sleep(6 * 1000);
		} catch (InterruptedException e) {
		}
		System.out.println("---------------\nCancel Observe");
		relation2.proactiveCancel();
		try {
			Thread.sleep(2 * 1000);
		} catch (InterruptedException e) {
		}

		client.setURI(uri + "/obs").useCONs();

		System.out.println("===============\nCO04");
		System.out.println("---------------\nGET /obs with Observe");
		CoapObserveRelation relation4 = client.observeAndWait(new CoapHandler() {

			@Override
			public void onLoad(CoapResponse response) {
				String content = response.getResponseText();
				System.out.println("-CO04----------");
				System.out.println(content);
			}

			@Override
			public void onError() {
				System.err.println("-Failed--------");
			}
		});
		long timeout = relation4.getCurrent().getOptions().getMaxAge();
		try {
			Thread.sleep(6 * 1000);
		} catch (InterruptedException e) {
		}
		System.out.println("---------------\nReboot Server");
		CoapClient clientStimulus = new CoapClient(uri + "/obs-reset");
		clientStimulus.setDestinationContext(context);
		clientStimulus.post("sesame", MediaTypeRegistry.TEXT_PLAIN);
		try {
			Thread.sleep((timeout + 6) * 1000);
		} catch (InterruptedException e) {
		}
		relation4.proactiveCancel();
		try {
			Thread.sleep(2 * 1000);
		} catch (InterruptedException e) {
		}

		client.setURI(uri + "/obs-large");

		System.out.println("===============\nCO13");
		System.out.println("---------------\nGET /obs-large with Observe");
		CoapObserveRelation relation13 = client.observe(new CoapHandler() {

			@Override
			public void onLoad(CoapResponse response) {
				String content = response.getResponseText();
				System.out.println("-CO13----------");
				System.out.println(content);
			}

			@Override
			public void onError() {
				System.err.println("-Failed--------");
			}
		});
		try {
			Thread.sleep(11 * 1000);
		} catch (InterruptedException e) {
		}
		System.out.println("---------------\nCancel Observe");
		relation13.proactiveCancel();
		try {
			Thread.sleep(6 * 1000);
		} catch (InterruptedException e) {
		}

		client.setURI(uri + "/obs-pumping");

		System.out.println("===============\nCO14");
		System.out.println("---------------\nGET /obs-pumping with Observe");
		CoapObserveRelation relation14 = client.observe(new CoapHandler() {

			@Override
			public void onLoad(CoapResponse response) {
				String content = response.getResponseText();
				System.out.println("-CO14----------");
				System.out.println(content);
			}

			@Override
			public void onError() {
				System.err.println("-Failed--------");
			}
		});
		try {
			Thread.sleep(21 * 1000);
		} catch (InterruptedException e) {
		}
		System.out.println("---------------\nCancel Observe");
		relation14.proactiveCancel();
		try {
			Thread.sleep(6 * 1000);
		} catch (InterruptedException e) {
		}

		client.shutdown();
	}

	public static void testCL(String uri, EndpointContext context) throws ConnectorException, IOException {

		CoapClient client = new CoapClient(uri);
		client.setDestinationContext(context);
		Set<WebLink> links;

		System.out.println("===============\nCL01");
		System.out.println("---------------\nGET /.well-known/core\n---------------");
		links = client.discover();
		context = client.getDestinationContext();
		if (context != null) {
			System.out.println(Utils.prettyPrint(context));
		}
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL02");
		System.out.println("---------------\nGET /.well-known/core?rt=Type1\n---------------");
		links = client.discover("rt=Type1");
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL03");
		System.out.println("---------------\nGET /.well-known/core?rt=*\n---------------");
		links = client.discover("rt=*");
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL04");
		System.out.println("---------------\nGET /.well-known/core?rt=Type2\n---------------");
		links = client.discover("rt=Type2");
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL05");
		System.out.println("---------------\nGET /.well-known/core?if=If*\n---------------");
		links = client.discover("if=If*");
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL06");
		System.out.println("---------------\nGET /.well-known/core?sz=*\n---------------");
		links = client.discover("sz=*");
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL07");
		System.out.println("---------------\nGET /.well-known/core?href=/link1\n---------------");
		links = client.discover("href=/link1");
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL08");
		System.out.println("---------------\nGET /.well-known/core?href=/link*\n---------------");
		links = client.discover("href=/link*");
		for (WebLink link : links) {
			System.out.println(link);
		}

		System.out.println("===============\nCL09");
		System.out.println("---------------\nGET /.well-known/core?ct=40\n---------------");
		links = client.discover("ct=40");
		System.out.println("Found " + links.size() + " resource(s)");
		for (WebLink link : links) {
			client.setURI(uri + link.getURI());
			System.out.println("---------------\nGET " + link.getURI() + " with ct=40\n---------------");
			String linkResponse = client.get(MediaTypeRegistry.APPLICATION_LINK_FORMAT).getResponseText();
			Set<WebLink> subLinks = LinkFormat.parse(linkResponse);
			System.out.println("Found " + subLinks.size() + " resource(s)");
			for (WebLink subLink : subLinks) {
				client.setURI(uri + subLink.getURI());
				System.out.println("---------------\nGET " + subLink.getURI() + "\n---------------");
				CoapResponse response = client.get();
				System.out.println(response.advanced().getType() + "-" + response.getCode());
				System.out.println(response.getResponseText());
			}
		}

		client.shutdown();
	}

	/**
	 * Test communication using OSCORE towards a resource only accessible if
	 * OSCORE is used. Similar to the requests in testCC.
	 * 
	 * @param uri URI of the OSCORE resource
	 * @param context endpoint context to use
	 * @throws ConnectorException on connection failure
	 * @throws IOException on IO failure
	 */
	public static void testOscore(String uri, EndpointContext context) throws ConnectorException, IOException {

		// re-usable response object
		CoapResponse response;

		CoapClient client = new CoapClient(uri + "/oscore");
		client.setDestinationContext(context);

		System.out.println("\nWill run OSCORE Appendix B.2 context rederivaton followed by 4 OSCORE requests.");

		System.out.println("===============\nOSCORE 01");
		System.out.println("---------------\nGET /oscore\n---------------");
		Request r = Request.newGet();
		r.getOptions().setOscore(Bytes.EMPTY);
		response = client.advanced(r);
		context = client.getDestinationContext();
		if (context != null) {
			System.out.println(Utils.prettyPrint(context));
		}
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nOSCORE 02");
		System.out.println("---------------\nDELETE /oscore\n---------------");
		r = Request.newDelete();
		r.getOptions().setOscore(Bytes.EMPTY);
		response = client.advanced(r);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nOSCORE 03");
		System.out.println("---------------\nPUT /oscore\n---------------");
		r = Request.newPut();
		r.setPayload("");
		r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		r.getOptions().setOscore(Bytes.EMPTY);
		response = client.advanced(r);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		System.out.println("===============\nOSCORE 04");
		System.out.println("---------------\nPOST /oscore\n---------------");
		r = Request.newPut();
		r.setPayload("non-empty");
		r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		r.getOptions().setOscore(Bytes.EMPTY);
		response = client.advanced(r);
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());
		
	}

	/**
	 * Initializes an OSCORE context for the client built on a pre-defined
	 * configuration and adds it to the OSCORE context database. The created
	 * context will support and by default always use the Appendix B.2 context
	 * rederivation procedure. This is to avoid message replay errors that would
	 * otherwise arise for clients.
	 * 
	 * @param config configuration with the URI of the OSCORE resource at the server
	 * @param db the OSCORE context database
	 */
	public static void initOscore(ClientBaseConfig config, HashMapCtxDB db) {
		AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
		AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

		byte[] master_secret = StringUtil.hex2ByteArray("0102030405060708090a0b0c0d0e0f10");
		byte[] master_salt = StringUtil.hex2ByteArray("9e7ca92223786340");
		byte[] sid = StringUtil.hex2ByteArray("01");
		byte[] rid = StringUtil.hex2ByteArray("02");
		byte[] id_context = StringUtil.hex2ByteArray("37cbf3210017a2d3");
		int MAX_UNFRAGMENTED_SIZE = config.configuration.get(CoapConfig.MAX_RESOURCE_BODY_SIZE);

		OSCoreCtx ctx = null;
		try {
			ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, id_context,
					MAX_UNFRAGMENTED_SIZE);
			ctx.setContextRederivationEnabled(true);
			ctx.setContextRederivationPhase(PHASE.CLIENT_INITIATE);
			db.addContext(config.uri, ctx);
		} catch (OSException e) {
			e.printStackTrace();
		}
	}

	public static String getLargeRequestPayload() {
		return new StringBuilder().append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 1 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 2 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 3 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 4 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n")
				.append("/-------------------------------------------------------------\\\n")
				.append("|                  Request BLOCK NO. 5 OF 5                   |\n")
				.append("|               [each line contains 64 bytes]                 |\n")
				.append("\\-------------------------------------------------------------/\n").toString();
	}
}
