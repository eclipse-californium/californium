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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP and encryption support.
 ******************************************************************************/
/**
 * 
 */
package org.eclipse.californium.plugtests;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.tcp.TcpClientConnector;
import org.eclipse.californium.elements.tcp.TlsClientConnector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * The PlugtestClient uses the developer API of Californium to test if the test
 * cases can be implemented successfully. This client does not implement the
 * tests that are meant to check the server functionality (e.g., stop Observe on
 * DELETE).
 * 
 * Use this flag to customize logging output:
 * -Djava.util.logging.config.file=../run/Californium-logging.properties
 */
public class PlugtestClient {

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final String PSK_IDENTITY_PREFIX = "cali.";
	private static final byte[] PSK_SECRET = ".fornium".getBytes();
	private static final int MAX_RESOURCE_SIZE = 8192;
	
	/**
	 * Main entry point.
	 * 
	 * @param args the arguments
	 */
	public static void main(String[] args) {

		if (args.length == 0) {

			System.out.println("\nCalifornium (Cf) Plugtest Client");
			System.out.println("(c) 2014, Institute for Pervasive Computing, ETH Zurich");
			System.out.println();
			System.out.println("Usage: " + PlugtestClient.class.getSimpleName() + " [-s] [-v] [-r|-x] URI");
			System.out.println("  -s        : Skip the ping in case the remote does not implement it");
			System.out.println("  -v        : verbose. Enable message tracing.");
			System.out.println("  -r        : use raw public certificate. Default PSK.");
			System.out.println("  -x        : use x.509 certificate");
			System.out.println("  URI       : The CoAP URI of the Plugtest server to test (coap://...)");
			System.exit(-1);
		}
		
		// Config used for plugtest
		NetworkConfig config = NetworkConfig.getStandard().setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 64)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 64);
		if (config.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE) < MAX_RESOURCE_SIZE) {
			config.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, MAX_RESOURCE_SIZE);
		}
		int index = 0;
		boolean verbose = false;
		boolean ping[] = {true};
		boolean rpc = false;
		boolean x509 = false;
		if (args[index].equals("-s")) {
			++index;
			ping[0] = false;
		}
		if (args[index].equals("-v")) {
			++index;
			verbose = true;
		}
		if (args[index].equals("-r")) {
			++index;
			rpc = true;
		} else if (args[index].equals("-x")) {
			++index;
			x509 = true;
		}

		String uri = args[index];

		// allow quick hostname as argument

		if (uri.indexOf("://") == -1) {
			uri = "coap://" + uri;
		}
		if (uri.endsWith("/")) {
			uri = uri.substring(-1);
		}

		setupEndpoint(uri, verbose, rpc, x509, ping);

		if (ping[0]) {
			CoapClient clientPing = new CoapClient(uri);
			System.out.println("===============\nCC31\n---------------");
			if (!clientPing.ping(2000)) {
				System.out.println(uri + " does not respond to ping, exiting...");
				System.exit(-1);
			} else {
				System.out.println(uri + " reponds to ping");
			}
		}

		testCC(uri);
		testCB(uri);
		testCO(uri);
		testCL(uri);

		System.exit(0);
	}
	
	private static void setupEndpoint(String uri, boolean verbose, boolean rpc, boolean x509, boolean ping[]) {
		NetworkConfig config = NetworkConfig.getStandard();
		Connector connector = null;

		if (uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME)) {
			SslContextUtil.Credentials clientCredentials = null;
			Certificate[] trustedCertificates = null;
			SSLContext serverSslContext = null;
			try {
				clientCredentials = SslContextUtil.loadCredentials(
						SslContextUtil.CLASSPATH_PROTOCOL + KEY_STORE_LOCATION, CLIENT_NAME, KEY_STORE_PASSWORD,
						KEY_STORE_PASSWORD);
				trustedCertificates = SslContextUtil.loadTrustedCertificates(
						SslContextUtil.CLASSPATH_PROTOCOL + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
				serverSslContext = SslContextUtil.createSSLContext(CLIENT_NAME, clientCredentials.getPrivateKey(),
						clientCredentials.getCertificateChain(), trustedCertificates);
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

			if (uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME + "://")) {
				DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
				if (rpc || x509) {
					dtlsConfig.setIdentity(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
							rpc);
					dtlsConfig.setTrustStore(trustedCertificates);
				} else {
					byte[] id =null;
					try {
						Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
						if (nets.hasMoreElements()) {
							id = nets.nextElement().getHardwareAddress();
						}
					} catch (Throwable e) {
					}
					if (id == null) {
						id = new byte[8];
						SecureRandom random = new SecureRandom();
						random.nextBytes(id);
					}					
					dtlsConfig.setPskStore(new PlugPskStore(ByteArrayUtils.toHex(id)));
				}
				connector = new DTLSConnector(dtlsConfig.build());
			} else if (uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://")) {
				int tcpThreads = config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS);
				int tcpConnectTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT);
				int tcpIdleTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT);
				connector = new TlsClientConnector(serverSslContext, tcpThreads, tcpConnectTimeout, tcpIdleTimeout);
				ping[0] = false;
			}
		} else if (uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")) {
			int tcpThreads = config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS);
			int tcpConnectTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT);
			int tcpIdleTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT);
			connector = new TcpClientConnector(tcpThreads, tcpConnectTimeout, tcpIdleTimeout);
			ping[0] = false;
		} else if (uri.startsWith(CoAP.COAP_URI_SCHEME + "://")) {
			connector = new UDPConnector();
		}

		CoapEndpoint endpoint = new CoapEndpoint(connector, config);
		if (verbose) {
			endpoint.addInterceptor(new MessageTracer());
		}
		EndpointManager.getEndpointManager().setDefaultEndpoint(endpoint);
	}

	public static void testCC(String uri) {

		// re-usable response object
		CoapResponse response;

		CoapClient client = new CoapClient(uri + "/test");

		System.out.println("===============\nCC01+10");
		System.out.println("---------------\nGET /test\n---------------");
		response = client.get();
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
		req12.setToken(new byte[0]);
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
		client.setTimeout(10000);
		client.useNONs();

		System.out.println("===============\nCC17");
		System.out.println("---------------\nNON-GET /separate\n---------------");
		response = client.get();
		System.out.println(response.advanced().getType() + "-" + response.getCode());
		System.out.println(response.getResponseText());

		client.setURI(uri + "/test");
		client.setTimeout(0);
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
	}

	public static void testCB(String uri) {

		CoapClient client = new CoapClient(uri + "/large");
		CoapResponse response;

		client.useEarlyNegotiation(64);

		System.out.println("===============\nCB01");
		System.out.println("---------------\nGET /large\n---------------");
		response = client.get();
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
	}

	public static void testCO(String uri) {

		CoapClient client = new CoapClient(uri + "/obs");

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
	}

	public static void testCL(String uri) {

		CoapClient client = new CoapClient(uri);
		Set<WebLink> links;

		System.out.println("===============\nCL01");
		System.out.println("---------------\nGET /.well-known/core\n---------------");
		links = client.discover();
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
			Set<WebLink> subLinks = LinkFormat
					.parse(linkResponse);
			System.out.println("Found " + subLinks.size() + " resource(s)");
			for (WebLink subLink : subLinks) {
				client.setURI(uri + subLink.getURI());
				System.out.println("---------------\nGET " + subLink.getURI() + "\n---------------");
				CoapResponse response = client.get();
				System.out.println(response.advanced().getType() + "-" + response.getCode());
				System.out.println(response.getResponseText());
			}
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

	private static class PlugPskStore implements PskStore {

		private final String identity;
		
		public PlugPskStore(String id) {
			identity = PSK_IDENTITY_PREFIX + id;
			System.out.println("DTLS-PSK-Identity: " + identity + " (" + (id.length()/2) + " bytes)");
		}
		
		@Override
		public byte[] getKey(String identity) {
			if (identity.startsWith(PSK_IDENTITY_PREFIX)) {
				return PSK_SECRET;
			}
			return null;
		}

		@Override
		public byte[] getKey(ServerNames serverNames, String identity) {
			return getKey(identity);
		}

		@Override
		public String getIdentity(InetSocketAddress inetAddress) {
			return identity;
		}

	}

}
