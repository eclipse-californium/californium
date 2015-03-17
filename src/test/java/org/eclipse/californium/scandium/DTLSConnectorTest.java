package org.eclipse.californium.scandium;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class DTLSConnectorTest {

	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
    private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
    
	DTLSConnector server;
	DTLSConnector client;
    InetSocketAddress serverEndpoint;
    InetSocketAddress clientEndpoint;
    Certificate[] trustedCertificates;

	@Before
	public void setUp() throws Exception {
		
		clientEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10000);
		serverEndpoint = new InetSocketAddress(InetAddress.getLocalHost(), 10100);
        // load the key store
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream in = new FileInputStream(KEY_STORE_LOCATION);
        keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
        PrivateKey serverPrivateKey = (PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray());
        Certificate[] serverKeyChain = keyStore.getCertificateChain("server");
        PrivateKey clientPrivateKey = (PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray());
        Certificate[] clientKeyChain = keyStore.getCertificateChain("client");

        // load the trust store
        KeyStore trustStore = KeyStore.getInstance("JKS");
        InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
        trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
        
        // You can load multiple certificates if needed
        trustedCertificates = new Certificate[1];
        trustedCertificates[0] = trustStore.getCertificate("root");
        
		server = createConnector(serverEndpoint, serverPrivateKey, serverKeyChain);
		client = createConnector(clientEndpoint, clientPrivateKey, clientKeyChain);
	}

	@Test
	public void testSecureMessageRoundtrip() throws IOException {
		
		final CountDownLatch latch = new CountDownLatch(2);
		Assert.assertNotNull(server);
        server.setRawDataReceiver(new RawDataChannel() {
			
			@Override
			public void receiveData(RawData raw) {
				latch.countDown();
				server.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
			}
		});
		server.start();
		Assert.assertTrue(server.isRunning());
		
		Assert.assertNotNull(client);
		client.setRawDataReceiver(new RawDataChannel() {
			
			@Override
			public void receiveData(RawData raw) {
				client.destroy();
				latch.countDown();
			}
		});
		client.start();
		client.send(new RawData("Hello World".getBytes(), serverEndpoint));

		try {
			latch.await(5, TimeUnit.SECONDS);
			Assert.assertTrue("Request/response roundtrip did not finish within 5 secs",
					0 == latch.getCount());
		} catch (InterruptedException e) {
		} finally {
			server.destroy();
		}
	}
	
	private DTLSConnector createConnector(InetSocketAddress endpoint, PrivateKey privateKey,
			Certificate[] keyChain) throws IOException, GeneralSecurityException {
        DTLSConnector dtlsConnector = new DTLSConnector(endpoint, trustedCertificates);
        dtlsConnector.getConfig().setPrivateKey(privateKey, keyChain, true);
        dtlsConnector.getConfig().setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
        
		return dtlsConnector;
	}

}
