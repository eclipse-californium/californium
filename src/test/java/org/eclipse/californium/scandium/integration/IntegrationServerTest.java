package org.eclipse.californium.scandium.integration;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.junit.Assert;
import org.junit.Test;

public class IntegrationServerTest {

    private CountDownLatch latch = new CountDownLatch(6);
    private List<RawData> rcvd = new ArrayList<>();
   
    
    /** 
     * This test run a DTLS server with a fixed PSK. A client is supposed to connect and send 6 messages.
     * It's supposed to be ran against an external DTLS client (like tinydtls)
     */
    @Test
    public void basic_tls_psk_test() throws IOException, InterruptedException {
        InMemoryPskStore pskStore = new InMemoryPskStore();
        // put in the PSK store the default identity/psk for tinydtls tests
        pskStore.setKey("Client_identity", "secretPSK".getBytes());
       
        DTLSConnector dtlsServer = new DTLSConnector(new InetSocketAddress(5684), null);
        dtlsServer.getConfig().setServerPsk(pskStore);
        
        dtlsServer.setRawDataReceiver(new RawDataChannelImpl(dtlsServer));


        dtlsServer.start();
        
        // wait for some  data
        Assert.assertTrue(latch.await(30, TimeUnit.SECONDS));
        dtlsServer.stop();
    }
    
    private class RawDataChannelImpl implements RawDataChannel {
        
        private Connector connector;
        
        public RawDataChannelImpl(Connector con) {
            this.connector = con;
        }

        public void receiveData(final RawData raw) {
            System.out.println("RCVD>>" + new String(raw.getBytes()));
            rcvd.add(raw);
            connector.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
            latch.countDown();
        }
    }
}
