/*******************************************************************************
 * Copyright (c) 2014 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla, Bosch Software Innovations GmbH
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import org.eclipse.californium.scandium.DTLSConnectorConfig;
import org.eclipse.californium.scandium.util.DatagramWriter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ServerHandshakerTest {

    private final int EPOCH = 1;
    ServerHandshaker handshaker;
    DTLSSession session;
    InetSocketAddress endpoint = InetSocketAddress.createUnresolved("localhost", 10000);
    byte[] sessionId = new byte[]{(byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};
    byte[] random;
    byte[] clientHelloMsg;
    
    @Before
    public void setup() throws Exception {
        session = new DTLSSession(endpoint, false);
        session.setReadEpoch(EPOCH);
        handshaker = new ServerHandshaker(endpoint, session, new Certificate[]{}, new DTLSConnectorConfig(null));

        DatagramWriter writer = new DatagramWriter();
        // uint32 gmt_unix_time
        Date now = new Date();
        writer.writeLong(Math.round(now.getTime() / 1000), 32);
        // opaque random_bytes[28]
        for (int i = 0; i < 28; i++) {
            writer.write(i, 8);
        }
        random = writer.toByteArray();
        
    }
    
    @Test
    public void testReceiveClientHelloSupportsUnknownCiphers() throws HandshakeException {
        
        // process initial Client Hello without cookie
        DTLSFlight flight = processClientHello(0, new byte[]{(byte) 0xFF, (byte) 0xA8, (byte) 0xC0, (byte) 0xA8}, null);
        
        Assert.assertNotNull(flight);
        Assert.assertFalse(flight.getMessages().isEmpty());
        HelloVerifyRequest verifyReq = (HelloVerifyRequest) flight.getMessages().get(0).getFragment();
        byte[] cookie = verifyReq.getCookie().getCookie();
        
        // process Client Hello including Cookie
        flight = processClientHello(1, new byte[]{(byte) 0xFF, (byte) 0xA8, (byte) 0xC0, (byte) 0xA8}, cookie);
        
        byte[] loggedMsg = new byte[clientHelloMsg.length];
        System.arraycopy(handshaker.handshakeMessages, 0, loggedMsg, 0, clientHelloMsg.length);
        Assert.assertArrayEquals(clientHelloMsg, loggedMsg);
    }

    private DTLSFlight processClientHello(int messageSeq, byte[] supportedCiphers, byte[] cookie) throws HandshakeException {
        byte[] clientHelloFragment = newClientHelloFragment(supportedCiphers, cookie);
        clientHelloMsg = newHandshakeMessage(1, messageSeq, clientHelloFragment);
        byte[] dtlsRecord = DtlsTestTools.newDTLSRecord(22, EPOCH, 0, clientHelloMsg);
        List<Record> list = Record.fromByteArray(dtlsRecord);
        Assert.assertFalse("Should be able to deserialize DTLS Record from byte array", list.isEmpty());
        Record record = list.get(0);
        return handshaker.processMessage(record);
    }
    
    private byte[] newHandshakeMessage(int type, int messageSeq, byte[] fragment) {
        int length = 8 + 24 + 16 + 24 + 24 + fragment.length;
        DatagramWriter writer = new DatagramWriter();
        writer.write(type, 8);
        writer.write(length, 24);
        writer.write(messageSeq, 16);
        writer.write(0, 24);
        writer.write(length, 24);
        writer.writeBytes(fragment);
        return writer.toByteArray();
    }
    
    /**
     * Creates a ClientHello message as defined by
     * <a href="http://tools.ietf.org/html/rfc5246#page-39">Client Hello</a>
     * 
     * @return the bytes of the message
     */
    private byte[] newClientHelloFragment(byte[] supportedCipherSuites, byte[] cookie) {
        DatagramWriter writer = new DatagramWriter();
        // Protocol version (DTLS 1.2)
        writer.write(254, 8);
        writer.write(253, 8);
        
        writer.writeBytes(random);
        
        // Session ID
        writer.write(sessionId.length, 8);
        writer.writeBytes(sessionId);
        
        // write cookie
        if (cookie == null) {
            writer.write(0,  8);
        } else {
            writer.write(cookie.length, 8);
            writer.writeBytes(cookie);
        }
        
        // supported Cipher Suites
        writer.write(supportedCipherSuites.length, 16);
        writer.writeBytes(supportedCipherSuites);
        
        // a single compression method is supported
        writer.write(1, 8);
        writer.writeByte((byte) 0x00); // compression method "null"
        
        return writer.toByteArray();
    }

}
