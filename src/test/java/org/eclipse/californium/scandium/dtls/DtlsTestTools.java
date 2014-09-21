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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.DatagramWriter;

public class DtlsTestTools {
    
    public static final byte[] newDTLSRecord(int typeCode, int epoch, long sequenceNo, byte[] fragment) {
    	
        ProtocolVersion protocolVer = new ProtocolVersion();
    	// the record header contains a type code, version, epoch, sequenceNo, length
        DatagramWriter writer = new DatagramWriter();
        writer.write(typeCode, 8);
        writer.write(protocolVer.getMajor(), 8);
        writer.write(protocolVer.getMinor(), 8);
        writer.write(epoch, 16);
        writer.writeLong(sequenceNo, 48);
        writer.write(fragment.length, 16);
        writer.writeBytes(fragment);
    	return writer.toByteArray();
    }

    public static final byte[] generateCookie(InetSocketAddress endpointAddress, ClientHello clientHello) throws NoSuchAlgorithmException {

        MessageDigest md;
        byte[] cookie = null;

        md = MessageDigest.getInstance("SHA-256");

        // Cookie = HMAC(Secret, Client-IP, Client-Parameters)
        byte[] secret = "generate cookie".getBytes();

        // Client-IP
        md.update(endpointAddress.toString().getBytes());

        // Client-Parameters
        md.update((byte) clientHello.getClientVersion().getMajor());
        md.update((byte) clientHello.getClientVersion().getMinor());
        md.update(clientHello.getRandom().getRandomBytes());
        md.update(clientHello.getSessionId().getSessionId());
        md.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
        md.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));

        byte[] data = md.digest();

        cookie = Handshaker.doHMAC(md, secret, data);
        return cookie;
    }

}