/*******************************************************************************
 * Copyright (c) 20187 Sierra Wireless and others.
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
 *    Sierra Wireless - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.credentialsstore;

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;

public class DtlsConfigCredentialsStore implements CredentialsStore{

	private CredentialsConfiguration config;
	
	
	public DtlsConfigCredentialsStore(final DtlsConnectorConfig dtlsConnectorConfig) {
		this.config = new CredentialsConfiguration() {
			
			@Override
			public Boolean isSendRawKey() {
				return dtlsConnectorConfig.isSendRawKey();
			}
			
			@Override
			public CertificateVerifier getCertificateVerifier() {
				return dtlsConnectorConfig.getCertificateVerifier();
			}
			
			@Override
			public CipherSuite[] getSupportedCipherSuites() {
				return dtlsConnectorConfig.getSupportedCipherSuites();
			}
			
			@Override
			public TrustedRpkStore getRpkTrustStore() {
				return dtlsConnectorConfig.getRpkTrustStore();
			}
			
			@Override
			public PublicKey getPublicKey() {
				return dtlsConnectorConfig.getPublicKey();
			}
			
			@Override
			public PskStore getPskStore() {
				return dtlsConnectorConfig.getPskStore();
			}
			
			@Override
			public PrivateKey getPrivateKey() {
				return dtlsConnectorConfig.getPrivateKey();
			}
			
			@Override
			public X509Certificate[] getCertificateChain() {
				return dtlsConnectorConfig.getCertificateChain();
			}
		};
	}
	
	@Override
	public CredentialsConfiguration getCredentialsConfiguration(InetSocketAddress inetAddress) {
		return config;
	}
}
