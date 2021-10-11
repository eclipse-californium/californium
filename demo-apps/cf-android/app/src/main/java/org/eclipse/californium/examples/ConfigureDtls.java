/*******************************************************************************
 * Copyright (c) 2018 Vikram and others.
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
 *    Vikram - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce configurable
 *                                                    key store type and
 *                                                    InputStreamFactory.
 ******************************************************************************/

package org.eclipse.californium.examples;

import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.concurrent.TimeUnit;

/**
 * class ConfigureDTLS.<br>
 * This class is used to configure dtls connector for both client and server side connections.
 * It allows to configure dtls connector in three different modes.
 * The class variables PSK, CERTIFICATE_MODE, and RPK_MODE define three different modes of dtls connector.
 * <br>PSK_MODE: supports PSK mode if this variable is set to true and to false if not.
 * <br>CERTIFICATE_MODE: supports certificate based authentication, if this variable is
 * set to true and false if not.
 * <br>RPK_MODE: alternatively supports RPK mode if this variable is set to true and to false if not.
 * <br>An endpoint may either support all the three modes or must support atleast one mode.
 */
public class ConfigureDtls {

    private static final boolean PSK_MODE = false;
    private static final boolean CERTIFICATE_MODE = true;
    private static final boolean RPK_MODE = false;
    public static final String PSK_IDENTITY = "password";
    public static final byte[] PSK_SECRET = "sesame".getBytes();
    private static final String TRUST_NAME = null; // loads all the certificates
    private static final String KEY_STORE_LOCATION = "certs/%s.p12";
    private static final String TRUST_STORE_LOCATION = "certs/trustStore.p12";
    private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
    private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();

    public static void loadCredentials(DtlsConnectorConfig.Builder dtlsConfig, String alias){

        boolean credentialsSet = false;
        SslContextUtil.Credentials endpointCredentials = null;
        Certificate[] trustedCertificates = null;
        if (CERTIFICATE_MODE || RPK_MODE) {
            try {
                String location = String.format(KEY_STORE_LOCATION, alias);
                endpointCredentials = SslContextUtil.loadCredentials(
                        SslContextUtil.CLASSPATH_SCHEME + location, alias, KEY_STORE_PASSWORD,
                        KEY_STORE_PASSWORD);
                trustedCertificates = SslContextUtil.loadTrustedCertificates(
                        SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, TRUST_NAME, TRUST_STORE_PASSWORD);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (CERTIFICATE_MODE && endpointCredentials != null && trustedCertificates != null) {
                dtlsConfig.setCertificateIdentityProvider(new SingleCertificateProvider(endpointCredentials.getPrivateKey(), endpointCredentials.getCertificateChain(), CertificateType.X_509));
                dtlsConfig.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder().setTrustedCertificates(trustedCertificates).build());
                dtlsConfig.set(DtlsConfig.DTLS_ADDITIONAL_ECC_TIMEOUT, 2000, TimeUnit.MILLISECONDS);
                dtlsConfig.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false);
                credentialsSet = true;
            } else if (RPK_MODE && endpointCredentials != null) {
                dtlsConfig.setCertificateIdentityProvider(new SingleCertificateProvider(endpointCredentials.getPrivateKey(), endpointCredentials.getCertificateChain(), CertificateType.RAW_PUBLIC_KEY));
                dtlsConfig.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder().setTrustAllRPKs().build());
                dtlsConfig.set(DtlsConfig.DTLS_ADDITIONAL_ECC_TIMEOUT, 1000, TimeUnit.MILLISECONDS);
                credentialsSet = true;
            }
        }
        if (PSK_MODE || !credentialsSet) {
            dtlsConfig.setAdvancedPskStore(new AdvancedSinglePskStore(PSK_IDENTITY, PSK_SECRET));
        }
    }
}
