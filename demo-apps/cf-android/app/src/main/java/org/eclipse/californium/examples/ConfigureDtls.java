/*******************************************************************************
 * Copyright (c) 2018 Vikram and others.
 * Contributors:
 *    Vikram - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce configurable
 *                                                    key store type and
 *                                                    InputStreamFactory.
 ******************************************************************************/
package org.eclipse.californium.examples;

import android.content.Context;

import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;

public class ConfigureDtls {

    private static final boolean PSK_MODE = false;
    private static final boolean CERTIFICATE_MODE = true;
    private static final boolean RPK_MODE = false;
    public static final String PSK_IDENTITY = "password";
    public static final byte[] PSK_SECRET = "sesame".getBytes();
    private static final String TRUST_NAME = null; // loads all the certificates
    private static final String KEY_STORE_LOCATION = "certs/keyStore.p12";
    private static final String TRUST_STORE_LOCATION = "certs/trustStore.p12";
    private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
    private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();

    public static void loadCredentials(Context context, DtlsConnectorConfig.Builder dtlsConfig,String alias){

        SslContextUtil.Credentials endpointCredentials = null;
        Certificate[] trustedCertificates = null;
        try {
            endpointCredentials = SslContextUtil.loadCredentials(
                    SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, alias, KEY_STORE_PASSWORD,
                    KEY_STORE_PASSWORD);
            trustedCertificates = SslContextUtil.loadTrustedCertificates(
                    SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, TRUST_NAME, TRUST_STORE_PASSWORD);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (PSK_MODE) {
            dtlsConfig.setPskStore(new StaticPskStore(PSK_IDENTITY, PSK_SECRET));
        } else if (CERTIFICATE_MODE) {
            dtlsConfig.setTrustStore(trustedCertificates);
            dtlsConfig.setIdentity(endpointCredentials.getPrivateKey(),
                    endpointCredentials.getCertificateChain(), false);
        } else if (RPK_MODE) {
            dtlsConfig.setIdentity(endpointCredentials.getPrivateKey(),
                    endpointCredentials.getCertificateChain(), true);
        }

    }
}
