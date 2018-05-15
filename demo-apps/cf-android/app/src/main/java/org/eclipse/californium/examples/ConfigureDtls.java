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
    private static final String KEY_STORE_LOCATION = "certs/keyStore.p12";
    private static final String TRUST_STORE_LOCATION = "certs/trustStore.p12";
    private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
    private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();

    public static void loadCredentials(DtlsConnectorConfig.Builder dtlsConfig, String alias){

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
