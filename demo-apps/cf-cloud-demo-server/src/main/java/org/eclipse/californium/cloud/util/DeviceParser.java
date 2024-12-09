/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.security.auth.DestroyFailedException;

import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.PemReader;
import org.eclipse.californium.elements.util.PemUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCertificateFactory;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Device credentials parser.
 * <p>
 * Format:
 * 
 * <pre>
 * {@code # <comment>}
 * {@code <device-name>[.group]=<group>}
 * {@code [[<device-name>].label=<label>]}
 * {@code [[<device-name>].psk=<identity>,<pre-shared-secret>]}
 * {@code [[<device-name>].rpk=<raw-public-key-certificate>]}
 * {@code [[<device-name>].sig=<signed raw-public-key-certificate>]}
 * {@code [[<device-name>].type=(dev|prov|ca)]}
 * {@code [[<device-name>].x509=]}
 * {@code [[<device-name>].ban=]}
 * {@code [[<device-name>].prov=1]} // deprecated, please use ".type=prov"
 * </pre>
 * 
 * <p>
 * The recommended "best practice" is to choose a long term stable and unique
 * {@code device-name}. In many cases that will be a technical ID, which is hard
 * to be used by humans to identify the device. Therefore an additional
 * {@code label} is available to provide human recognizable identities. The PSK
 * {@code identity} may be included in single- ({@code '}) or double-quotes
 * ({@code "}). The {@code pre-shared-secret} may be provided in base 64
 * encoding, in hexadecimal encoding with leading {@code :x0}, or as plain text
 * in single- ({@code '}) or double-quotes ({@code "}). The
 * {@code raw-public-key-certificate} may be provided in base 64 encoding, or in
 * hexadecimal encoding with leading {@code :x0}. The
 * {@code raw-public-key-certificate} must be given in ASN.1/PEM format (public
 * key including the algorithm and curve identifier). Only for the
 * {@code secp256r1} curve the public key may be provided as the plain 64 bytes
 * of the public key. If {@code raw-public-key-certificate} is provided by other
 * parties, it may be relevant to have a proof that the device has a matching
 * private key for the provide public key. Therefore a optional signature may be
 * provided.
 * <p>
 * For {@code x509} client and certificate authority certificates, the base 64
 * encoding of the ".pem" file is supported. See example below.
 * <p>
 * Not all credentials are identifying a device, some are used for provisioning
 * or as trusted <b>C</b>ertificate <b>A</b>uthority for x509 device
 * certificates. That is indicated by the {@code .type=(dev|prov|ca)} entry. If
 * no one is given, "dev" is assumed.
 * <p>
 * In order to block (or ban) a device, {@code .ban=1} is used. Ban a CA will
 * also ban all devices with that CA as trust root. Ban provisioning credentials
 * will not ban the devices provisioned with that.
 * <p>
 * The CoAP-S3-proxy offers additionally http-forwarding and a device specific
 * configuration of that function is done with custom fields:
 * 
 * <pre>
 * {@code [[<device-name>].fdest=<http-forward-destination>]}
 * {@code [[<device-name>].fauth=<http-forward-authentication>]}
 * {@code [[<device-name>].fdevid=(NONE,HEADLINE,QUERY_PARAMETER)]}
 * {@code [[<device-name>].fresp=<http-forward-response-filter>]}
 * {@code [[<device-name>].fservice=<java-http-forward-service>]}
 * </pre>
 * 
 * For details please see the documentation of {@code BasicHttpForwardConfiguration}.
 * <p>
 * Example:
 * 
 * <pre>
 * {@code # base64 secret}
 * {@code DemoClient=Demo}
 * {@code .psk='Client_identity',c2VjcmV0UFNL}
 * {@code .rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQxYO5/M5ie6+3QPOaAy5MD6CkFILZwIb2rOBCX/EWPaocX1H+eynUnaEEbmqxeN6rnI/pH19j4PtsegfHLrzzQ==}
 * 
 * {@code # PSK only, hexadecimal secret}
 * {@code DemoDevice1=Demo}
 * {@code .psk='Device_identity',:0x010203040506}
 * 
 * {@code # RPK only, base64 certificate and signature}
 * {@code DemoDevice2=Demo}
 * {@code .rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZRd+6w2dbCoDlIhrbkBkQdEHkiayS3CUgWYOanlU5curNy3H+MOheCqbmPZJdQud8KNvXXYTUyeYX/IqyOk8nQ==}
 * {@code .sig=BAMARzBFAiEAioj8fh5VrTYMz93XakmlCS283zAv8JxWcpADnbwlhGwCIDwm5mEXP8MBV1o7w08a79d+y84w81vW9LgP8QbDCp/p}
 * 
 * {@code # x509}
 * {@code DemoDevice3=Demo}
 * {@code .x509=}
 * {@code -----BEGIN CERTIFICATE-----}
 * {@code MIICAjCCAaigAwIBAgIJAJvzugZ7RkwVMAoGCCqGSM49BAMCMFwxEDAOBgNVBAMT}
 * {@code B2NmLXJvb3QxFDASBgNVBAsTC0NhbGlmb3JuaXVtMRQwEgYDVQQKEwtFY2xpcHNl}
 * {@code IElvVDEPMA0GA1UEBxMGT3R0YXdhMQswCQYDVQQGEwJDQTAeFw0yNDExMDcxNTA5}
 * {@code MzVaFw0yNjExMDcxNTA5MzVaMGAxFDASBgNVBAMTC2NmLWNsaWVudC0yMRQwEgYD}
 * {@code VQQLEwtDYWxpZm9ybml1bTEUMBIGA1UEChMLRWNsaXBzZSBJb1QxDzANBgNVBAcT}
 * {@code Bk90dGF3YTELMAkGA1UEBhMCQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATa}
 * {@code v2cItqEoanxb1UduhvKR+dlbkr0lsbR/ql01UPuAa2ONNt9uIl9FCXoF3V/VzE3O}
 * {@code xW5+YTUraJ/CcuARZC5Mo08wTTAdBgNVHQ4EFgQU0d8npcBVyIxSwE9hPFTJ7qmZ}
 * {@code 04owCwYDVR0PBAQDAgeAMB8GA1UdIwQYMBaAFBifxGwtiNzNWfvoU9IdZYrqJqp3}
 * {@code MAoGCCqGSM49BAMCA0gAMEUCIQC5F+tgTY5IzmbjlXqQE6ha/hFHE981mo0pSAzv}
 * {@code NdTutwIgS0YrTmYDan4J8Z+svEG89HbLk2QlY2aGrzyjce7faSk=}
 * {@code -----END CERTIFICATE-----}
 * </pre>
 * 
 * <b>Note:</b> the data associated for a {@code device-name} may change, but
 * the {@code device-name} itself is considered to be stable. However, though
 * during the DTLS handshake the credentials are used to identify the device,
 * changing them here in the store must reflect a change on the device.
 * Otherwise the device will not longer be assigned to the {@code device-name}.
 * 
 * @since 3.12
 */
public class DeviceParser implements AppendingResourceParser<DeviceParser> {

	private static final Logger LOGGER = LoggerFactory.getLogger(DeviceParser.class);

	private static final String CERTIFICATE_TYPE_X509 = "X.509";

	private static final ThreadLocalCertificateFactory CERTIFICATE_FACTORY = new ThreadLocalCertificateFactory(
			CERTIFICATE_TYPE_X509);

	/**
	 * ASN.1 header for plain {@code secp256r1} public key.
	 */
	private static final byte[] ECC_SECP256R1_HEADER;

	static {
		// initialize header for secp256r1
		byte[] header = null;
		try {
			String oid = JceProviderUtil.getEdDsaStandardAlgorithmName("EC", "EC");
			KeyPairGenerator generator = KeyPairGenerator.getInstance(oid);
			generator.initialize(new ECGenParameterSpec("secp256r1"), RandomManager.currentSecureRandom());
			KeyPair keyPair = generator.generateKeyPair();
			byte[] encoded = keyPair.getPublic().getEncoded();
			header = Arrays.copyOf(encoded, encoded.length - 64);
		} catch (GeneralSecurityException ex) {
			header = null;
			LOGGER.error("EC failed!", ex);
		}
		ECC_SECP256R1_HEADER = header;
	}

	/**
	 * Device credentials.
	 * 
	 * @since 3.13 implements DeviceIdentifier
	 */
	public static class Device implements DeviceIdentifier {

		/**
		 * Comment.
		 */
		public final String comment;
		/**
		 * Device name.
		 */
		public final String name;
		/**
		 * Device label.
		 * 
		 * @since 3.13
		 */
		public final String label;
		/**
		 * Device group.
		 */
		public final String group;
		/**
		 * PreSharedKey identity. {@code null}, if no PreSharedKey credentials
		 * are used.
		 */
		public final String pskIdentity;
		/**
		 * PreSharedKey secret. {@code null}, if no PreSharedKey credentials are
		 * used.
		 */
		public final byte[] pskSecret;
		/**
		 * RawPublicKey certificate. {@code null}, if no RawPublicKey
		 * certificate is used.
		 */
		public final PublicKey publicKey;
		/**
		 * Signature as "proof of possession" of a {@link #publicKey} matching
		 * private key.
		 * <p>
		 * Only used, if {@link #publicKey} is provided. May be {@code null}.
		 * 
		 * @since 3.13
		 */
		public final byte[] sign;
		/**
		 * X509 certificate. {@code null}, if no x509 certificate is used.
		 * 
		 * @since 4.0
		 */
		public final X509Certificate x509;
		/**
		 * X509 PEM tag.
		 * 
		 * @since 4.0
		 */
		public final String x509PemTag;
		/**
		 * Device type.
		 * 
		 * @since 4.0
		 */
		public final Type type;
		/**
		 * Ban device.
		 * 
		 * @since 4.0
		 */
		public final boolean ban;
		/**
		 * Custom fields.
		 */
		public final Map<String, String> customFields;

		/**
		 * Create device credentials.
		 * 
		 * @param name name of device
		 * @param label label of device. If {@code null}, the name is used as
		 *            label.
		 * @param comment leading comment. {@code null}, if not used.
		 * @param group group of device
		 * @param pskIdentity PreSharedKey identity. {@code null}, if no
		 *            PreSharedKey credentials are used.
		 * @param pskSecret PreSharedKey secret. {@code null}, if no
		 *            PreSharedKey credentials are used.
		 * @param publicKey RawPublicKey certificate. {@code null}, if no
		 *            RawPublicKey certificate is used.
		 * @param sign Signature as "proof of possession" of a
		 *            {@link #publicKey} matching private key. Only used, if
		 *            {@link #publicKey} is provided. May be {@code null}.
		 * @param x509PemTag tag in PEM file for x509 certificate
		 * @param x509 x509 certificate.
		 * @param type device type.
		 * @param ban {@code true} to ban device.
		 * @param customFields map of custom field values. May be {@code null}.
		 * @throws NullPointerException if name or group is {@code null}
		 * @throws IllegalArgumentException if sign without public key is
		 *             provided, or neither valid psk nor rpk credentials are
		 *             provided.
		 * @since 4.0 (added more fields)
		 */
		public Device(String name, String label, String comment, String group, String pskIdentity, byte[] pskSecret,
				PublicKey publicKey, byte[] sign, String x509PemTag, X509Certificate x509, Type type, boolean ban,
				Map<String, String> customFields) {
			if (name == null) {
				throw new NullPointerException("name must not be null!");
			}
			if (group == null) {
				throw new NullPointerException("group must not be null!");
			}
			if (pskIdentity == null && publicKey == null && x509 == null) {
				throw new IllegalArgumentException("either pskIdentity, publicKey or x509 must not be null!");
			}
			if (pskIdentity != null && pskSecret == null) {
				throw new IllegalArgumentException("pskSecret must not be null, if pskIdentity is provided!");
			}
			if (pskIdentity == null && pskSecret != null) {
				throw new IllegalArgumentException("pskIdentity must not be null, if pskSecret is provided!");
			}
			if (x509 != null && x509PemTag == null) {
				throw new IllegalArgumentException("x509PemTag must not be null, if x509 is provided!");
			}
			if (x509 == null && x509PemTag != null) {
				throw new IllegalArgumentException("x509 must not be null, if x509PemTag is provided!");
			}
			if (sign != null) {
				if (publicKey == null) {
					throw new IllegalArgumentException("sign must only be provided, if a public key is provided!");
				}
				DatagramReader reader = new DatagramReader(sign);
				try {
					SignedMessage signed = SignedMessage.fromReader(reader);
					byte[] data0 = new byte[] { 0 };
					signed.verifySignature(publicKey, data0, publicKey.getEncoded());
					LOGGER.debug("{} Signature verified!", name);
				} catch (GeneralSecurityException e) {
					throw new IllegalArgumentException("Signature not verified!");
				}
			}
			this.comment = comment;
			this.name = name;
			this.label = label;
			this.group = group;
			this.pskIdentity = pskIdentity;
			this.pskSecret = pskSecret;
			this.publicKey = publicKey;
			this.x509 = x509;
			this.x509PemTag = x509PemTag;
			this.sign = sign;
			this.type = type;
			this.ban = ban;
			this.customFields = customFields;
		}

		/**
		 * Create device credentials from device with additional label and custom fields.
		 * 
		 * @param device device. The {@link #customFields} of this device may get modified!
		 * @param label additional label
		 * @param customFields map of custom field values. May be {@code null}.
		 * @since 4.0 (added customFields)
		 */
		public Device(Device device, String label, Map<String, String> customFields) {
			this.comment = device.comment;
			this.name = device.name;
			this.label = applyDefault(device.label, label);
			this.group = device.group;
			this.pskIdentity = device.pskIdentity;
			this.pskSecret = device.pskSecret;
			this.publicKey = device.publicKey;
			this.sign = device.sign;
			this.x509 = device.x509;
			this.x509PemTag = device.x509PemTag;
			this.type = device.type;
			this.ban = device.ban;
			if (customFields != null) {
				if (device.customFields != null) {
					for (Map.Entry<String, String> entry : customFields.entrySet()) {
						device.customFields.putIfAbsent(entry.getKey(), entry.getValue());
					}
				}
			} else {
				customFields = device.customFields;
			}
			this.customFields = customFields;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getLabel() {
			return label;
		}

		@Override
		public int hashCode() {
			return name.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Device other = (Device) obj;
			if (!name.equals(other.name))
				return false;
			return true;
		}

		private static <T> T applyDefault(T value, T def) {
			return value != null ? value : def;
		}

		/**
		 * Create builder for {@link Device}.
		 * 
		 * @return builder.
		 */
		public static Builder builder() {
			return new Builder();
		}

		/**
		 * Builder for Device.
		 */
		public static class Builder {

			/**
			 * Comment.
			 */
			public String comment;
			/**
			 * Device name.
			 */
			public String name;
			/**
			 * Device label.
			 * 
			 * @since 3.13
			 */
			public String label;
			/**
			 * Device group.
			 */
			public String group;
			/**
			 * PreSharedKey identity. {@code null}, if no PreSharedKey
			 * credentials are used.
			 */
			public String pskIdentity;
			/**
			 * PreSharedKey secret. {@code null}, if no PreSharedKey credentials
			 * are used.
			 */
			public byte[] pskSecret;
			/**
			 * RawPublicKey certificate. {@code null}, if no RawPublicKey
			 * certificate is used.
			 */
			public PublicKey publicKey;
			/**
			 * Signature as "proof of possession" of a {@link #publicKey}
			 * matching private key.
			 * <p>
			 * Only used, if {@link #publicKey} is provided. May be
			 * {@code null}.
			 * 
			 * @since 3.13
			 */
			public byte[] sign;
			/**
			 * X509 device certificate.
			 * 
			 * @since 4.0
			 */
			public X509Certificate x509;
			/**
			 * X509 PEM tag.
			 * 
			 * @since 4.0
			 */
			public String x509PemTag;
			/**
			 * Provisioning credentials.
			 * 
			 * @since 4.0
			 */
			public Type type;
			/**
			 * Ban device.
			 * 
			 * @since 4.0
			 */
			public boolean ban;
			/**
			 * Custom fields.
			 */
			public Map<String, String> customFields;

			/**
			 * Create builder.
			 */
			private Builder() {

			}

			public boolean addCustomField(String name, String value) {
				if (customFields == null) {
					customFields = new HashMap<>();
				}
				return customFields.putIfAbsent(name, value) == null;
			}

			public void applyDefaults() {
				type = applyDefault(type, Type.DEVICE);
			}

			/**
			 * Create device from builder data.
			 * 
			 * @return created device
			 */
			public Device build() {
				applyDefaults();
				return new Device(name, label, comment, group, pskIdentity, pskSecret, publicKey, sign, x509PemTag,
						x509, type, ban, customFields);
			}
		}

	}

	/**
	 * Postfix in field name for group.
	 */
	public static final String GROUP_POSTFIX = ".group";
	/**
	 * Postfix in field name for label.
	 * 
	 * @since 3.13
	 */
	public static final String LABEL_POSTFIX = ".label";
	/**
	 * Postfix in field name for PreSharedKey credentials.
	 */
	public static final String PSK_POSTFIX = ".psk";
	/**
	 * Postfix in field name for RawPublicKey certificate.
	 */
	public static final String RPK_POSTFIX = ".rpk";
	/**
	 * Postfix in field name for signature.
	 * 
	 * @since 3.13
	 */
	public static final String SIG_POSTFIX = ".sig";
	/**
	 * Postfix in field name for x509 certificate.
	 */
	public static final String X509_POSTFIX = ".x509";
	/**
	 * Postfix in field name for provisioning credentials.
	 * 
	 * @since 3.13
	 * @deprecated replaced by {@link #TYPE_POSTFIX} {@code =prov}.
	 */
	@Deprecated
	public static final String PROV_POSTFIX = ".prov";
	/**
	 * Postfix in field name for credentials type.
	 * 
	 * @since 4.0
	 */
	public static final String TYPE_POSTFIX = ".type";
	/**
	 * Postfix in field name for banned credentials.
	 * 
	 * @since 4.0
	 */
	public static final String BAN_POSTFIX = ".ban";

	private static final List<String> POSTFIXES = Arrays.asList(LABEL_POSTFIX, PSK_POSTFIX, RPK_POSTFIX, SIG_POSTFIX,
			X509_POSTFIX, PROV_POSTFIX, TYPE_POSTFIX, BAN_POSTFIX);
	/**
	 * ReadWrite lock to protect access to maps.
	 */
	private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
	/**
	 * Map of device names and credentials.
	 */
	private final ConcurrentMap<String, Device> map = new ConcurrentHashMap<>();
	/**
	 * Map of device names and credentials of new devices.
	 */
	private final ConcurrentMap<String, Device> newDevices = new ConcurrentHashMap<>();
	/**
	 * Map of PreSharedKey identities and credentials.
	 */
	private final ConcurrentMap<String, Device> psk = new ConcurrentHashMap<>();
	/**
	 * Map of RawPublicKeys.
	 */
	private final ConcurrentMap<PublicKey, Device> rpk = new ConcurrentHashMap<>();
	/**
	 * Map of x509 certificates.
	 */
	private final ConcurrentMap<X509Certificate, Device> x509 = new ConcurrentHashMap<>();
	/**
	 * Map of x509 CA certificates.
	 */
	private final ConcurrentMap<X509Certificate, Device> x509Ca = new ConcurrentHashMap<>();
	/**
	 * Map of group names and sets of device identifiers.
	 * 
	 * @since 3.13 use DeviceIdentifier instead of String
	 */
	private final ConcurrentMap<String, Set<DeviceIdentifier>> groups = new ConcurrentHashMap<>();
	/**
	 * {@code true} to use case sensitive names, {@code false}, otherwise.
	 */
	private final boolean caseSensitiveNames;
	/**
	 * {@code true} to replace previous credentials, {@code false}, to reject
	 * the new ones, if already available.
	 */
	private final boolean replace;
	/**
	 * Set of custom fields.
	 */
	private final List<String> customFields;
	/**
	 * {@code true} if credentials are destroyed.
	 */
	private volatile boolean destroyed;

	private volatile X509Certificate[] trusts;

	/**
	 * Create device store.
	 * 
	 * @param caseSensitiveNames {@code true} to use case sensitive names,
	 *            {@code false}, otherwise.
	 * @param replace {@code true} to replace previous credentials,
	 *            {@code false}, to reject the new ones, if already available.
	 * @param customFields set of custom fields. {@code null}, if not used.
	 */
	public DeviceParser(boolean caseSensitiveNames, boolean replace, List<String> customFields) {
		if (customFields != null) {
			for (String name : customFields) {
				if (!name.startsWith(".")) {
					throw new IllegalArgumentException("Custom field '" + name + "' doesn't start with '.'!");
				}
			}
		}
		this.caseSensitiveNames = caseSensitiveNames;
		this.replace = replace;
		this.customFields = customFields;
	}

	/**
	 * Get key from name.
	 * 
	 * @param name name of entry
	 * @return key from name
	 * @see #caseSensitiveNames
	 */
	private String getKey(String name) {
		String key = name == null ? "" : name;
		if (!caseSensitiveNames && key != null) {
			key = key.toLowerCase();
		}
		return key;
	}

	/**
	 * Match names considering {@link #caseSensitiveNames}.
	 * 
	 * @param name1 first name to match
	 * @param name2 second name to match
	 * @return {@code true}, if names are matching, {@code false}, otherwise.
	 */
	private boolean match(String name1, String name2) {
		if (caseSensitiveNames) {
			return name1.equals(name2);
		} else {
			return name1.equalsIgnoreCase(name2);
		}
	}

	/**
	 * Get prefix from id.
	 * 
	 * @param id id
	 * @param postfix postfix to be removed from id
	 * @return either the unchanged id, or the id with the postfix tail removed.
	 * @see StringUtil#truncateTail(boolean, String, String)
	 */
	private String prefix(String id, String postfix) {
		return StringUtil.truncateTail(!caseSensitiveNames, id, postfix);
	}

	/**
	 * Checks, if provided id ends with provided postfix.
	 * 
	 * @param id id
	 * @param postfix postfix
	 * @return {@code true}, if matching, {@code false}, if not.
	 */
	private boolean endsWith(String id, String postfix) {
		int length = postfix.length();
		int offset = id.length() - length;
		if (offset >= 0) {
			return id.regionMatches(!caseSensitiveNames, offset, postfix, 0, length);
		}
		return false;
	}

	/**
	 * Checks, if provided id is a name.
	 * <p>
	 * The id is a name, if it ends with {@link #GROUP_POSTFIX}, or if it
	 * doesn't end with one of the {@link #POSTFIXES} nor {@link #customFields}.
	 * 
	 * @param id id to check
	 * @return {@code true}, if id complies with a name, {@code false},
	 *         otherwise.
	 */
	private boolean isName(String id) {
		if (endsWith(id, GROUP_POSTFIX)) {
			return true;
		}
		for (String postfix : POSTFIXES) {
			if (endsWith(id, postfix)) {
				return false;
			}
		}
		if (isCustomField(id) != null) {
			return false;
		}
		return !id.startsWith(".");
	}

	/**
	 * Checks, if provided id is a custom field.
	 * 
	 * @param id id to check
	 * @return custom field name, or {@code null}, if id is no custom field.
	 * @since 4.0
	 */
	private String isCustomField(String id) {
		if (customFields != null) {
			for (String postfix : customFields) {
				if (endsWith(id, postfix)) {
					return postfix;
				}
			}
		}
		return null;
	}

	/**
	 * Match the device builder with the provided name
	 * <p>
	 * A device builder without a name doesn't match at all. A empty name
	 * matches any non empty builder name. Or the name must match the builder's
	 * name according {@link #match(String, String)}.
	 * 
	 * @param builder device builder
	 * @param name name
	 * @return {@code true}, if the builder and name matches, {@code false},
	 *         otherwise.
	 */
	private boolean match(Device.Builder builder, String name) {
		if (builder.name == null) {
			return false;
		}
		if (name.isEmpty()) {
			return !builder.name.isEmpty();
		} else {
			return match(builder.name, name);
		}
	}

	/**
	 * Add device from builder credentials.
	 * 
	 * @param builder builder with device data
	 * @return {@code true}, if device was added, {@code false}, if the device
	 *         was already added
	 */
	public boolean add(Device.Builder builder) {
		return add(builder.build());
	}

	/**
	 * Add device.
	 * 
	 * @param device device to add
	 * @return {@code true}, if device was added, {@code false}, if the device
	 *         was already added
	 */
	public boolean add(Device device) {
		String key = getKey(device.name);
		lock.writeLock().lock();
		try {
			Device replaced = map.putIfAbsent(key, device);
			if (replaced != null) {
				if (replace && replaced.type == Type.DEVICE && !replaced.ban) {
					if (device.label == null && replaced.label != null) {
						device = new Device(device, replaced.label, replaced.customFields);
					}
					remove(replaced);
					map.putIfAbsent(key, device);
				} else {
					return false;
				}
			}
			Device previous = null;
			if (device.pskIdentity != null && (previous = psk.putIfAbsent(device.pskIdentity, device)) != null) {
				LOGGER.info("psk {} {} ambiguous {}", device.pskIdentity, device.name, previous.name);
				map.remove(key, device);
				if (replaced != null) {
					add(replaced);
				}
				return false;
			}
			if (device.publicKey != null && (previous = rpk.putIfAbsent(device.publicKey, device)) != null) {
				LOGGER.info("rpk {} ambiguous {}", device.name, previous.name);
				remove(device);
				if (replaced != null) {
					add(replaced);
				}
				return false;
			}
			if (device.x509 != null) {
				if ((previous = x509.putIfAbsent(device.x509, device)) != null) {
					LOGGER.info("x509 {} ambiguous {}", device.name, previous.name);
					remove(device);
					if (replaced != null) {
						add(replaced);
					}
					return false;
				}
				if (device.type == Type.CA) {
					if ((previous = x509Ca.putIfAbsent(device.x509, device)) != null) {
						LOGGER.info("x509 {} ambiguous CA {}", device.name, previous.name);
						remove(device);
						if (replaced != null) {
							add(replaced);
						}
						return false;
					}
					synchronized (x509Ca) {
						trusts = null;
					}
				}
			}
			LOGGER.info("added {}{}{}{}{} {}{}", device.name, device.pskIdentity != null ? " psk" : "",
					device.publicKey != null ? " rpk" : "", device.sign != null ? " (sign)" : "",
					device.x509 != null ? " x509" : "", device.type.getShortName(), device.ban ? " (banned)" : "");
			Set<DeviceIdentifier> group = new HashSet<>();
			Set<DeviceIdentifier> prev = groups.putIfAbsent(device.group, group);
			if (prev != null) {
				group = prev;
			}
			group.add(device);
			newDevices.put(key, device);
			return true;
		} finally {
			lock.writeLock().unlock();
		}
	}

	/**
	 * Get devices of group
	 * 
	 * @param group group
	 * @return set of device names
	 */
	public Set<DeviceIdentifier> getGroup(String group) {

		Set<DeviceIdentifier> devices = groups.get(group);
		if (devices == null) {
			devices = Collections.emptySet();
		}
		return devices;
	}

	public X509Certificate[] getTrustedCertificates() {
		X509Certificate[] trusts = this.trusts;
		if (trusts == null) {
			synchronized (x509Ca) {
				trusts = this.trusts;
				if (trusts == null) {
					int index = 0;
					LOGGER.debug("{} CA x509 certificates", x509Ca.size());
					trusts = new X509Certificate[x509Ca.size()];
					for (X509Certificate certificate : x509Ca.keySet()) {
						trusts[index++] = certificate;
					}
					this.trusts = trusts;
				}
			}
		}
		return trusts;
	}

	/**
	 * Get device.
	 * 
	 * @param name device
	 * @return device credentials, or {@code null}, if not available.
	 */
	public Device get(String name) {
		return map.get(getKey(name));
	}

	/**
	 * Get device by PreSharedKey identity.
	 * 
	 * @param identity PreSharedKey identity
	 * @return device credentials, or {@code null}, if not available.
	 */
	public Device getByPreSharedKeyIdentity(String identity) {
		return psk.get(identity);
	}

	/**
	 * Get device by raw public key.
	 * 
	 * @param publicKey raw public key
	 * @return device credentials, or {@code null}, if not available.
	 */
	public Device getByRawPublicKey(PublicKey publicKey) {
		return rpk.get(publicKey);
	}

	/**
	 * Get device by x509 certificate.
	 * 
	 * @param x509Certificate x509 certificate
	 * @return device credentials, or {@code null}, if not available.
	 */
	public Device getByX509(X509Certificate x509Certificate) {
		return x509.get(x509Certificate);
	}

	/**
	 * Get device by principal.
	 * 
	 * @param principal device principal
	 * @return device credentials, or {@code null}, if not available.
	 * @see #getByPreSharedKeyIdentity(String)
	 * @see #getByRawPublicKey(PublicKey)
	 * @see #getByX509(X509Certificate)
	 */
	public Device getByPrincipal(Principal principal) {
		if (principal instanceof PreSharedKeyIdentity) {
			PreSharedKeyIdentity pskIdentity = (PreSharedKeyIdentity) principal;
			return getByPreSharedKeyIdentity(pskIdentity.getIdentity());
		} else if (principal instanceof RawPublicKeyIdentity) {
			RawPublicKeyIdentity rpkIdentity = (RawPublicKeyIdentity) principal;
			return getByRawPublicKey(rpkIdentity.getKey());
		} else if (principal instanceof X509CertPath) {
			X509CertPath x509Identity = (X509CertPath) principal;
			return getByX509(x509Identity.getTarget());
		}
		return null;
	}

	/**
	 * Remove device.
	 * 
	 * @param name device name
	 * @return {@code true}, if device was removed, {@code false} otherwise.
	 */
	public boolean remove(String name) {
		return remove(get(name));
	}

	/**
	 * Remove device.
	 * 
	 * @param device device to remove
	 * @return {@code true}, if device was removed, {@code false} otherwise.
	 */
	public boolean remove(Device device) {
		lock.writeLock().lock();
		try {
			String key = getKey(device.name);
			boolean removed = map.remove(key, device);
			if (removed) {
				if (device.pskIdentity != null) {
					psk.remove(device.pskIdentity, device);
				}
				if (device.publicKey != null) {
					rpk.remove(device.publicKey, device);
				}
				if (device.x509 != null) {
					x509.remove(device.x509, device);
					if (device.type == Type.CA) {
						if (x509Ca.remove(device.x509, device)) {
							synchronized (x509Ca) {
								trusts = null;
							}
						}
					}
				}
				Set<DeviceIdentifier> group = groups.get(device.group);
				if (group != null) {
					group.remove(device);
				}
				newDevices.remove(key, device);
				return true;
			}
			return removed;
		} finally {
			lock.writeLock().unlock();
		}
	}

	/**
	 * Number of entries.
	 * 
	 * @return number of entries
	 */
	public int size() {
		return map.size();
	}

	@Override
	public int sizeNewEntries() {
		return newDevices.size();
	}

	@Override
	public void clearNewEntries() {
		lock.writeLock().lock();
		try {
			newDevices.clear();
		} finally {
			lock.writeLock().unlock();
		}
	}

	@Override
	public void saveNewEntries(Writer writer) throws IOException {
		lock.readLock().lock();
		try {
			save(newDevices, writer);
		} finally {
			lock.readLock().unlock();
		}
	}

	@Override
	public void save(Writer writer) throws IOException {
		lock.readLock().lock();
		try {
			save(map, writer);
		} finally {
			lock.readLock().unlock();
		}
	}

	private void save(ConcurrentMap<String, Device> map, Writer writer) throws IOException {
		List<String> names = new ArrayList<>(map.keySet());
		Collections.sort(names);
		for (String name : names) {
			Device credentials = map.get(name);
			if (credentials != null) {
				if (credentials.comment != null) {
					writer.write(StringUtil.lineSeparator());
					writer.write("# ");
					writer.write(credentials.comment);
					writer.write(StringUtil.lineSeparator());
				}
				writer.write(credentials.name);
				writer.write('=');
				writer.write(credentials.group);
				writer.write(StringUtil.lineSeparator());
				if (credentials.label != null) {
					writer.write(LABEL_POSTFIX);
					writer.write('=');
					writer.write(credentials.label);
					writer.write(StringUtil.lineSeparator());
				}
				if (credentials.pskIdentity != null && credentials.pskSecret != null) {
					writer.write(PSK_POSTFIX);
					writer.write('=');
					writer.write(credentials.pskIdentity);
					writer.write(',');
					writer.write(encode64(credentials.pskSecret));
					writer.write(StringUtil.lineSeparator());
				}
				if (credentials.publicKey != null) {
					writer.write(RPK_POSTFIX);
					writer.write('=');
					writer.write(encode64(credentials.publicKey.getEncoded()));
					writer.write(StringUtil.lineSeparator());
					if (credentials.sign != null) {
						writer.write(SIG_POSTFIX);
						writer.write('=');
						writer.write(encode64(credentials.sign));
						writer.write(StringUtil.lineSeparator());
					}
				}
				if (credentials.x509 != null) {
					try {
						byte[] data = credentials.x509.getEncoded();
						writer.write(X509_POSTFIX);
						writer.write('=');
						writer.write(StringUtil.lineSeparator());
						PemUtil.write(credentials.x509PemTag, data, writer);
					} catch (CertificateEncodingException e) {
					}
				}
				if (credentials.type != Type.DEVICE) {
					writer.write(TYPE_POSTFIX);
					writer.write("=");
					writer.write(credentials.type.getShortName());
					writer.write(StringUtil.lineSeparator());
				}
				if (credentials.ban) {
					writer.write(BAN_POSTFIX);
					writer.write("=1");
					writer.write(StringUtil.lineSeparator());
				}
				if (credentials.customFields != null) {
					for (Map.Entry<String, String> entry : credentials.customFields.entrySet()) {
						writer.write(entry.getKey());
						writer.write("=");
						writer.write(entry.getValue());
						writer.write(StringUtil.lineSeparator());
					}
				}
			}
		}
	}

	@Override
	public int load(Reader reader) throws IOException {
		int entriesBefore = size();
		int entries = 0;
		BufferedReader lineReader = new BufferedReader(reader);
		PemReader pemReader = new PemReader(lineReader);
		String errorMessage = null;
		lock.writeLock().lock();
		try {
			int lineNumber = 0;
			int errors = 0;
			int comments = 0;
			Device.Builder builder = Device.builder();

			String line;
			// readLine() reads the secret into a String,
			// what may be considered to be a weak practice.
			while ((line = lineReader.readLine()) != null) {
				++lineNumber;
				try {
					if (line.isEmpty()) {
						if (builder.name == null) {
							builder.comment = null;
						}
					} else if (line.startsWith("#")) {
						++comments;
						if (builder.name == null) {
							String comment = line.substring(1).trim();
							if (!comment.isEmpty()) {
								builder.comment = comment;
							}
						}
					} else {
						String[] entry = line.split("=", 2);
						if (entry.length == 2) {
							String name = entry[0];
							String[] values = entry[1].split(",");
							String prefix = prefix(name, RPK_POSTFIX);
							if (prefix != name) {
								if (!parseRPK(builder, prefix, values)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							prefix = prefix(name, SIG_POSTFIX);
							if (prefix != name) {
								if (!parseSignature(builder, prefix, values)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							prefix = prefix(name, X509_POSTFIX);
							if (prefix != name) {
								if (values.length != 1 || !match(builder, prefix)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									String tag = pemReader.readNextBegin();
									byte[] data = pemReader.readToEnd();
									if (!parseX509(builder, tag, data)) {
										++errors;
										LOGGER.warn("{}: {} invalid {}!", lineNumber, line, tag);
									}
									lineNumber += pemReader.lines();
								}
								continue;
							}
							prefix = prefix(name, PSK_POSTFIX);
							if (prefix != name) {
								if (!parsePSK(builder, prefix, values)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							prefix = prefix(name, TYPE_POSTFIX);
							if (prefix != name) {
								if (values.length != 1 || !match(builder, prefix)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									Type type = Type.valueOfShortName(values[0]);
									if (type == null) {
										++errors;
										LOGGER.warn("{}: '{}' value not supported!", lineNumber, line);
									} else if (type == Type.WEB) {
										++errors;
										LOGGER.warn("{}: '{}', 'web' not supported!", lineNumber, line);
									} else if (builder.type != null) {
										++errors;
										LOGGER.warn("{}: '{}' invalid line, type already provided!", lineNumber, line);
									} else {
										builder.type = type;
									}
								}
								continue;
							}
							/* deprecated */
							prefix = prefix(name, PROV_POSTFIX);
							if (prefix != name) {
								if (values.length != 1 || !match(builder, prefix)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else if (builder.type != null) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line, type already provided!", lineNumber, line);
								} else {
									builder.type = Type.PROVISIONING;
								}
								continue;
							}
							prefix = prefix(name, BAN_POSTFIX);
							if (prefix != name) {
								if (values.length != 1 || !match(builder, prefix)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									builder.ban = true;
								}
								continue;
							}
							prefix = prefix(name, LABEL_POSTFIX);
							if (prefix != name) {
								if (values.length != 1 || !match(builder, prefix)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									builder.label = decodeText(values[0]);
								}
								continue;
							}
							String customField = isCustomField(name);
							if (customField != null) {
								prefix = prefix(name, customField);
								if (!match(builder, prefix)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									builder.addCustomField(customField, entry[1]);
								}
								continue;
							}
							prefix = prefix(name, GROUP_POSTFIX);
							if (prefix != name || isName(name)) {
								if (builder.name != null) {
									builder.applyDefaults();
									if (entriesBefore > 0 && builder.type != Type.DEVICE) {
										++errors;
										LOGGER.warn("{}: non-device entry is not allowed to be appended!", lineNumber);
										errorMessage = "non-device entry is not allowed to be appended!";
									} else if (add(builder)) {
										++entries;
									}
									builder = Device.builder();
								}
								if (values.length != 1) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									if (prefix == null) {
										builder.name = name;
									} else {
										builder.name = prefix;
									}
									builder.group = decodeText(values[0]);
								}
							}
						} else {
							++errors;
							LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
						}
					}
				} catch (IllegalArgumentException ex) {
					++errors;
					LOGGER.warn("{}: '{}' invalid line!", lineNumber, line, ex);
				}
			}
			if (builder.name != null) {
				builder.applyDefaults();
				if (entriesBefore > 0 && builder.type != Type.DEVICE) {
					++errors;
					LOGGER.warn("{}: non-device entry is not allowed to be appended!", lineNumber);
					errorMessage = "non-device entry is not allowed to be appended!";
				} else if (add(builder)) {
					++entries;
				}
			}
			if (size() == 0 && errors > 0 && lineNumber == comments + errors) {
				LOGGER.warn("read store, only errors, wrong password?");
				SecretUtil.destroy(this);
			}
		} catch (RuntimeException e) {
			LOGGER.warn("read store, unexpected error occurred!", e);
		} catch (IOException e) {
			if (e.getCause() instanceof GeneralSecurityException) {
				LOGGER.warn("read store, wrong password?", e);
				SecretUtil.destroy(this);
			} else {
				throw e;
			}
		} finally {
			lock.writeLock().unlock();
			try {
				lineReader.close();
			} catch (IOException e) {
			}
		}
		if (entriesBefore == 0) {
			LOGGER.info("read {} device credentials.", size());
		} else {
			LOGGER.info("read {} new device credentials (total {}).", entries, size());
		}
		if (errorMessage != null) {
			throw new IllegalArgumentException(errorMessage);
		}
		return entries;
	}

	/**
	 * Parse PreSharedKey credentials.
	 * <p>
	 * The values must contain the identity in the first and the secret in the
	 * second value.
	 * 
	 * @param builder builder with device data
	 * @param name name part of line
	 * @param values split values of line
	 * @return {@code true} if the PreSharedKey credentials are valid,
	 *         {@code false}, otherwise.
	 */
	private boolean parsePSK(Device.Builder builder, String name, String[] values) {
		if (values.length != 2 || !match(builder, name)) {
			return false;
		}
		builder.pskIdentity = decodeText(values[0]);
		builder.pskSecret = binDecodeTextOr64(values[1]);
		return !builder.pskIdentity.isEmpty() && builder.pskSecret.length > 0;
	}

	/**
	 * Parse RawPublicKey.
	 * <p>
	 * The values must contain the public key in the first value.
	 * 
	 * @param builder builder with device data
	 * @param name name part of line
	 * @param values split values of line
	 * @return {@code true} if the RawPublicKey is valid, {@code false},
	 *         otherwise.
	 */
	private boolean parseRPK(Device.Builder builder, String name, String[] values) {
		if (values.length != 1 || !match(builder, name)) {
			return false;
		}
		byte[] publicKey = binDecodeTextOr64(values[0]);
		Throwable error = null;
		try {
			builder.publicKey = Asn1DerDecoder.readSubjectPublicKey(publicKey);
			return true;
		} catch (GeneralSecurityException e) {
			error = e;
		} catch (IllegalArgumentException e) {
			error = e;
		}
		if (error != null) {
			if (publicKey.length == 64) {
				publicKey = Bytes.concatenate(ECC_SECP256R1_HEADER, publicKey);
				try {
					builder.publicKey = Asn1DerDecoder.readSubjectPublicKey(publicKey);
					return true;
				} catch (GeneralSecurityException i) {
				} catch (IllegalArgumentException e) {
				}
			}
			LOGGER.warn("RPK:", error);
		}
		return false;
	}

	/**
	 * Parse Signature.
	 * <p>
	 * The values must contain the public key in the first value.
	 * 
	 * @param builder builder with device data
	 * @param name name part of line
	 * @param values split values of line
	 * @return {@code true} if the RawPublicKey is valid, {@code false},
	 *         otherwise.
	 */
	private boolean parseSignature(Device.Builder builder, String name, String[] values) {
		if (values.length != 1 || !match(builder, name)) {
			return false;
		}
		builder.sign = binDecodeTextOr64(values[0]);
		return true;
	}

	private boolean parseX509(Device.Builder builder, String tag, byte[] value) {
		if (value == null) {
			LOGGER.warn("X509: {} missing certificate data", tag);
		}
		try {
			CertificateFactory factory = CERTIFICATE_FACTORY.currentWithCause();
			Certificate certificate = factory.generateCertificate(new ByteArrayInputStream(value));
			if (certificate instanceof X509Certificate) {
				builder.x509 = (X509Certificate) certificate;
				builder.x509PemTag = tag;
				return true;
			}
			LOGGER.warn("X509: {} is no X509 certificate", certificate.getType());
		} catch (GeneralSecurityException e) {
			LOGGER.warn("X509:", e);
		}
		return false;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		map.clear();
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	/**
	 * Encode byte array in base 64.
	 * 
	 * @param value byte array
	 * @return base 64
	 */
	private static String encode64(byte[] value) {
		return StringUtil.byteArrayToBase64(value);
	}

	/**
	 * Decode value to byte array.
	 * <p>
	 * A plain text value must be in single- ({@code '}) or double-quotes
	 * ({@code "}). A hexadecimal value starts with {@code :0x}. Other values
	 * are considered to be base 64 encoded.
	 * 
	 * @param value value to be decoded
	 * @return byte array
	 */
	private static byte[] binDecodeTextOr64(String value) {
		if (value.isEmpty()) {
			return Bytes.EMPTY;
		}
		char c = value.charAt(0);
		if (c == '\'' || c == '"') {
			if (value.length() > 2) {
				int end = value.length() - 1;
				char e = value.charAt(end);
				if (e == c) {
					value = value.substring(1, end);
					return value.getBytes(StandardCharsets.UTF_8);
				}
			}
		} else if (c == ':') {
			if (value.startsWith(":0x")) {
				return StringUtil.hex2ByteArray(value.substring(3));
			}
		}
		return StringUtil.base64ToByteArray(value);
	}

	/**
	 * Decode text value.
	 * <p>
	 * If the value is in single- ({@code '}) or double-quotes ({@code "}),
	 * these are removed.
	 * 
	 * @param value value to be decoded
	 * @return text value
	 */
	private static String decodeText(String value) {
		if (!value.isEmpty()) {
			char c = value.charAt(0);
			if (value.length() > 2 && (c == '\'' || c == '"')) {
				int end = value.length() - 1;
				char e = value.charAt(end);
				if (e == c) {
					value = value.substring(1, end);
				}
			}
		}
		return value;
	}

	@Override
	public DeviceParser create() {
		return new DeviceParser(caseSensitiveNames, replace, customFields);
	}

}
