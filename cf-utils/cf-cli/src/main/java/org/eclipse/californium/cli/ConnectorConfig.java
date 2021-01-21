/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cli;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.IDefaultValueProvider;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.Option;

/**
 * Connector command line configuration.
 * 
 * @since 2.3
 */
public class ConnectorConfig implements Cloneable {

	protected static final Logger LOGGER = LoggerFactory.getLogger(ConnectorConfig.class);

	/**
	 * Width for printing to the command line console.
	 */
	public static final int MAX_WIDTH = 60;
	/**
	 * Dummy PSK identity for sandbox "californium.eclipseprojects.io". All identities,
	 * starting with this prefix, share the "not" secret {@link #PSK_SECRET}.
	 */
	public static final String PSK_IDENTITY_PREFIX = "cali.";
	/**
	 * Dummy secret for sandbox "californium.eclipseprojects.io".
	 */
	public static final SecretKey PSK_SECRET = SecretUtil.create(".fornium".getBytes(), "PSK");

	/**
	 * Authentication modes.
	 */
	public static enum AuthenticationMode {
		NONE, PSK, RPK, X509, ECDHE_PSK
	}

	/**
	 * Default Ec credentials. Load Californium's client credentials from demo
	 * keystore.
	 * 
	 * @since 2.4
	 */
	public String defaultEcCredentials = createDescriptor("certs/keyStore.jks", "endPass".toCharArray(),
			"endPass".toCharArray(), "client");
	/**
	 * Default Ec trusts. Load Californium's trusted certificates from demo
	 * truststore.
	 * 
	 * @since 2.4
	 */
	public String defaultEcTrusts = createDescriptor("certs/trustStore.jks", "rootPass".toCharArray(), null, null);

	/**
	 * Header for new network configuration files.
	 */
	public String networkConfigHeader = NetworkConfig.DEFAULT_HEADER;
	/**
	 * Default values handler for for new network configuration files.
	 */
	public NetworkConfigDefaultHandler networkConfigDefaultHandler;
	/**
	 * Network Configuration.
	 */
	public NetworkConfig networkConfig;

	/**
	 * Filename for network configuration.
	 */
	@Option(names = { "-N",
			"--netconfig" }, paramLabel = "FILE", description = "network config file. Default ${DEFAULT-VALUE}.")
	public File networkConfigFile;

	/**
	 * Use record-size-limit for DTLS handshake.
	 */
	@Option(names = "--record-size", description = "record size limit.")
	public Integer recordSizeLimit;

	/**
	 * Use MTU.
	 */
	@Option(names = "--mtu", description = "MTU.")
	public Integer mtu;

	/**
	 * Use CID .
	 */
	@Option(names = "--cid-length", description = "Use cid with length. 0 to support cid only without using it.")
	public Integer cidLength;

	/**
	 * Authentication.
	 */
	@ArgGroup(exclusive = true)
	public Authentication authentication;

	public static class Authentication {

		/**
		 * X509 credentials loaded from store.
		 */
		@Option(names = { "-c",
				"--cert" }, description = "certificate store. Format keystore#hexstorepwd#hexkeypwd#alias or keystore.pem")
		public SslContextUtil.Credentials credentials;

		/**
		 * X509 trusts all.
		 */
		@Option(names = "--anonymous", description = "anonymous, no certificate.")
		public boolean anonymous;

	}

	/**
	 * Trusts.
	 */
	@ArgGroup(exclusive = true)
	public Trust trust;

	public static class Trust {

		/**
		 * X509 trusts loaded from store.
		 */
		@Option(names = { "-t",
				"--trusts" }, description = "trusted certificates. Format keystore#hexstorepwd#alias or truststore.pem")
		public Certificate[] trusts;

		/**
		 * X509 trusts all.
		 */
		@Option(names = "--trust-all", description = "trust all valid certificates.")
		public boolean trustall;
	}

	/**
	 * PSK store index.
	 * 
	 * @since 2.4
	 */
	@Option(names = "--psk-index", description = "Index of identity in PSK store. Starts at 0.")
	public Integer pskIndex;

	/**
	 * PSK store file. Lines in format:
	 * 
	 * <pre>
	 * identity = secret - key(base64)
	 * </pre>
	 */
	@Option(names = "--psk-store", description = "PSK store. Lines format: identity=secretkey (in base64).")
	public PskCredentialStore pskStore;

	/**
	 * List of cipher suites (ordered by preference).
	 */
	@Option(names = "--cipher", split = ":", description = "use ciphersuites. '--help-cipher' to list available cipher suites.")
	public List<CipherSuite> cipherSuites;

	/**
	 * List of authentication modes (ordered by preference).
	 */
	@Option(names = { "-a",
			"--auth" }, split = ":", description = "use authentikation modes. '--help-auth' to list available authentication modes.")
	public List<AuthenticationMode> authenticationModes;

	/**
	 * Identity for PSK.
	 */
	@Option(names = { "-i", "--identity" }, description = "PSK identity")
	public String identity;

	/**
	 * Secret key for PSK.
	 */
	@ArgGroup(exclusive = true)
	public Secret secret;

	public static class Secret {

		/**
		 * Secret key in utf-8.
		 */
		@Option(names = { "-s", "--secret" }, description = "PSK secret, utf8")
		public String text;

		/**
		 * Secret key in hexadecimal.
		 */
		@Option(names = "--secrethex", description = "PSK secret, hexadecimal")
		public String hex;

		/**
		 * Secret key in base64.
		 */
		@Option(names = "--secret64", description = "PSK secret, base64")
		public String base64;

	}

	@Option(names = { "-v", "--verbose" }, negatable = true, description = "verbose")
	public boolean verbose;

	@Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
	public boolean helpRequested;

	@Option(names = "--help-cipher", description = "display a help message for cipher suites")
	public boolean cipherHelpRequested;

	@Option(names = "--help-auth", description = "display a help message for authentication modes")
	public boolean authHelpRequested;

	@Option(names = { "-V", "--version" }, versionHelp = true, description = "display version info")
	boolean versionInfoRequested;

	/**
	 * PSK secret key in bytes.
	 */
	public byte[] secretKey;

	/**
	 * Register converter and providers.
	 * 
	 * @param cmd command line to register to.
	 */
	public void register(CommandLine cmd) {
		cmd.registerConverter(SslContextUtil.Credentials.class, credentialsReader);
		cmd.registerConverter(Certificate[].class, trustsReader);
		cmd.registerConverter(PskCredentialStore.class, pskCredentialsStoreReader);
		cmd.setDefaultValueProvider(defaultValueProvider);
	}

	/**
	 * Setup dependent defaults.
	 */
	public void defaults() {
		if (pskStore != null) {
			if (identity != null || secret != null) {
				System.err.println("Use either '--psk-store' or single psk credentials!");
				helpRequested = true;
			}
			if (pskIndex != null) {
				secret = new ConnectorConfig.Secret();
				secret.hex = StringUtil.byteArray2Hex(pskStore.getSecrets(pskIndex));
				identity = pskStore.getIdentity(pskIndex);
			}
		}
		if (secret != null && secretKey == null) {
			if (secret.text != null) {
				secretKey = secret.text.getBytes();
			} else if (secret.hex != null) {
				secretKey = StringUtil.hex2ByteArray(secret.hex);
			} else if (secret.base64 != null) {
				secretKey = StringUtil.base64ToByteArray(secret.base64);
			}
		}
		if (authenticationModes == null) {
			authenticationModes = new ArrayList<ConnectorConfig.AuthenticationMode>();
		}
		if (authenticationModes.isEmpty()) {
			if (identity != null || secretKey != null || pskStore != null) {
				authenticationModes.add(AuthenticationMode.PSK);
			}
			if (authentication != null) {
				authenticationModes.add(AuthenticationMode.X509);
			}
		} else {
			if (authenticationModes.contains(AuthenticationMode.X509)
					|| authenticationModes.contains(AuthenticationMode.RPK)) {
				if (trust == null) {
					trust = new Trust();
				}
				if (trust.trusts == null) {
					if (trust.trustall) {
						trust.trusts = new Certificate[0];
					} else {
						try {
							trust.trusts = SslContextUtil.loadTrustedCertificates(defaultEcTrusts);
						} catch (GeneralSecurityException e) {
							e.printStackTrace();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
				if (authentication == null) {
					authentication = new Authentication();
				}
				if (!authentication.anonymous && authentication.credentials == null) {
					try {
						authentication.credentials = SslContextUtil.loadCredentials(defaultEcCredentials);
					} catch (GeneralSecurityException e) {
						e.printStackTrace();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}
		if (cipherHelpRequested || authHelpRequested) {
			helpRequested = true;
		}
		networkConfig = NetworkConfig.createWithFile(networkConfigFile, networkConfigHeader,
				networkConfigDefaultHandler);

		int extra = RecordLayer.IPV4_HEADER_LENGTH + 20 - Record.DTLS_HANDSHAKE_HEADER_LENGTH
				- CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8.getMaxCiphertextExpansion();
		if (mtu != null && recordSizeLimit == null) {
			recordSizeLimit = mtu - extra;
		} else if (mtu == null && recordSizeLimit != null) {
			mtu = recordSizeLimit + extra;
		}
	}

	public static String createDescriptor(String store, char[] storePass, char[] keyPass, String alias) {
		StringBuilder descriptor = new StringBuilder(SslContextUtil.CLASSPATH_SCHEME);
		descriptor.append(store).append('#');
		if (storePass != null) {
			descriptor.append(StringUtil.charArray2hex(storePass)).append('#');
		}
		if (keyPass != null) {
			descriptor.append(StringUtil.charArray2hex(keyPass)).append('#');
		}
		if (alias != null) {
			descriptor.append(alias);
		}
		return descriptor.toString();
	}

	/**
	 * Default-value provider for --netconfig.
	 */
	protected IDefaultValueProvider defaultValueProvider = new IDefaultValueProvider() {

		@Override
		public String defaultValue(ArgSpec argSpec) throws Exception {
			if (argSpec instanceof OptionSpec) {
				OptionSpec optionSpec = (OptionSpec) argSpec;
				if ("--netconfig".equals(optionSpec.longestName())) {
					if (networkConfigFile != null) {
						return networkConfigFile.getPath();
					} else {
						return NetworkConfig.DEFAULT_FILE_NAME;
					}
				}
			}
			return null;
		}

	};

	/**
	 * Truststore reader.
	 */
	private static ITypeConverter<Certificate[]> trustsReader = new ITypeConverter<Certificate[]>() {

		@Override
		public Certificate[] convert(String value) throws Exception {
			return SslContextUtil.loadTrustedCertificates(value);
		}

	};

	/**
	 * X509 credentials reader.
	 */
	private static ITypeConverter<SslContextUtil.Credentials> credentialsReader = new ITypeConverter<SslContextUtil.Credentials>() {

		@Override
		public SslContextUtil.Credentials convert(String value) throws Exception {
			return SslContextUtil.loadCredentials(value);
		}

	};

	/**
	 * PSK credentials store reader-
	 */
	private static ITypeConverter<PskCredentialStore> pskCredentialsStoreReader = new ITypeConverter<PskCredentialStore>() {

		@Override
		public PskCredentialStore convert(String value) throws Exception {
			return loadPskCredentials(value);
		}

	};

	/**
	 * Load PSK credentials store.
	 * 
	 * Lines in format:
	 * 
	 * <pre>
	 * identity = secret - key(base64)
	 * </pre>
	 * 
	 * The identity must not contain a {@code =}! The created psk credentials
	 * store keeps the order of the credentials in the file. Index {@code 0}
	 * will contain the credential of the first line.
	 * 
	 * @param file filename of credentials store.
	 * @return psk credentials store
	 */
	public static PskCredentialStore loadPskCredentials(String file) {
		boolean error = false;
		BufferedReader lineReader = null;
		try (FileReader reader = new FileReader(file)) {
			PskCredentialStore pskCredentials = new PskCredentialStore();
			int lineNumber = 0;
			String line;
			lineReader = new BufferedReader(reader);
			while ((line = lineReader.readLine()) != null) {
				++lineNumber;
				String[] entry = line.split("=", 2);
				if (entry.length == 2) {
					byte[] secretBytes = StringUtil.base64ToByteArray(entry[1]);
					pskCredentials.add(entry[0], secretBytes);
				} else {
					error = true;
					LOGGER.error("{}: '{}' invalid psk-line!", lineNumber, line);
				}
			}
			if (!error) {
				return pskCredentials;
			}
		} catch (IOException e) {
		} finally {
			if (lineReader != null) {
				try {
					lineReader.close();
				} catch (IOException e) {
				}
			}
		}
		return null;
	}

	/**
	 * PSK credentials store.
	 */
	public static class PskCredentialStore {

		/**
		 * Identities.
		 */
		private List<String> identities = new ArrayList<String>();
		/**
		 * secret keys.
		 */
		private List<byte[]> secrets = new ArrayList<byte[]>();

		/**
		 * Add entry.
		 * 
		 * @param identity identity
		 * @param secret secret key
		 */
		private void add(String identity, byte[] secret) {
			identities.add(identity);
			secrets.add(secret);
		}

		/**
		 * Get identity.
		 * 
		 * @param index index of identity.
		 * @return identity at provided index
		 */
		public String getIdentity(int index) {
			return identities.get(index);
		}

		/**
		 * Get secret key.
		 * 
		 * @param index index of key
		 * @return secret key at provided index
		 */
		public byte[] getSecrets(int index) {
			return secrets.get(index);
		}

		/**
		 * Size.
		 * 
		 * @return number of identity and key pairs.
		 */
		public int size() {
			return secrets.size();
		}
	}
}
