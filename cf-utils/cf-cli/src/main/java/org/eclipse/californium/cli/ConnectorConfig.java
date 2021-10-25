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

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.SslContextUtil.IncompleteCredentialsException;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
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
	 * Dummy PSK identity for sandbox "californium.eclipseprojects.io". All
	 * identities, starting with this prefix, share the "not" secret
	 * {@link #PSK_SECRET}.
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
	 * Header for new configuration files.
	 */
	public String configurationHeader = Configuration.DEFAULT_HEADER;
	/**
	 * Default values provider for new configuration files.
	 */
	public DefinitionsProvider customConfigurationDefaultsProvider;
	/**
	 * Configuration.
	 */
	public Configuration configuration;

	/**
	 * Filename for configuration.
	 */
	@Option(names = { "-C",
			"--config" }, paramLabel = "FILE", description = "configuration file. Default ${DEFAULT-VALUE}.")
	public File configurationFile;

	@Option(names = "--tag", description = "use logging tag.")
	public String tag;

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
		 * X509/RPK credentials loaded from store.
		 * 
		 * @see #defaults()
		 */
		public Credentials credentials;

		/**
		 * X509/RPK Identity loaded from store.
		 */
		@ArgGroup(exclusive = false)
		public Identity identity;

		/**
		 * X509 trusts all.
		 */
		@Option(names = "--anonymous", description = "anonymous, no certificate.")
		public boolean anonymous;

		public void defaults() {
			if (!anonymous) {
				if (identity.certificate == null) {
					LOGGER.info("x509 identity from private key.");
					credentials = identity.privateKey;
				} else if (identity.certificate.getPrivateKey() == null) {
					LOGGER.info("x509 identity from certificate and private key.");
					credentials = new Credentials(identity.privateKey.getPrivateKey(),
							identity.certificate.getPublicKey(), identity.certificate.getCertificateChain());
				} else {
					LOGGER.info("x509 identity from certificate.");
					credentials = identity.certificate;
				}
				if (credentials.getPrivateKey() == null) {
					throw new IllegalArgumentException("Missing private key!");
				}
				if (credentials.getPublicKey() == null) {
					throw new IllegalArgumentException("Missing public key or certificate!");
				}
			}
		}
	}

	/**
	 * X509 identity.
	 *
	 * If the private key is stored separately, it's loaded by different option
	 * {@link Identity#privateKey} and included in the
	 * {@link Authentication#credentials} calling {@link #defaults()}.
	 * 
	 * @since 3.0
	 */
	public static class Identity {

		/**
		 * X509 credentials loaded from store and/or the {@link #privateKey}
		 * option.
		 * 
		 * If provided, {@link ConnectorConfig#defaults()} prepares
		 * {@link Authentication#credentials} with the data from this.
		 */
		@Option(names = { "-c",
				"--cert" }, description = "certificate store. Format keystore#hexstorepwd#hexkeypwd#alias or keystore.pem")
		public Credentials certificate;

		/**
		 * X509 private key loaded from store.
		 * 
		 * If provided, {@link ConnectorConfig#defaults()} prepares
		 * {@link Authentication#credentials} with the keys from this.
		 */
		@Option(names = "--private-key", description = "private key store. Format keystore#hexstorepwd#hexkeypwd#alias or keystore.pem")
		public Credentials privateKey;

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
		 * Secret key in UTF-8.
		 */
		@Option(names = { "-s", "--secret" }, description = "PSK secret, UTF-8")
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

		/**
		 * Byte encoded secret key.
		 * 
		 * @return secret key in bytes encoded
		 * @since 3.0
		 */
		public byte[] toKey() {
			if (text != null && text.length() > 0) {
				return text.getBytes();
			} else if (hex != null && hex.length() > 0) {
				return StringUtil.hex2ByteArray(hex);
			} else if (base64 != null && base64.length() > 0) {
				return StringUtil.base64ToByteArray(base64);
			} else {
				return null;
			}
		}

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
				secret = new Secret();
				secret.hex = StringUtil.byteArray2Hex(pskStore.getSecrets(pskIndex));
				identity = pskStore.getIdentity(pskIndex);
			}
		}
		if (secret != null && secretKey == null) {
			secretKey = secret.toKey();
		}
		if (authenticationModes == null) {
			authenticationModes = new ArrayList<ConnectorConfig.AuthenticationMode>();
		}
		if (authenticationModes.isEmpty()) {
			defaultAuthenticationModes();
		}
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
			if (!authentication.anonymous && authentication.identity == null) {
				try {
					authentication.identity = new Identity();
					authentication.identity.certificate = SslContextUtil.loadCredentials(defaultEcCredentials);
					LOGGER.info("x509 default identity.");
				} catch (GeneralSecurityException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			authentication.defaults();
		}
		if (cipherHelpRequested || authHelpRequested) {
			helpRequested = true;
		}
		CoapConfig.register();
		UdpConfig.register();
		DtlsConfig.register();
		DefinitionsProvider provider = new DefinitionsProvider() {
			@Override
			public void applyDefinitions(Configuration config) {
				config.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
				config.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
				if (customConfigurationDefaultsProvider != null) {
					customConfigurationDefaultsProvider.applyDefinitions(config);
				}
			}
		};
		configuration = Configuration.createWithFile(configurationFile, configurationHeader, provider);
	}

	protected void defaultAuthenticationModes() {
		if (identity != null || secretKey != null || pskStore != null) {
			authenticationModes.add(AuthenticationMode.PSK);
		}
		if (authentication != null) {
			authenticationModes.add(AuthenticationMode.X509);
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
				if ("--config".equals(optionSpec.longestName())) {
					if (configurationFile != null) {
						return configurationFile.getPath();
					} else {
						return Configuration.DEFAULT_FILE_NAME;
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
			try {
				return SslContextUtil.loadCredentials(value);
			} catch (IncompleteCredentialsException ex) {
				return ex.getIncompleteCredentials();
			}
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
