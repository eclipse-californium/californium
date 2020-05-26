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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.IDefaultValueProvider;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.Option;

/**
 * Connector command line config
 * 
 * @since 2.3
 */
public class ConnectorConfig implements Cloneable {

	/**
	 * Width for printing to the comand line console.
	 */
	public static final int MAX_WIDTH = 60;

	/**
	 * Authentication modes.
	 */
	public static enum AuthenticationMode {
		NONE, PSK, RPK, X509, ECDHE_PSK
	}

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
	 * X509 credentials loaded from store.
	 */
	@Option(names = { "-c",
			"--cert" }, description = "certificate store. Format keystore#hexstorepwd#hexkeypwd#alias or keystore.pem")
	public SslContextUtil.Credentials credentials;

	/**
	 * X509 trusts loaded from store.
	 */
	@Option(names = { "-t",
			"--trusts" }, description = "trusted certificates. Format keystore#hexstorepwd#alias or truststore.pem")
	public Certificate[] trusts;

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
			if (credentials != null) {
				authenticationModes.add(AuthenticationMode.X509);
			}
		}
		if (cipherHelpRequested || authHelpRequested) {
			helpRequested = true;
		}
		networkConfig = NetworkConfig.createWithFile(networkConfigFile, networkConfigHeader,
				networkConfigDefaultHandler);
	}

	/**
	 * Defaultvalue provider for --netconfig.
	 */
	protected IDefaultValueProvider defaultValueProvider = new IDefaultValueProvider() {

		@Override
		public String defaultValue(ArgSpec argSpec) throws Exception {
			if (argSpec instanceof OptionSpec) {
				OptionSpec optionSpec = (OptionSpec) argSpec;
				if ("--netconfig".equals(optionSpec.longestName())) {
					return networkConfigFile.getPath();
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
	 * @param file filename of credentials store.
	 * @return psk credentials store
	 */
	public static PskCredentialStore loadPskCredentials(String file) {
		Properties credentials = new Properties();
		try (FileReader reader = new FileReader(file)) {
			credentials.load(reader);
			Set<Object> keys = credentials.keySet();
			SortedSet<String> sortedKeys = new TreeSet<>();
			for (Object key : keys) {
				if (key instanceof String) {
					sortedKeys.add((String) key);
				}
			}
			if (!sortedKeys.isEmpty()) {
				PskCredentialStore pskCredentials = new PskCredentialStore();
				for (String key : sortedKeys) {
					String secret = credentials.getProperty(key);
					byte[] secretBytes = StringUtil.base64ToByteArray(secret);
					pskCredentials.add(key, secretBytes);
				}
				return pskCredentials;
			}
		} catch (IOException e) {
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
		 * @param secret   secret key
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
