/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation. 
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Utility logging function of TLS/SSL context.
 */
public class SslContextLoggingUtil {

	private static final Logger LOG = Logger.getLogger(SslContextLoggingUtil.class.getName());
	/**
	 * Logging level for key manager.
	 * 
	 * @see #logging(KeyManager[])
	 */
	private static final Level KEY_MANAGER_DETAIL_LEVEL = Level.INFO;
	/**
	 * Logging level for trust manager.
	 * 
	 * @see #logging(TrustManager[])
	 */
	private static final Level TRUST_MANAGER_DETAIL_LEVEL = Level.INFO;

	/**
	 * EOL used for multi-line logging.
	 * 
	 * @see #list(Object[])
	 * @see #list(X509Certificate[])
	 */
	private static final String EOL = System.getProperty("line.separator", null);

	/**
	 * Line header used for multi-line logging.
	 * 
	 * @see #list(Object[])
	 * @see #list(X509Certificate[])
	 */
	private static final String HEADER = "   ";
	/**
	 * ID to identify logging instances.
	 */
	private static int loggingID = 0;

	/**
	 * Get next logger id. Used to distinguish loggers.
	 * 
	 * @return next logging id
	 */
	private static synchronized int nextLoggingID() {
		return ++loggingID;
	}

	/**
	 * Convert array of objects into String. Used for logging.
	 * 
	 * @param objects array of object.
	 * @return string representing the objects.
	 */
	private static String list(Object[] objects) {
		StringBuffer line = new StringBuffer("[");
		if (null == objects) {
			line.append("null ");
		} else {
			final String eol = 3 < objects.length ? EOL : null;
			if (null != eol) {
				line.append(eol);
			}
			for (Object obj : objects) {
				String text = "null";
				if (obj instanceof X509Certificate) {
					text = ((X509Certificate) obj).getSubjectX500Principal().getName();
				} else if (null != obj) {
					text = obj.toString();
				}
				if (null == eol) {
					line.append('"').append(text).append("\" ");
				} else {
					line.append(HEADER).append(text).append(eol);
				}
			}
		}
		line.append(']');
		return line.toString();
	}

	/**
	 * Create a supplier to be used for logging.
	 * 
	 * @param header header for logging
	 * @param certificates certificates to be logged.
	 * @return supplier
	 */
	public static Object supplier(final String header, final Certificate[] certificates) {

		return new Object() {

			@Override
			public String toString() {
				return header + " " + list(certificates);
			}

		};
	}

	/**
	 * Create logging key manager, if logging level is at least
	 * {@link #KEY_MANAGER_DETAIL_LEVEL}.
	 * 
	 * @param managers key manager to be wrapped for logging
	 * @param label label for logger
	 * @return array with logging key manager or the provided key manager
	 */
	public static KeyManager[] logging(KeyManager[] managers, String label) {
		if (LOG.isLoggable(KEY_MANAGER_DETAIL_LEVEL)) {
			for (int index = 0; index < managers.length; ++index) {
				if (managers[index] instanceof X509ExtendedKeyManager) {
					managers[index] = new LoggingX509ExtendedKeyManager((X509ExtendedKeyManager) managers[index], label);
				}
			}
		}
		return managers;
	}

	/**
	 * Create logging trust manager, if logging level is at least
	 * {@link #TRUST_MANAGER_DETAIL_LEVEL}.
	 * 
	 * @param managers trust manager to be wrapped for logging
	 * @param label label for logger
	 * @return array with logging trust manager or the provided trust manager
	 */
	public static TrustManager[] logging(TrustManager[] managers, String label) {
		if (LOG.isLoggable(TRUST_MANAGER_DETAIL_LEVEL)) {
			for (int index = 0; index < managers.length; ++index) {
				if (managers[index] instanceof X509ExtendedTrustManager) {
					managers[index] = new LoggingX509ExtendedTrustManager((X509ExtendedTrustManager) managers[index],
							label);
				}
			}
		}
		return managers;
	}

	/**
	 * Logging X509ExtendedKeyManager.
	 * 
	 * @see #LOG_KEYS
	 */
	private static class LoggingX509ExtendedKeyManager extends X509ExtendedKeyManager {

		/**
		 * Origin X509ExtendedKeyManager.
		 */
		private final X509ExtendedKeyManager manager;

		/**
		 * Distinguishing ID for loggers.
		 */
		private final String id;

		/**
		 * Create instance of logging X509ExtendedKeyManager.
		 * 
		 * @param manager origin manager. Calls are delegated to this manager.
		 * @param label label for logger. If null, only
		 *            {@link SslContextLoggingUtil#nextLoggingID()} is used.
		 */
		public LoggingX509ExtendedKeyManager(X509ExtendedKeyManager manager, String label) {
			this.manager = manager;
			String id = Integer.toString(nextLoggingID());
			if (null == label || label.isEmpty()) {
				this.id = id;
			} else {
				this.id = label + "-" + id;
			}
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "LoggingX509ExtendedKeyManager[ID {0}] {1}", new Object[] { this.id,
					manager });
		}

		@Override
		public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
			String alias = manager.chooseEngineClientAlias(keyType, issuers, engine);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] key type {1}, issuer {2}, {3} => {4}", new Object[] { id,
					list(keyType), list(issuers), engine, alias });
			return alias;
		}

		@Override
		public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
			String alias = manager.chooseEngineServerAlias(keyType, issuers, engine);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] key type {1}, issuer {2}, {3} => {4}", new Object[] { id,
					keyType, list(issuers), engine, alias });
			return alias;
		}

		@Override
		public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
			String alias = manager.chooseClientAlias(keyType, issuers, socket);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] key type {1}, issuer {2}, {3} => {4}", new Object[] { id,
					list(keyType), list(issuers), socket, alias });
			return alias;
		}

		@Override
		public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
			String alias = manager.chooseServerAlias(keyType, issuers, socket);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] key type {1}, issuer {2}, {3} => {4}", new Object[] { id,
					keyType, list(issuers), socket, alias });
			return alias;
		}

		@Override
		public X509Certificate[] getCertificateChain(String alias) {
			X509Certificate[] chain = manager.getCertificateChain(alias);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] alias {1} => {2}", new Object[] { id, alias, list(chain) });
			return chain;
		}

		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			String[] alias = manager.getClientAliases(keyType, issuers);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] key type {1}, issuer {2} => {3}", new Object[] { id, keyType,
					list(issuers), list(alias) });
			return alias;
		}

		@Override
		public PrivateKey getPrivateKey(String alias) {
			PrivateKey key = manager.getPrivateKey(alias);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] alias {1} => {2}", new Object[] { id, alias, key });
			return key;
		}

		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			String[] alias = manager.getServerAliases(keyType, issuers);
			LOG.log(KEY_MANAGER_DETAIL_LEVEL, "[ID {0}] key type {1}, issuer {2} => {3}", new Object[] { id, keyType,
					list(issuers), list(alias) });
			return alias;
		}
	}

	/**
	 * Logging X509ExtendedTrustManager.
	 * 
	 * @see #LOG_TRUSTS
	 */
	private static class LoggingX509ExtendedTrustManager extends X509ExtendedTrustManager {

		/**
		 * Origin X509ExtendedTrustManager.
		 */
		private final X509ExtendedTrustManager manager;

		/**
		 * Distinguishing ID for loggers.
		 */
		private final String id;

		/**
		 * Create instance of logging X509ExtendedTrustManager.
		 * 
		 * @param manager origin trust manager. Calls are delegated to this
		 *            manager.
		 * @param label label for logger. If null, only
		 *            {@link SslContextLoggingUtil#nextLoggingID()} is used.
		 */
		public LoggingX509ExtendedTrustManager(X509ExtendedTrustManager manager, String label) {
			this.manager = manager;
			String id = Integer.toString(nextLoggingID());
			if (null == label || label.isEmpty()) {
				this.id = id;
			} else {
				this.id = label + "-" + id;
			}
			LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "LoggingX509ExtendedTrustManager[ID {0}] {1}", new Object[] { this.id,
					manager });
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] {1} {2}", new Object[] { id, list(chain), authType });
			try {
				manager.checkClientTrusted(chain, authType);
			} catch (CertificateException e) {
				LOG.log(Level.SEVERE, "[ID {0}] failed {1}", new Object[] { id, e });
				throw e;
			}
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] {1} {2}", new Object[] { id, list(chain), authType });
			try {
				manager.checkServerTrusted(chain, authType);
			} catch (CertificateException e) {
				LOG.log(Level.SEVERE, "[ID {0}] failed {1}", new Object[] { id, e });
				throw e;
			}
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			X509Certificate[] issuers = manager.getAcceptedIssuers();
			if (null == issuers) {
				LOG.log(Level.SEVERE, "[ID {0}] issuers missing", id);
			} else if (0 == issuers.length) {
				LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] no issuers", id);
			} else {
				LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] => {1}", new Object[] { id, list(issuers) });
			}
			return issuers;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] {1} {2} {3}", new Object[] { id, list(chain), authType,
					socket });
			try {
				manager.checkClientTrusted(chain, authType, socket);
			} catch (CertificateException e) {
				LOG.log(Level.SEVERE, "[ID {0}] failed {1}", new Object[] { id, e });
				throw e;
			}
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] {1} {2} {3}", new Object[] { id, list(chain), authType,
					engine });
			try {
				manager.checkClientTrusted(chain, authType, engine);
			} catch (CertificateException e) {
				LOG.log(Level.SEVERE, "[ID {0}] failed {1}", new Object[] { id, e });
				throw e;
			}
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
			LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] {1} {2} {3}", new Object[] { id, list(chain), authType,
					socket });
			try {
				manager.checkServerTrusted(chain, authType, socket);
			} catch (CertificateException e) {
				LOG.log(Level.SEVERE, "[ID {0}] failed {1}", new Object[] { id, e });
				throw e;
			}
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
			LOG.log(TRUST_MANAGER_DETAIL_LEVEL, "[ID {0}] {1} {2} {3}", new Object[] { id, list(chain), authType,
					engine });
			try {
				manager.checkServerTrusted(chain, authType, engine);
			} catch (CertificateException e) {
				LOG.log(Level.SEVERE, "[ID {0}] failed {1}", new Object[] { id, e });
				throw e;
			}
		}
	}
}
