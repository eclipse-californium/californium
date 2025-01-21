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
package org.eclipse.californium.cloud.s3.util;

import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.SecretKey;

import org.eclipse.californium.cloud.s3.forward.BasicHttpForwardConfiguration;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfiguration;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfigurationProvider;
import org.eclipse.californium.cloud.util.DeviceIdentifier;
import org.eclipse.californium.cloud.util.DeviceManager;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.DeviceParser.Device;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.cloud.util.ResultConsumer;
import org.eclipse.californium.cloud.util.ResultConsumer.ResultCode;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ApplicationPrincipal;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Domain device manager.
 * <p>
 * Organize devices into separate domains.
 * 
 * @since 3.12
 */
public class DomainDeviceManager extends DeviceManager
		implements DeviceGroupProvider, DomainPrincipalInfoProvider, HttpForwardConfigurationProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(DomainDeviceManager.class);

	/**
	 * Default device domain, if domain name is not available in additional
	 * info.
	 */
	public static final String DEFAULT_DOMAIN = "default";

	/**
	 * Map of domains.
	 */
	private final ConcurrentMap<String, ResourceStore<DeviceParser>> domains;

	/**
	 * Creates device manager.
	 * 
	 * @param domains domains of device stores with PreSharedKey and
	 *            RawPublicKey credentials
	 * @param credentials server's credentials for DTLS 1.2 certificate based
	 *            authentication
	 * @param addTimeoutMillis timeout in milliseconds configuration values
	 * @throws NullPointerException if domains is {@code null}
	 * @since 4.0 (added parameter addTimeoutMillis)
	 */
	public DomainDeviceManager(ConcurrentMap<String, ResourceStore<DeviceParser>> domains, Credentials credentials,
			long addTimeoutMillis) {
		super(null, credentials, addTimeoutMillis);
		if (domains == null) {
			throw new NullPointerException("domains must not be null!");
		}
		this.domains = domains;
	}

	@Override
	public void add(PrincipalInfo info, long time, String data, final ResultConsumer response) {
		if (!(info instanceof DomainPrincipalInfo)) {
			response.results(ResultCode.SERVER_ERROR, "no DomainDeviceInfo.");
			return;
		}
		final String domain = ((DomainPrincipalInfo) info).domain;
		ResourceStore<DeviceParser> store = domains.get(domain);
		if (store == null) {
			response.results(ResultCode.SERVER_ERROR, "Domain " + domain + " not available.");
			return;
		}
		add(store, info, time, data, new ResultConsumer() {

			@Override
			public void results(ResultCode resultCode, String message) {
				response.results(resultCode, domain + ": " + message);
			}

		});
	}

	@Override
	public PskStore getPskStore() {
		if (pskStore == null) {
			pskStore = new DevicePskStore();
		}
		return pskStore;
	}

	@Override
	public CertificateVerifier getCertificateVerifier() {
		if (credentials == null) {
			return null;
		}
		if (certificateVerifier == null) {
			certificateVerifier = new DomainDeviceCertificateVerifier(
					createCertificateTypesList(credentials.hasCertificateChain()));
		}
		return certificateVerifier;
	}

	@Override
	public CertificateProvider getCertificateProvider() {
		if (credentials == null) {
			return null;
		}
		if (certificateProvider == null) {
			if (certificateProvider == null) {
				certificateProvider = new ServerCertificateProvider(
						createCertificateTypesList(credentials.hasCertificateChain()));
			}
		}
		return certificateProvider;
	}

	@Override
	public AdditionalInfo createAdditionalInfo(Principal clientIdentity) {
		if (ApplicationPrincipal.ANONYMOUS.equals(clientIdentity)) {
			return DomainApplicationAnonymous.APPL_AUTH_PRINCIPAL.getExtendedInfo();
		}
		for (Entry<String, ResourceStore<DeviceParser>> domain : domains.entrySet()) {
			Device device = domain.getValue().getResource().getByPrincipal(clientIdentity);
			if (device != null) {
				return createAdditionalInfo(domain.getKey(), device);
			}
		}
		return null;
	}

	/**
	 * Creates additional info for a domain device.
	 * 
	 * @param domain domain name
	 * @param device device to create additional info
	 * @return additional info of device, or {@code null}, if provided device is
	 *         {@code null}.
	 */
	public AdditionalInfo createAdditionalInfo(String domain, Device device) {
		if (device != null) {
			if (device.ban) {
				return AdditionalInfo.empty();
			} else {
				Map<String, Object> info = new HashMap<>();
				info.put(PrincipalInfo.INFO_PROVIDER, this);
				info.put(PrincipalInfo.INFO_NAME, device.name);
				info.put(DomainPrincipalInfo.INFO_DOMAIN, domain);
				return AdditionalInfo.from(info);
			}
		}
		return null;
	}

	@Override
	public DomainPrincipalInfo getPrincipalInfo(Principal principal) {
		if (principal instanceof ExtensiblePrincipal) {
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensiblePrincipal = (ExtensiblePrincipal<? extends Principal>) principal;
			String domainName = null;
			Device device = null;
			if (!extensiblePrincipal.getExtendedInfo().isEmpty()) {
				String name = extensiblePrincipal.getExtendedInfo().get(PrincipalInfo.INFO_NAME, String.class);
				domainName = extensiblePrincipal.getExtendedInfo().get(DomainPrincipalInfo.INFO_DOMAIN, String.class);
				DomainDeviceManager manager = extensiblePrincipal.getExtendedInfo().get(PrincipalInfo.INFO_PROVIDER,
						DomainDeviceManager.class);
				if (manager == this && domainName != null && name != null && !name.contains("/")) {
					ResourceStore<DeviceParser> deviceStore = domains.get(domainName);
					if (deviceStore != null) {
						device = deviceStore.getResource().get(name);
					}
				}
			}
			if (device == null) {
				for (Entry<String, ResourceStore<DeviceParser>> domain : domains.entrySet()) {
					device = domain.getValue().getResource().getByPrincipal(principal);
					if (device != null) {
						domainName = domain.getKey();
						break;
					}
				}
			}
			if (domainName != null && device != null && !device.ban) {
				return new DomainPrincipalInfo(domainName, device.group, device.name, device.type);
			}
		}
		return null;
	}

	@Override
	public Set<DeviceIdentifier> getGroup(String domain, String group) {
		ResourceStore<DeviceParser> resource = domains.get(domain);
		if (resource == null) {
			return Collections.emptySet();
		} else {
			return resource.getResource().getGroup(group);
		}
	}

	@Override
	public HttpForwardConfiguration getConfiguration(DomainPrincipalInfo principalInfo) {
		ResourceStore<DeviceParser> resource = domains.get(principalInfo.domain);
		if (resource != null) {
			Device device = resource.getResource().get(principalInfo.name);
			if (device != null) {
				try {
					return BasicHttpForwardConfiguration.create(device.customFields);
				} catch (URISyntaxException e) {
					LOGGER.warn("Failed to configure http forward '{}'.", e.getMessage());
				}
			}
		}
		return null;
	}

	/**
	 * PreSharedKey store for devices in domains.
	 */
	private class DevicePskStore implements PskStore {

		private final PskPublicInformation dummy = new PskPublicInformation("dummy");

		@Override
		public boolean hasEcdhePskSupported() {
			return true;
		}

		@Override
		public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
				PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
				boolean useExtendedMasterSecret) {
			DomainNamePair domainName = DomainNamePair.fromName(identity.getPublicInfoAsString());
			if (domainName.domain != null) {
				ResourceStore<DeviceParser> resource = domains.get(domainName.domain);
				if (resource != null) {
					Device device = resource.getResource().getByPreSharedKeyIdentity(domainName.name);
					if (device != null) {
						AdditionalInfo info = createAdditionalInfo(domainName.domain, device);
						return new PskSecretResult(cid, identity, SecretUtil.create(device.pskSecret, "PSK"), info);
					}
				}
			} else {
				Device device = null;
				String domain = null;
				for (Entry<String, ResourceStore<DeviceParser>> domainEntry : domains.entrySet()) {
					Device match = domainEntry.getValue().getResource().getByPreSharedKeyIdentity(domainName.name);
					if (match != null) {
						if (device == null) {
							device = match;
							domain = domainEntry.getKey();
						} else {
							// ambiguous
							device = null;
							break;
						}
					}
				}
				if (device != null) {
					AdditionalInfo info = createAdditionalInfo(domain, device);
					return new PskSecretResult(cid, identity, SecretUtil.create(device.pskSecret, "PSK"), info);
				}
			}
			return new PskSecretResult(cid, identity, null);
		}

		@Override
		public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return dummy;
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {
		}
	}

	/**
	 * Certificate verifier for devices in domains.
	 */
	private class DomainDeviceCertificateVerifier extends DeviceCertificateVerifier {

		private DomainDeviceCertificateVerifier(List<CertificateType> supportedCertificateTypes) {
			super(supportedCertificateTypes);
		}

		@Override
		protected AdditionalInfo getByRawPublicKey(PublicKey publicKey) {
			for (Entry<String, ResourceStore<DeviceParser>> domain : domains.entrySet()) {
				Device device = domain.getValue().getResource().getByRawPublicKey(publicKey);
				if (device != null) {
					return createAdditionalInfo(domain.getKey(), device);
				}
			}
			return null;
		}

		@Override
		protected AdditionalInfo getByX509(X509Certificate certificate) {
			for (Entry<String, ResourceStore<DeviceParser>> domain : domains.entrySet()) {
				Device device = domain.getValue().getResource().getByX509(certificate);
				if (device != null) {
					if (LOGGER.isDebugEnabled()) {
						String cn = CertPathUtil.getSubjectsCn(certificate);
						LOGGER.debug("x509 certificate for {}", cn);
					}
					return createAdditionalInfo(domain.getKey(), device);
				}
			}
			if (LOGGER.isDebugEnabled()) {
				String cn = CertPathUtil.getSubjectsCn(certificate);
				LOGGER.debug("No x509 certificate for {}", cn);
			}
			return null;
		}

		@Override
		protected X509Certificate[] getTrustedCertificates() {
			int allSize = 0;
			List<X509Certificate[]> all = new ArrayList<>();
			for (Entry<String, ResourceStore<DeviceParser>> domain : domains.entrySet()) {
				X509Certificate[] trustedCertificates = domain.getValue().getResource().getTrustedCertificates();
				all.add(trustedCertificates);
				allSize += trustedCertificates.length;
			}

			X509Certificate[] trustedCertificates = new X509Certificate[allSize];
			int index = 0;
			for (X509Certificate[] trusts : all) {
				if (trusts.length > 0) {
					System.arraycopy(trusts, 0, trustedCertificates, index, trusts.length);
					index += trusts.length;
				}
			}
			return trustedCertificates;
		}
	}
}
