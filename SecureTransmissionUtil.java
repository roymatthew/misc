package com.ode.commons.util.security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.ode.commons.util.CommonsConstants;
import com.ode.commons.util.vo.CommonsUtilNvpVO;

/**
 * @author rmathew
 *
 */
public class SecureTransmissionUtil implements CommonsConstants {
	private static final Logger logger = LogManager.getLogger(SecureTransmissionUtil.class);

	/**
	 * @param listOfWebServiceFeatures
	 * @return
	 * @throws Exception
	 */
	public static RestTemplate getRestTemplate(final List<CommonsUtilNvpVO> listOfWebServiceFeatures) throws Exception {
		logger.debug("Entered getRestTemplate(List<CommonsUtilNvpVO>) method of SecureTransmissionUtil class");
		RestTemplate restTemplate = null;
		Map<String, CommonsUtilNvpVO> mapOfWebServiceFeatures = null;
		CommonsUtilNvpVO x509FeatureVO = null;
		if (null != listOfWebServiceFeatures && !listOfWebServiceFeatures.isEmpty()) {
			mapOfWebServiceFeatures = getMapOfWebServiceFeatures(listOfWebServiceFeatures);
			logger.debug("webServiceFeatures map contains {} items", mapOfWebServiceFeatures.size());
			x509FeatureVO = (CommonsUtilNvpVO) mapOfWebServiceFeatures.get(KEY_X509);
		}

		if (null != x509FeatureVO && StringUtils.isNotBlank(x509FeatureVO.getValue())) {
			String keyStoreName = ((CommonsUtilNvpVO) mapOfWebServiceFeatures.get(KEY_KEY_STORE)).getValue();
			String keyStoreFormat = ((CommonsUtilNvpVO) mapOfWebServiceFeatures.get(KEY_KEY_STORE_FORMAT)).getValue();
			String protocolVersion;
			if (StringUtils.isNotBlank(keyStoreName) && keyStoreName.indexOf(".") < 0) {
				protocolVersion = keyStoreFormat.equals(JKS_FORMAT) ? EXTN_JKS : EXTN_PFX;
				keyStoreName = keyStoreName + protocolVersion;
			}

			protocolVersion = ((CommonsUtilNvpVO) mapOfWebServiceFeatures.get(KEY_PROTOCOL_VERSION)).getValue();
			String keyStorePassword = ((CommonsUtilNvpVO) mapOfWebServiceFeatures.get(KEY_KEY_STORE_PWD)).getValue();
			String certPassword = ((CommonsUtilNvpVO) mapOfWebServiceFeatures.get(KEY_CERT_PWD)).getValue();
			if (VALUE_X509_CLIENT_AUTH.equalsIgnoreCase(x509FeatureVO.getValue())) {
				restTemplate = restTemplateWithKeyStore(keyStoreName, keyStoreFormat, (String) null, protocolVersion,
						keyStorePassword, certPassword);
			} else if (VALUE_X509_MUTUAL_AUTH.equalsIgnoreCase(x509FeatureVO.getValue())) {
				String trustStoreName = ((CommonsUtilNvpVO) mapOfWebServiceFeatures.get(KEY_TRUST_STORE)).getValue();
				restTemplate = restTemplateWithKeyStore(keyStoreName, keyStoreFormat, trustStoreName, protocolVersion,
						keyStorePassword, certPassword);
			}
		} else {
			restTemplate = new RestTemplate();
		}

		logger.debug("Exit getRestTemplate(List<CommonsUtilNvpVO>) method of SecureTransmissionUtil class");
		return restTemplate;
	}

	/**
	 * @param listOfWebServiceFeatures
	 * @return
	 */
	private static Map<String, CommonsUtilNvpVO> getMapOfWebServiceFeatures(
			final List<CommonsUtilNvpVO> listOfWebServiceFeatures) {
		logger.debug("Entered getMapOfWebServiceFeatures() method of SecureTransmissionUtil class");
		Map<String, CommonsUtilNvpVO> mapOfWebServiceFeatures = new HashMap<>();
		listOfWebServiceFeatures.stream().forEach(feature -> {
			mapOfWebServiceFeatures.put(feature.getName(), feature);
		});
		return mapOfWebServiceFeatures;
	}

	/**
	 * @param keyStoreName
	 * @param keyStoreFormat
	 * @param trustStoreName
	 * @param protocolVersion
	 * @param keyStorePassword
	 * @param certPassword
	 * @return
	 * @throws UnrecoverableKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws KeyManagementException
	 */
	private static RestTemplate restTemplateWithKeyStore(final String keyStoreName, String keyStoreFormat,
			final String trustStoreName, final String protocolVersion, final String keyStorePassword,
			final String certPassword) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
			CertificateException, FileNotFoundException, IOException, KeyManagementException {
		logger.debug(
				"Entered restTemplateWithKeyStore() method of SecureTransmissionUtil class. keyStoreName: {}, trustStoreName: {}, protocolVersion:{}",
				keyStoreName, trustStoreName, protocolVersion);
		if (StringUtils.isNotBlank(keyStorePassword)) {
			logger.debug("Received non-empty value for keyStorePassword");
		}

		KeyStore keyStore = KeyStore.getInstance(keyStoreFormat);
		keyStore.load(new FileInputStream(keyStoreName), keyStorePassword.toCharArray());
		SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
		sslContextBuilder.setProtocol(protocolVersion);
		sslContextBuilder.loadKeyMaterial(keyStore, certPassword.toCharArray());
		if (StringUtils.isNotBlank(trustStoreName)) {
			logger.debug("Received non-empty value for certPassword");
			KeyStore trustKeyStore = KeyStore.getInstance(keyStoreFormat);
			trustKeyStore.load(new FileInputStream(trustStoreName), keyStorePassword.toCharArray());
			sslContextBuilder.loadTrustMaterial(trustKeyStore, (TrustStrategy) null);
		} else {
			sslContextBuilder.loadTrustMaterial(new TrustSelfSignedStrategy());
		}

		logger.debug("SSLContextBuilder -> OK");
		SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
				sslContextBuilder.build());
		logger.debug("SSLConnectionSocketFactory -> OK");
		CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslConnectionSocketFactory).build();
		logger.debug("CloseableHttpClient -> OK");
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
		requestFactory.setConnectTimeout(30000);
		requestFactory.setReadTimeout(30000);
		logger.debug("HttpComponentsClientHttpRequestFactory -> OK");
		logger.debug("Exit restTemplateWithKeyStore() method of SecureTransmissionUtil class");
		return new RestTemplate(requestFactory);
	}
}