package com.successfactors.I311616.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;

public class CredentialUtil {

	private static Logger log = LogManager.getLogger(CredentialUtil.class);

	private static final String ALIAS = "saml";

	private static final String KEYSTORE_PASSWORD = "password";

	private static CertificateFactory certFactory = null;

	private static KeyFactory pkFactory = null;

	private static BasicX509Credential basicX509Credential = null;

	private static BasicCredential basicCredential = null;

	private static BasicX509Credential spBasicX509Credential = null;

	static {
		basicX509Credential = getCredentialFromKeyStoreFile("idp.keystore", ALIAS, KEYSTORE_PASSWORD);

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);

			SecretKey secretkey = keyGen.generateKey();
			basicCredential = SecurityHelper.getSimpleCredential(secretkey);
		} catch (NoSuchAlgorithmException e) {
			log.error("Create basic certificate error");
			throw new RuntimeException(e);
		}

		try {
			certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(CredentialUtil.class.getResourceAsStream("/sp.cert"));
			spBasicX509Credential = SecurityHelper.getSimpleCredential(cert, null);
		} catch (CertificateException e) {
			log.error("Get certificate error");
			throw new RuntimeException(e);
		}

		try {
			pkFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			log.error("Get private key error");
			throw new RuntimeException(e);
		}

	}

	public static BasicX509Credential getBasicX509Credential() {
		return basicX509Credential;
	}

	public static BasicCredential getBasicCredential() {
		return basicCredential;
	}

	public static BasicX509Credential getSPBasicX509Credential() {
		return spBasicX509Credential;
	}

	public static BasicX509Credential buildBasicX509Credential(String certStr, String pkStr) {
		X509Certificate cert = null;
		PrivateKey pk = null;

		// x509 certificate
		if (certStr != null) {
			try {
				cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(Base64.decode(certStr)));
			} catch (CertificateException e) {
				log.error("Get certificate error");
				throw new RuntimeException(e);
			}
		}

		// private key
		if (pkStr != null) {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(pkStr));
			try {
				pk = pkFactory.generatePrivate(keySpec);
			} catch (InvalidKeySpecException e) {
				log.error("Get private key error");
				throw new RuntimeException(e);
			}
		}

		return SecurityHelper.getSimpleCredential(cert, pk);
	}

	public static BasicX509Credential getCredentialFromKeyStoreFile(String path, String alias, String pwd) {
		
		return getCredentialFromKeyStoreFile(path, alias, pwd, KeyStore.getDefaultType());
		
	}
	
	public static BasicX509Credential getCredentialFromKeyStoreFile(String path, String alias, String pwd, String type) {

		BasicX509Credential credential = null;
		try {
			KeyStore keyStore = KeyStore.getInstance(type);
			keyStore.load(CredentialUtil.class.getResourceAsStream("/" + path), pwd.toCharArray());

			credential = SecurityHelper.getSimpleCredential((X509Certificate) keyStore.getCertificate(alias),
					(PrivateKey) keyStore.getKey(alias, pwd.toCharArray()));
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException | UnrecoverableKeyException e) {
			log.error("Create x509 certificate error");
			throw new RuntimeException(e);
		}

		return credential;
	}
}
