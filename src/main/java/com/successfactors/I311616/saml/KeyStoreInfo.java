package com.successfactors.I311616.saml;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;

public class KeyStoreInfo extends HttpServlet {
	
	private static Logger log = LogManager.getLogger(KeyStoreInfo.class);

	private static final long serialVersionUID = 1L;
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		
		// PKCS12 or KeyStore.getDefaultType()
		BasicX509Credential credential = CredentialUtil.getCredentialFromKeyStoreFile("oiosaml.keystore", "s0018467969", "changeit", "JKS");
		
		req.setAttribute("PrivateKey", Base64.encodeBytes(credential.getPrivateKey().getEncoded(), Base64.DONT_BREAK_LINES));
		try {
			req.setAttribute("Certificate", Base64.encodeBytes(credential.getEntityCertificate().getEncoded(), Base64.DONT_BREAK_LINES));
		} catch (CertificateEncodingException e) {
			log.error("Error when parse certificate");
			throw new RuntimeException(e);
		}
		
		req.getRequestDispatcher("WEB-INF/keystoreinfo.jsp").forward(req, resp);
	}

}
