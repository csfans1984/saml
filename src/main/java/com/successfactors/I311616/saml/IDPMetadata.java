package com.successfactors.I311616.saml;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLConstants;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class IDPMetadata extends HttpServlet{
	
	private static Logger log = LogManager.getLogger(IDPMetadata.class);

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		
		EntityDescriptor ed = (EntityDescriptor) SAMLUtil.buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		Namespace dsns = new Namespace(XMLConstants.XMLSIG_NS, XMLConstants.XMLSIG_PREFIX);
		ed.getNamespaceManager().registerNamespace(dsns);
		ed.setID(SAMLUtil.getUUID());
		ed.setEntityID(SAMLConstants.ISSUER);
		
		IDPSSODescriptor sd = (IDPSSODescriptor) SAMLUtil.buildObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		sd.setWantAuthnRequestsSigned(true);
		sd.addSupportedProtocol(org.opensaml.common.xml.SAMLConstants.SAML20P_NS);
		ed.getRoleDescriptors().add(sd);
		
		KeyDescriptor kd = (KeyDescriptor) SAMLUtil.buildObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		kd.setUse(UsageType.SIGNING);
		sd.getKeyDescriptors().add(kd);
		
		KeyInfo ki = (KeyInfo) SAMLUtil.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		kd.setKeyInfo(ki);
		
		KeyName kn = (KeyName) SAMLUtil.buildObject(KeyName.DEFAULT_ELEMENT_NAME);
		kn.setValue(SAMLConstants.ISSUER);
		ki.getKeyNames().add(kn);
		
		X509Data x509d = (X509Data) SAMLUtil.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
		ki.getX509Datas().add(x509d);
		
		X509Certificate x509c = (X509Certificate) SAMLUtil.buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
		try {
			x509c.setValue(Base64.encodeBytes(CredentialUtil.getBasicX509Credential().getEntityCertificate().getEncoded(), Base64.DONT_BREAK_LINES));
		} catch (CertificateEncodingException e) {
			log.error("Certificate encode error", e);
		}
		x509d.getX509Certificates().add(x509c);
		
		kd = (KeyDescriptor) SAMLUtil.buildObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		kd.setUse(UsageType.ENCRYPTION);
		sd.getKeyDescriptors().add(kd);
		
		ki = (KeyInfo) SAMLUtil.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		kd.setKeyInfo(ki);
		
		kn = (KeyName) SAMLUtil.buildObject(KeyName.DEFAULT_ELEMENT_NAME);
		kn.setValue(SAMLConstants.ISSUER);
		ki.getKeyNames().add(kn);
		
		x509d = (X509Data) SAMLUtil.buildObject(X509Data.DEFAULT_ELEMENT_NAME);
		ki.getX509Datas().add(x509d);
		
		x509c = (X509Certificate) SAMLUtil.buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
		try {
			x509c.setValue(Base64.encodeBytes(CredentialUtil.getBasicX509Credential().getEntityCertificate().getEncoded(), Base64.DONT_BREAK_LINES));
		} catch (CertificateEncodingException e) {
			log.error("Certificate encode error", e);
		}
		x509d.getX509Certificates().add(x509c);
		
		SingleLogoutService slo = (SingleLogoutService) SAMLUtil.buildObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
		slo.setBinding(org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		slo.setLocation(SAMLConstants.LOGOUT_DESTINATION);
		slo.setResponseLocation(SAMLConstants.LOGOUT_RESPONSE_DESTINATION);
		sd.getSingleLogoutServices().add(slo);
		
		SingleSignOnService sso = (SingleSignOnService) SAMLUtil.buildObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
		sso.setBinding(org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		sso.setLocation(SAMLConstants.LOGIN_DESTINATION);
		sd.getSingleSignOnServices().add(sso);
		
		SAMLUtil.signObject(ed);
		
		String xml = null;
		try {
			Element element = Configuration.getMarshallerFactory().getMarshaller(ed).marshall(ed);
			xml = XMLHelper.nodeToString(element);
		} catch (MarshallingException e) {
			log.error("Marshaller error");
			throw new RuntimeException(e);
		}
		
		resp.getWriter().write(xml);
		
		resp.setHeader("Content-Type", "application/xml");
	}
	
}
