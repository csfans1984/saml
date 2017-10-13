package com.successfactors.I311616.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class SPLoginServlet extends HttpServlet {

	private static Logger log = LogManager.getLogger(SPLoginServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.getRequestDispatcher("WEB-INF/splogin.jsp").forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String responseXML = new String(Base64.decode(req.getParameter(SAMLConstants.SAML_RESPONSE_PARAM_NAME)));
		Response response = (Response) SAMLUtil.parseObject(responseXML);

		boolean hasPublicKey = !req.getParameter("Certificate").trim().equals("");
		boolean hasPrivateKey = !req.getParameter("PrivateKey").trim().equals("");

		BasicX509Credential credential = null;
		if (hasPublicKey || hasPrivateKey) {
			credential = CredentialUtil.buildBasicX509Credential(hasPublicKey ? req.getParameter("Certificate").trim() : null,
					hasPrivateKey ? req.getParameter("PrivateKey").trim() : null);
		}

		if (hasPublicKey && response.getSignature() != null) {
			req.setAttribute("ResponseSignVerified", SAMLUtil.verifyObject(response, credential));
		}

		Assertion assertion = null;
		if (hasPrivateKey && response.getEncryptedAssertions().size() > 0) {
			EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
			assertion = SAMLUtil.decryptAssertion(encryptedAssertion, credential);
			try {
				Element element = Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
				assertion = (Assertion) SAMLUtil.parseObject(XMLHelper.nodeToString(element));
			} catch (MarshallingException e) {
				log.error("Marshaller error");
				throw new RuntimeException(e);
			}
			response.getEncryptedAssertions().remove(response.getEncryptedAssertions().get(0));
			response.getAssertions().add(assertion);
		} else if (response.getAssertions().size() > 0) {
			assertion = response.getAssertions().get(0);
		}

		if (hasPublicKey && assertion != null && assertion.getSignature() != null) {
			req.setAttribute("AssertionSignVerified", SAMLUtil.verifyObject(assertion, credential));
		}

		if (hasPrivateKey && assertion != null && assertion.getSubject().getEncryptedID() != null) {
			EncryptedID encryptedID = assertion.getSubject().getEncryptedID();
			NameID nameID = SAMLUtil.decryptNameID(encryptedID, credential);

			assertion.getSubject().setEncryptedID(null);
			assertion.getSubject().setNameID(nameID);
		}

		if (hasPrivateKey && assertion != null && assertion.getAttributeStatements().size() > 0) {
			int attributesSize = assertion.getAttributeStatements().get(0).getEncryptedAttributes().size();
			for (int i = 0; i < attributesSize; i++) {
				EncryptedAttribute encryptedAttribute = assertion.getAttributeStatements().get(0).getEncryptedAttributes().get(0);
				Attribute attribute = SAMLUtil.decryptAttribute(encryptedAttribute, credential);

				assertion.getAttributeStatements().get(0).getEncryptedAttributes().remove(encryptedAttribute);
				assertion.getAttributeStatements().get(0).getAttributes().add(attribute);
			}
		}

		try {
			Element element = Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
			responseXML = XMLHelper.nodeToString(element);
			req.setAttribute("SAMLResponse", responseXML);
		} catch (MarshallingException e) {
			log.error("Marshaller error");
			throw new RuntimeException(e);
		}

		req.getRequestDispatcher("WEB-INF/sploginresult.jsp").forward(req, resp);
	}

}
