package com.successfactors.I311616.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class LoginServlet extends HttpServlet {

	private static Logger log = LogManager.getLogger(LoginServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.info("login get start");
		if (req.getParameter(SAMLConstants.SAML_REQUEST_PARAM_NAME) != null) {
			String authnRequestXML = SAMLUtil.inflater(req.getParameter(SAMLConstants.SAML_REQUEST_PARAM_NAME));
			req.setAttribute("SAMLRequest", authnRequestXML);
			
			AuthnRequest authnRequest = (AuthnRequest) SAMLUtil.parseObject(authnRequestXML);
			String id = authnRequest.getID();
			req.setAttribute("InResponseTo", id);
		}

		String signAlg = req.getParameter(SAMLConstants.SIG_ALG_PARAM_NAME);
		req.setAttribute("SignAlg", signAlg);

		if (req.getParameter(SAMLConstants.SIG_VALUE_PARAM_NAME) != null) {
			boolean signVerified = SAMLUtil.verifyQueryString(SAMLConstants.SAML_REQUEST_PARAM_NAME, req.getParameter(SAMLConstants.SAML_REQUEST_PARAM_NAME),
					req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME), req.getParameter(SAMLConstants.SIG_ALG_PARAM_NAME),
					req.getParameter(SAMLConstants.SIG_VALUE_PARAM_NAME));
			req.setAttribute("SignVerified", signVerified);
		}

		req.setAttribute("Issuer", SAMLConstants.ISSUER);

		req.setAttribute("BizxUser", "cgrant");
		req.setAttribute("ProvisioningUser", "sfv4@successfactors.com");

		req.setAttribute("BizxDestination", SAMLConstants.BIZX_ASSERTION_CONSUMER_DESTINATION);
		req.setAttribute("ProvisioningDestination", SAMLConstants.PROVISIONING_ASSERTION_CONSUMER_DESTINATION);

		req.setAttribute("AudienceURI", SAMLConstants.AUDIENCE_URI);

		req.setAttribute("RelayState", req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME));

		req.getRequestDispatcher("WEB-INF/login.jsp").forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (req.getParameter("Submit") != null) {
			req.setAttribute("Destination", req.getParameter("Destination"));
			req.setAttribute("RelayState", req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME));
			if ("bizx".equals(req.getParameter("SP"))) {
				req.setAttribute("Company", req.getParameter(SAMLConstants.COMPANY_PARAM_NAME));
			}

			if ("Y".equals(req.getParameter("Artifact"))) {
				ByteArrayOutputStream bOut = new ByteArrayOutputStream(44);

				// Type code 0x0004
				byte[] typeCode = { 0, 4 };
				bOut.write(typeCode);

				// End point index;
				byte[] endpointIndex = { 0, 0 };
				bOut.write(endpointIndex);

				// Source Id
				MessageDigest md = null;
				try {
					md = MessageDigest.getInstance("SHA-1");
				} catch (NoSuchAlgorithmException e) {
					log.error("SHA1 generate error");
					throw new RuntimeException(e);
				}
				byte[] sourceId = md.digest(SAMLConstants.ISSUER.getBytes());
				bOut.write(sourceId);

				// Message Handle
				Random r = new Random();
				byte[] messageHandle = new byte[20];
				r.nextBytes(messageHandle);
				bOut.write(messageHandle);

				String samlArtifact = Base64.encodeBytes(bOut.toByteArray(), Base64.DONT_BREAK_LINES);
				req.setAttribute("SAMLArtifact", samlArtifact);

				Map<String, Object> attrs = new HashMap<String, Object>();
				attrs.put("Issuer", req.getParameter("Issuer"));
				attrs.put("Destination", req.getParameter("Destination"));
				attrs.put("InResponseTo", req.getParameter("InResponseTo"));
				attrs.put("User", req.getParameter("User"));
				attrs.put("AudienceURI", req.getParameter("AudienceURI"));
				attrs.put("EncryptNameID", req.getParameter("EncryptNameID") != null);
				attrs.put("EncryptNameIDKeyType", req.getParameter("EncryptNameIDKeyType"));
				attrs.put("EncryptAttribute", req.getParameter("EncryptAttribute") != null);
				attrs.put("EncryptAttributeKeyType", req.getParameter("EncryptAttributeKeyType"));
				attrs.put("EncryptAssertion", req.getParameter("EncryptAssertion") != null);
				attrs.put("EncryptAssertionKeyType", req.getParameter("EncryptAssertionKeyType"));
				attrs.put("SignAssertion", req.getParameter("SignAssertion") != null);
				attrs.put("SignResponse", req.getParameter("SignResponse") != null);

				req.getServletContext().setAttribute(samlArtifact, attrs);

				req.getRequestDispatcher("WEB-INF/loginart.jsp").forward(req, resp);
			} else {
				String issuer = req.getParameter("Issuer");
				String destination = req.getParameter("Destination");
				String inResponseTo = req.getParameter("InResponseTo");
				String user = req.getParameter("User");
				String password = "";
				String audienceURI = req.getParameter("AudienceURI");
				boolean encryptNameID = req.getParameter("EncryptNameID") != null;
				String encryptNameIDKeyType = req.getParameter("EncryptNameIDKeyType");
				boolean encryptAttribute = req.getParameter("EncryptAttribute") != null;
				String encryptAttributeKeyType = req.getParameter("EncryptAttributeKeyType");
				boolean encryptAssertion = req.getParameter("EncryptAssertion") != null;
				String encryptAssertionKeyType = req.getParameter("EncryptAssertionKeyType");
				boolean signAssertion = req.getParameter("SignAssertion") != null;
				boolean signResponse = req.getParameter("SignResponse") != null;

				Response response = SAMLUtil
						.buildAuthnResponse(issuer, destination, inResponseTo, user, password, audienceURI, encryptNameID, encryptNameIDKeyType,
								encryptAttribute, encryptAttributeKeyType, encryptAssertion, encryptAssertionKeyType, signAssertion, signResponse);

				try {
					Element element = Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
					String xml = XMLHelper.nodeToString(element);
					req.setAttribute("ResponseXML", xml);
					req.setAttribute("ResponseCode", Base64.encodeBytes(xml.getBytes(), Base64.DONT_BREAK_LINES));
				} catch (MarshallingException e) {
					log.error("Marshaller error");
					throw new RuntimeException(e);
				}

				req.getRequestDispatcher("WEB-INF/loginresp.jsp").forward(req, resp);
			}
		}
	}
}
