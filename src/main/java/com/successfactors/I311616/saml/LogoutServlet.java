package com.successfactors.I311616.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class LogoutServlet extends HttpServlet {

	private static Logger log = LogManager.getLogger(LogoutServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.info("logout get start");
		String authnRequestXML = SAMLUtil.inflater(req.getParameter(SAMLConstants.SAML_REQUEST_PARAM_NAME));
		req.setAttribute("SAMLRequest", authnRequestXML);

		String signAlg = req.getParameter(SAMLConstants.SIG_ALG_PARAM_NAME);
		req.setAttribute("SignAlg", signAlg);

		if (req.getParameter(SAMLConstants.SIG_VALUE_PARAM_NAME) != null) {
			boolean signVerified = SAMLUtil.verifyQueryString(SAMLConstants.SAML_REQUEST_PARAM_NAME, req.getParameter(SAMLConstants.SAML_REQUEST_PARAM_NAME),
					req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME), req.getParameter(SAMLConstants.SIG_ALG_PARAM_NAME),
					req.getParameter(SAMLConstants.SIG_VALUE_PARAM_NAME));
			req.setAttribute("SignVerified", signVerified);
		}

		LogoutRequest logoutRequest = (LogoutRequest) SAMLUtil.parseObject(authnRequestXML);
		String id = logoutRequest.getID();
		req.setAttribute("InResponseTo", id);

		req.setAttribute("Issuer", SAMLConstants.ISSUER);

		req.setAttribute("BizxDestination", SAMLConstants.BIZX_LOGOUT_DESTINATION);
		req.setAttribute("ProvisioningDestination", SAMLConstants.PROVISIONING_LOGOUT_DESTINATION);

		req.setAttribute("RelayState", req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME));

		req.getRequestDispatcher("WEB-INF/logout.jsp").forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (req.getParameter("Submit") != null) {
			req.setAttribute("Destination", req.getParameter("Destination"));
			req.setAttribute("RelayState", req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME));
			if ("bizx".equals(req.getParameter("SP"))) {
				req.setAttribute("Company", req.getParameter(SAMLConstants.COMPANY_PARAM_NAME));
			}

			LogoutResponse logoutResponse = (LogoutResponse) SAMLUtil.buildObject(LogoutResponse.DEFAULT_ELEMENT_NAME);
			logoutResponse.setID(SAMLUtil.getUUID());
			logoutResponse.setVersion(SAMLVersion.VERSION_20);
			logoutResponse.setDestination(req.getParameter("Destination"));
			logoutResponse.setInResponseTo(req.getParameter("InResponseTo"));

			Issuer issuer = (Issuer) SAMLUtil.buildObject(Issuer.DEFAULT_ELEMENT_NAME);
			issuer.setValue(req.getParameter("Issuer"));
			logoutResponse.setIssuer(issuer);

			Status status = (Status) SAMLUtil.buildObject(Status.DEFAULT_ELEMENT_NAME);

			StatusCode statusCode = (StatusCode) SAMLUtil.buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
			statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
			status.setStatusCode(statusCode);

			logoutResponse.setStatus(status);

			try {
				Element element = Configuration.getMarshallerFactory().getMarshaller(logoutResponse).marshall(logoutResponse);
				String xml = XMLHelper.nodeToString(element);
				req.setAttribute("ResponseXML", xml);

				String encodedXML = SAMLUtil.deflater(xml);
				req.setAttribute("ResponseCode", encodedXML);

				boolean signResponse = req.getParameter("SignResponse") != null;
				if (signResponse) {
					req.setAttribute("SignAlg", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);

					String sign = SAMLUtil.signQueryString(SAMLConstants.SAML_RESPONSE_PARAM_NAME, encodedXML,
							req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME), XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
					req.setAttribute("Sign", sign);
				}
			} catch (MarshallingException e) {
				log.error("Marshaller error");
				throw new RuntimeException(e);
			}

			req.getRequestDispatcher("WEB-INF/logoutresp.jsp").forward(req, resp);
		}
	}
}
