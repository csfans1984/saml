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
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class GlobalLogoutServlet extends HttpServlet {

	private static Logger log = LogManager.getLogger(GlobalLogoutServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setAttribute("Issuer", SAMLConstants.ISSUER);

		req.setAttribute("BizxDestination", SAMLConstants.BIZX_GLOBAL_LOGOUT_DESTINATION);
		req.setAttribute("ProvisioningDestination", SAMLConstants.PROVISIONING_GLOBAL_LOGOUT_DESTINATION);

		req.getRequestDispatcher("WEB-INF/globallogout.jsp").forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (req.getParameter("Submit") != null) {
			req.setAttribute("Destination", req.getParameter("Destination"));
			if (!"".equals(req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME))) {
				req.setAttribute("RelayState", req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME));
			}
			if ("bizx".equals(req.getParameter("SP"))) {
				req.setAttribute("Company", req.getParameter(SAMLConstants.COMPANY_PARAM_NAME));
			}

			LogoutRequest logoutRequest = (LogoutRequest) SAMLUtil.buildObject(LogoutRequest.DEFAULT_ELEMENT_NAME);
			logoutRequest.setID(SAMLUtil.getUUID());
			logoutRequest.setVersion(SAMLVersion.VERSION_20);
			logoutRequest.setDestination(req.getParameter("Destination"));

			Issuer issuer = (Issuer) SAMLUtil.buildObject(Issuer.DEFAULT_ELEMENT_NAME);
			issuer.setValue(req.getParameter("Issuer"));
			logoutRequest.setIssuer(issuer);

			try {
				Element element = Configuration.getMarshallerFactory().getMarshaller(logoutRequest).marshall(logoutRequest);
				String xml = XMLHelper.nodeToString(element);
				req.setAttribute("RequestXML", xml);

				String encodedXML = SAMLUtil.deflater(xml);
				req.setAttribute("RequestCode", encodedXML);

				boolean signRequest = req.getParameter("SignRequest") != null;
				if (signRequest) {
					req.setAttribute("SignAlg", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);

					String sign = SAMLUtil.signQueryString(SAMLConstants.SAML_REQUEST_PARAM_NAME, encodedXML,
							(String) req.getAttribute("RelayState"), XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
					req.setAttribute("Sign", sign);
				}
			} catch (MarshallingException e) {
				log.error("Marshaller error");
				throw new RuntimeException(e);
			}

			req.getRequestDispatcher("WEB-INF/globallogoutreq.jsp").forward(req, resp);
		}
	}
}
