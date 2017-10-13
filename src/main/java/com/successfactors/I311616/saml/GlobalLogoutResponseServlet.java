package com.successfactors.I311616.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class GlobalLogoutResponseServlet extends HttpServlet {

	private static Logger log = LogManager.getLogger(GlobalLogoutResponseServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String responseXML = SAMLUtil.inflater(req.getParameter(SAMLConstants.SAML_RESPONSE_PARAM_NAME));
		req.setAttribute("SAMLResponse", responseXML);

		String signAlg = req.getParameter(SAMLConstants.SIG_ALG_PARAM_NAME);
		req.setAttribute("SignAlg", signAlg);

		if (req.getParameter(SAMLConstants.SIG_VALUE_PARAM_NAME) != null) {
			boolean signVerified = SAMLUtil.verifyQueryString(SAMLConstants.SAML_RESPONSE_PARAM_NAME, req.getParameter(SAMLConstants.SAML_RESPONSE_PARAM_NAME),
					req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME), req.getParameter(SAMLConstants.SIG_ALG_PARAM_NAME),
					req.getParameter(SAMLConstants.SIG_VALUE_PARAM_NAME));
			req.setAttribute("SignVerified", signVerified);
		}
		
		req.setAttribute("RelayState", req.getParameter(SAMLConstants.RELAY_STATE_PARAM_NAME));

		req.getRequestDispatcher("WEB-INF/globallogoutresp.jsp").forward(req, resp);
	}
}
