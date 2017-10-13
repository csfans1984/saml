package com.successfactors.I311616.saml;

public class SAMLConstants {

	public static final String ISSUER = "http://localhost:8081";

	public static final String BIZX_ASSERTION_CONSUMER_DESTINATION = "https://localhost:8443/saml2/SAMLAssertionConsumer";

	public static final String PROVISIONING_ASSERTION_CONSUMER_DESTINATION = "https://localhost:8443/sfsaml2/SAMLAssertionConsumer";

	public static final String BIZX_LOGOUT_DESTINATION = "https://localhost:8443/saml2/LogoutServiceHTTPRedirectResponse";

	public static final String PROVISIONING_LOGOUT_DESTINATION = "https://localhost:8443/sfsaml2/LogoutServiceHTTPRedirectResponse";
	
	public static final String BIZX_GLOBAL_LOGOUT_DESTINATION = "https://localhost:8443/saml2/LogoutServiceHTTPRedirect";

	public static final String PROVISIONING_GLOBAL_LOGOUT_DESTINATION = "https://localhost:8443/sfsaml2/LogoutServiceHTTPRedirect";
	
	public static final String LOGIN_DESTINATION = "http://localhost:8081/saml/login";
	
	public static final String LOGOUT_DESTINATION = "http://localhost:8081/saml/logout";
	
	public static final String LOGOUT_RESPONSE_DESTINATION = "http://localhost:8081/saml/globallogoutresp";

	public static final String AUDIENCE_URI = "https://www.successfactors.com";

	public static final String USERNAME_ATTRIBUTE = "username";

	public static final String PASSWORD_ATTRIBUTE = "password";

	public static final String SAML_REQUEST_PARAM_NAME = "SAMLRequest";
	
	public static final String SAML_RESPONSE_PARAM_NAME = "SAMLResponse";
	
	public static final String RELAY_STATE_PARAM_NAME = "RelayState";

	public static final String SIG_ALG_PARAM_NAME = "SigAlg";

	public static final String SIG_VALUE_PARAM_NAME = "Signature";
	
	public static final String COMPANY_PARAM_NAME = "Company";
	
}
