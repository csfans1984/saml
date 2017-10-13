package com.successfactors.I311616.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class ArtifactServlet extends HttpServlet {

	private static Logger log = LogManager.getLogger(ArtifactServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		byte[] buf = new byte[100];
		int size = 0;
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		InputStream in = req.getInputStream();
		while ((size = in.read(buf)) > 0) {
			out.write(buf, 0, size);
		}

		String envelopeXML = out.toString();
		log.info(envelopeXML);

		Envelope envelope = (Envelope) SAMLUtil.parseObject(envelopeXML);

		ArtifactResolve artifactResolve = (ArtifactResolve) envelope.getBody().getUnknownXMLObjects(ArtifactResolve.DEFAULT_ELEMENT_NAME).get(0);

		log.info("Verify: " + SAMLUtil.verifyObject(artifactResolve));

		String inResponseTo = artifactResolve.getID();
		String artifact = artifactResolve.getArtifact().getArtifact();

		envelope = (Envelope) SAMLUtil.buildObject(Envelope.DEFAULT_ELEMENT_NAME);

		Header header = (Header) SAMLUtil.buildObject(Header.DEFAULT_ELEMENT_NAME);
		envelope.setHeader(header);

		Body body = (Body) SAMLUtil.buildObject(Body.DEFAULT_ELEMENT_NAME);

		ArtifactResponse artifactResponse = (ArtifactResponse) SAMLUtil.buildObject(ArtifactResponse.DEFAULT_ELEMENT_NAME);
		artifactResponse.setID(SAMLUtil.getUUID());
		artifactResponse.setVersion(SAMLVersion.VERSION_20);

		DateTime instant = new DateTime();
		artifactResponse.setIssueInstant(instant);

		artifactResponse.setInResponseTo(inResponseTo);

		Status status = (Status) SAMLUtil.buildObject(Status.DEFAULT_ELEMENT_NAME);

		StatusCode statusCode = (StatusCode) SAMLUtil.buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
		statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");

		status.setStatusCode(statusCode);
		artifactResponse.setStatus(status);

		Map<String, Object> attrs = (Map<String, Object>) req.getServletContext().getAttribute(artifact);
		String issuer = (String) attrs.get("Issuer");
		String destination = (String) attrs.get("Destination");
		inResponseTo = (String) attrs.get("InResponseTo");
		String user = (String) attrs.get("User");
		String password = "";
		String audienceURI = (String) attrs.get("AudienceURI");
		boolean encryptNameID = (boolean) attrs.get("EncryptNameID");
		String encryptNameIDKeyType = (String) attrs.get("EncryptNameIDKeyType");
		boolean encryptAttribute = (boolean) attrs.get("EncryptAttribute");
		String encryptAttributeKeyType = (String) attrs.get("EncryptAttributeKeyType");
		boolean encryptAssertion = (boolean) attrs.get("EncryptAssertion");
		String encryptAssertionKeyType = (String) attrs.get("EncryptAssertionKeyType");
		boolean signAssertion = (boolean) attrs.get("SignAssertion");
		boolean signResponse = (boolean) attrs.get("SignResponse");

		Response response = SAMLUtil.buildAuthnResponse(issuer, destination, inResponseTo, user, password, audienceURI, encryptNameID, encryptNameIDKeyType,
				encryptAttribute, encryptAttributeKeyType, encryptAssertion, encryptAssertionKeyType, signAssertion, signResponse);
		artifactResponse.setMessage(response);

		SAMLUtil.signObject(artifactResponse);

		body.getUnknownXMLObjects().add(artifactResponse);

		envelope.setBody(body);

		try {
			Element element = Configuration.getMarshallerFactory().getMarshaller(envelope).marshall(envelope);
			String xml = XMLHelper.nodeToString(element);
			resp.getOutputStream().write(xml.getBytes());
		} catch (MarshallingException e) {
			log.error("Marshaller error");
			throw new RuntimeException(e);
		}

	}

}
