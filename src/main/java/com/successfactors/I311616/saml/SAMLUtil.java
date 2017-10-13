package com.successfactors.I311616.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class SAMLUtil {

	private static Logger log = LogManager.getLogger(CredentialUtil.class);

	public static final String NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

	private static XMLObjectBuilderFactory builderFactory;

	static {
		builderFactory = Configuration.getBuilderFactory();
		// BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
		// config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
	}

	public static String getUUID() {
		return "_" + UUID.randomUUID().toString();
	}

	public static XMLObject buildObject(QName qName) {
		XMLObjectBuilder<XMLObject> builder = builderFactory.getBuilder(qName);
		return builder.buildObject(qName);
	}

	public static XMLObject buildObject(QName qName1, QName qName2) {
		XMLObjectBuilder<XMLObject> builder = builderFactory.getBuilder(qName2);
		return builder.buildObject(qName1, qName2);
	}

	public static void signObject(SignableSAMLObject object) {
		Signature signature = (Signature) buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(CredentialUtil.getBasicX509Credential());
		signature.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		KeyInfo keyInfo = (KeyInfo) buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

		X509Data x509Data = (X509Data) buildObject(X509Data.DEFAULT_ELEMENT_NAME);

		X509Certificate x509Certificate = (X509Certificate) buildObject(X509Certificate.DEFAULT_ELEMENT_NAME);
		try {
			x509Certificate.setValue(Base64.encodeBytes(CredentialUtil.getBasicX509Credential().getEntityCertificate().getEncoded(), Base64.DONT_BREAK_LINES));
		} catch (CertificateEncodingException e) {
			log.error("Certificate encode error");
			throw new RuntimeException(e);
		}
		x509Data.getX509Certificates().add(x509Certificate);

		keyInfo.getX509Datas().add(x509Data);

		signature.setKeyInfo(keyInfo);

		object.setSignature(signature);
		
		((SAMLObjectContentReference)signature.getContentReferences().get(0)).setDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA256);

		try {
			Configuration.getMarshallerFactory().getMarshaller(object).marshall(object);
		} catch (MarshallingException e) {
			log.error("Marshaller error");
			throw new RuntimeException(e);
		}

		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			log.error("Sign error");
			throw new RuntimeException(e);
		}
	}

	public static boolean verifyObject(SignableSAMLObject object) {
		return verifyObject(object, CredentialUtil.getSPBasicX509Credential());
	}

	public static boolean verifyObject(SignableSAMLObject object, BasicX509Credential basicX509Credential) {
		Signature signature = object.getSignature();

		if (signature == null) {
			return false;
		}
		// verify signature element according to SAML profile
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		try {
			profileValidator.validate(signature);
		} catch (ValidationException e) {
			log.error("Validate signature error", e);
			return false;
		}

		// verify signature
		SignatureValidator validator = new SignatureValidator(basicX509Credential);
		try {
			validator.validate(signature);
		} catch (ValidationException e) {
			log.error("Validate signature error", e);
			return false;
		}

		return true;
	}

	public static String signQueryString(String samlMsgParamName, String samlMsgParamValue, String relayStateParamValue, String sigAlgParamValue) {
		String sign = "";

		try {
			java.security.Signature signer = java.security.Signature.getInstance("SHA1withRSA");
			signer.initSign(CredentialUtil.getBasicX509Credential().getPrivateKey());
			signer.update(buildQueryString(samlMsgParamName, samlMsgParamValue, relayStateParamValue, sigAlgParamValue).getBytes());
			sign = Base64.encodeBytes(signer.sign(), Base64.DONT_BREAK_LINES);
		} catch (NoSuchAlgorithmException | InvalidKeyException | java.security.SignatureException e) {
			log.error("Verify sign error");
			throw new RuntimeException(e);
		}

		return sign;
	}

	public static boolean verifyQueryString(String samlMsgParamName, String samlMsgParamValue, String relayStateParamValue, String sigAlgParamValue, String sign) {
		return verifyQueryString(samlMsgParamName, samlMsgParamValue, relayStateParamValue, sigAlgParamValue, sign, CredentialUtil.getSPBasicX509Credential());
	}

	public static boolean verifyQueryString(String samlMsgParamName, String samlMsgParamValue, String relayStateParamValue, String sigAlgParamValue,
			String sign, BasicX509Credential basicX509Credential) {
		boolean verified = false;

		try {
			java.security.Signature signer = java.security.Signature.getInstance("SHA1withRSA");
			signer.initVerify(basicX509Credential.getEntityCertificate());
			signer.update(buildQueryString(samlMsgParamName, samlMsgParamValue, relayStateParamValue, sigAlgParamValue).getBytes());

			verified = signer.verify(Base64.decode(sign));
		} catch (NoSuchAlgorithmException | InvalidKeyException | java.security.SignatureException e) {
			log.error("Verify sign error");
			throw new RuntimeException(e);
		}

		return verified;
	}

	private static String buildQueryString(String samlMsgParamName, String samlMsgParamValue, String relayStateParamValue, String sigAlgParamValue) {
		StringBuilder sb = new StringBuilder();
		sb.append(samlMsgParamName);
		sb.append("=");
		sb.append(URLEncoder.encode(samlMsgParamValue));

		if (relayStateParamValue != null) {
			sb.append("&");
			sb.append(SAMLConstants.RELAY_STATE_PARAM_NAME);
			sb.append("=");
			sb.append(URLEncoder.encode(relayStateParamValue));
		}

		sb.append("&");
		sb.append(SAMLConstants.SIG_ALG_PARAM_NAME);
		sb.append("=");
		sb.append(URLEncoder.encode(sigAlgParamValue));

		return sb.toString();
	}

	private static Encrypter getEncrypter(String encryptKeyType) {
		EncryptionParameters encryptionParameters = new EncryptionParameters();
		encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
		encryptionParameters.setEncryptionCredential(CredentialUtil.getBasicCredential());

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
		keyEncryptionParameters.setEncryptionCredential(CredentialUtil.getSPBasicX509Credential());

		Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
		encrypter.setKeyPlacement(KeyPlacement.valueOf(encryptKeyType));

		return encrypter;
	}

	private static Decrypter getDecrypter(BasicX509Credential basicX509Credential) {
		KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(basicX509Credential);

		ChainingEncryptedKeyResolver kekResolver = new ChainingEncryptedKeyResolver();
		kekResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
		kekResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
		kekResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());

		return new Decrypter(null, keyResolver, kekResolver);
	}

	private static EncryptedID encryptNameID(NameID nameID, String encryptKeyType) {
		Encrypter encrypter = getEncrypter(encryptKeyType);

		EncryptedID encryptedNameID = null;
		try {
			encryptedNameID = encrypter.encrypt(nameID);
		} catch (EncryptionException e) {
			log.error("Encrypt name id error");
			throw new RuntimeException(e);
		}

		return encryptedNameID;
	}

	public static NameID decryptNameID(EncryptedID encryptedID, BasicX509Credential basicX509Credential) {
		Decrypter decrypter = getDecrypter(basicX509Credential);

		NameID nameID = null;
		try {
			nameID = (NameID) decrypter.decrypt(encryptedID);
		} catch (DecryptionException e) {
			log.error("Decrypt name id error");
			throw new RuntimeException(e);
		}

		return nameID;
	}

	private static EncryptedAttribute encryptAttribute(Attribute attribute, String encryptKeyType) {
		Encrypter encrypter = getEncrypter(encryptKeyType);

		EncryptedAttribute encryptedAttribute = null;
		try {
			encryptedAttribute = encrypter.encrypt(attribute);
		} catch (EncryptionException e) {
			log.error("Encrypt name id error");
			throw new RuntimeException(e);
		}

		return encryptedAttribute;
	}

	public static Attribute decryptAttribute(EncryptedAttribute encryptedAttribute, BasicX509Credential basicX509Credential) {
		Decrypter decrypter = getDecrypter(basicX509Credential);

		Attribute attribute = null;
		try {
			attribute = (Attribute) decrypter.decrypt(encryptedAttribute);
		} catch (DecryptionException e) {
			log.error("Decrypt attribute error");
			throw new RuntimeException(e);
		}

		return attribute;
	}

	private static EncryptedAssertion encryptAssertion(Assertion assertion, String encryptKeyType) {
		Encrypter encrypter = getEncrypter(encryptKeyType);

		EncryptedAssertion encryptedAssertion = null;
		try {
			encryptedAssertion = encrypter.encrypt(assertion);
		} catch (EncryptionException e) {
			log.error("Encrypt name id error");
			throw new RuntimeException(e);
		}

		return encryptedAssertion;
	}

	public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, BasicX509Credential basicX509Credential) {
		Decrypter decrypter = getDecrypter(basicX509Credential);

		Assertion assertion = null;
		try {
			assertion = (Assertion) decrypter.decrypt(encryptedAssertion);
		} catch (DecryptionException e) {
			log.error("Decrypt assertion error");
			throw new RuntimeException(e);
		}

		return assertion;
	}

	public static String inflater(String code) {
		Inflater inflater = new Inflater(true);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		InflaterOutputStream iOut = new InflaterOutputStream(out, inflater);
		try {
			iOut.write(Base64.decode(code));
			iOut.finish();
		} catch (IOException e) {
			log.error("Inflater error");
			throw new RuntimeException(e);
		}

		return out.toString();
	}

	public static String deflater(String xml) {
		Deflater deflater = new Deflater(Deflater.DEFLATED, true);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DeflaterOutputStream dOut = new DeflaterOutputStream(out, deflater);
		try {
			dOut.write(xml.getBytes());
			dOut.finish();
		} catch (IOException e) {
			log.error("Deflater error");
			throw new RuntimeException(e);
		}

		return Base64.encodeBytes(out.toByteArray(), Base64.DONT_BREAK_LINES);
	}

	public static XMLObject parseObject(String xml) {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);

		DocumentBuilder builder = null;
		try {
			builder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			log.error("Create document builder error");
			throw new RuntimeException(e);
		}

		Document doc = null;
		try {
			doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
		} catch (SAXException | IOException e) {
			log.error("Parse document error");
			throw new RuntimeException(e);
		}

		XMLObject object = null;
		try {
			object = Configuration.getUnmarshallerFactory().getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
		} catch (UnmarshallingException e) {
			log.error("Unmarshaller error");
			throw new RuntimeException(e);
		}

		return object;
	}

	public static Response buildAuthnResponse(String issuerName, String destination, String inResponseTo, String user, String password, String audienceURI,
			boolean encryptNameID, String encryptNameIDKeyType, boolean encryptAttribute, String encryptAttributeKeyType, boolean encryptAssertion,
			String encryptAssertionKeyType, boolean signAssertion, boolean signResponse) {
		DateTime instant = new DateTime();
		DateTime notOnOrAfter = new DateTime(instant.getMillis() + 60000);

		Response response = (Response) buildObject(Response.DEFAULT_ELEMENT_NAME);
		response.setID(getUUID());
		response.setDestination(destination);
		if (inResponseTo != null)
			response.setInResponseTo(inResponseTo);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssueInstant(instant);

		Issuer issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(issuerName);
		response.setIssuer(issuer);

		Status status = (Status) buildObject(Status.DEFAULT_ELEMENT_NAME);

		StatusCode statusCode = (StatusCode) buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
		statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
		status.setStatusCode(statusCode);

		response.setStatus(status);

		Assertion assertion = (Assertion) buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID(getUUID());
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setIssueInstant(instant);

		issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(issuerName);
		assertion.setIssuer(issuer);

		Subject subject = (Subject) buildObject(Subject.DEFAULT_ELEMENT_NAME);

		NameID nameID = (NameID) buildObject(NameID.DEFAULT_ELEMENT_NAME);
		nameID.setValue(user);
		nameID.setFormat(NAMEID_FORMAT);
		if (encryptNameID) {
			EncryptedID encryptedID = encryptNameID(nameID, encryptNameIDKeyType);
			subject.setEncryptedID(encryptedID);
		} else {
			subject.setNameID(nameID);
		}

		SubjectConfirmation subjectConfirmation = (SubjectConfirmation) buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

		SubjectConfirmationData subjectConfirmationData = (SubjectConfirmationData) buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		subjectConfirmationData.setRecipient(destination);
		subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
		subjectConfirmationData.setInResponseTo(getUUID());
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

		subject.getSubjectConfirmations().add(subjectConfirmation);

		assertion.setSubject(subject);

		Conditions conditions = (Conditions) buildObject(Conditions.DEFAULT_ELEMENT_NAME);
		conditions.setNotBefore(instant);
		conditions.setNotOnOrAfter(notOnOrAfter);

		AudienceRestriction audienceRestriction = (AudienceRestriction) buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);

		Audience audience = (Audience) buildObject(Audience.DEFAULT_ELEMENT_NAME);
		audience.setAudienceURI(audienceURI);
		audienceRestriction.getAudiences().add(audience);

		conditions.getAudienceRestrictions().add(audienceRestriction);

		assertion.setConditions(conditions);

		AuthnStatement authnStatement = (AuthnStatement) buildObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnInstant(instant);
		// authnStatement.setSessionIndex("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93");
		authnStatement.setSessionNotOnOrAfter(notOnOrAfter);

		AuthnContext authnContext = (AuthnContext) buildObject(AuthnContext.DEFAULT_ELEMENT_NAME);

		AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
		authnContext.setAuthnContextClassRef(authnContextClassRef);

		authnStatement.setAuthnContext(authnContext);

		assertion.getAuthnStatements().add(authnStatement);

		AttributeStatement attributeStatement = (AttributeStatement) buildObject(AttributeStatement.DEFAULT_ELEMENT_NAME);

		Attribute attribute = (Attribute) buildObject(Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(SAMLConstants.USERNAME_ATTRIBUTE);

		XSString xsString = (XSString) buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		xsString.setValue(user);
		attribute.getAttributeValues().add(xsString);

		if (encryptAttribute) {
			EncryptedAttribute encryptedAttribute = encryptAttribute(attribute, encryptAttributeKeyType);
			attributeStatement.getEncryptedAttributes().add(encryptedAttribute);
		} else {
			attributeStatement.getAttributes().add(attribute);
		}

		attribute = (Attribute) buildObject(Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(SAMLConstants.PASSWORD_ATTRIBUTE);

		xsString = (XSString) buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		xsString.setValue(password);
		attribute.getAttributeValues().add(xsString);

		if (encryptAttribute) {
			EncryptedAttribute encryptedAttribute = encryptAttribute(attribute, encryptAttributeKeyType);
			attributeStatement.getEncryptedAttributes().add(encryptedAttribute);
		} else {
			attributeStatement.getAttributes().add(attribute);
		}

		assertion.getAttributeStatements().add(attributeStatement);

		if (signAssertion) {
			signObject(assertion);
		}

		if (encryptAssertion) {
			EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, encryptAssertionKeyType);
			response.getEncryptedAssertions().add(encryptedAssertion);
		} else {
			response.getAssertions().add(assertion);
		}

		if (signResponse) {
			signObject(response);
		}

		return response;
	}
}
