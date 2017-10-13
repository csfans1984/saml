<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>login</title>
<style type="text/css">
.inputText {
	width: 500px;
}
</style>
<script type="text/javascript">
var bizxIssuer = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("Issuer").toString()) %>';
var provisioningIssuer = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("Issuer").toString()) %>';
var bizxUser = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("BizxUser").toString()) %>';
var provisioningUser = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("ProvisioningUser").toString()) %>';
var bizxDestination = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("BizxDestination").toString()) %>';
var provisioningDestination = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("ProvisioningDestination").toString()) %>';
var bizxAudienceURI = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("AudienceURI").toString()) %>';
var provisioningAudienceURI = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("AudienceURI").toString()) %>';
	function switchAttr(event) {
		var switchers = document.getElementsByName('SP');
		var sp;
		for (var i = 0; i < switchers.length; i++) {
			if (switchers[i].checked) {
				sp = switchers[i].value;
			}
		}

		document.getElementsByName('Issuer')[0].value = eval(sp + 'Issuer');
		document.getElementsByName('User')[0].value = eval(sp + 'User');
		document.getElementsByName('Destination')[0].value = eval(sp
				+ 'Destination');
		document.getElementsByName('AudienceURI')[0].value = eval(sp
				+ 'AudienceURI');

		if (sp == 'bizx') {
			document.getElementById('company').style.display = '';
		} else {
			document.getElementById('company').style.display = 'none';
		}
	}
	window.addEventListener('load', switchAttr, false);
</script>
</head>
<body>
	<form action="login" method="post">
		<table width="100%" border="1">
			<tr>
				<th>Login:</th>
				<td><input type="submit" name="Submit" value="Login" /></td>
			</tr>
			<% if (request.getAttribute("SAMLRequest") != null) { %>
			<tr>
				<th>SAML Request XML:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SAMLRequest").toString()) %></td>
			</tr>
			<%
				}
			
				if (request.getAttribute("SignAlg") != null) {
			%>
			<tr>
				<th>Signature Algorithm:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SignAlg").toString()) %></td>
			</tr>
			<%
				}
			
				if (request.getAttribute("SignVerified") != null) {
			%>
			<tr>
				<th>Signature Verified:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SignVerified").toString()) %></td>
			</tr>
			<%
				}
			%>
			<tr>
				<th>SP:</th>
				<td><input type="radio" name="SP" value="bizx"
					onclick="switchAttr();" />Bizx<input type="radio" name="SP"
					value="provisioning" checked="checked" onclick="switchAttr();" />Provisioning</td>
			</tr>
			<tr>
				<th>Artifact:</th>
				<td><input type="radio" name="Artifact" value="Y" />Y<input
					type="radio" name="Artifact" value="N" checked="checked" />N</td>
			</tr>
			<% if (request.getAttribute("InResponseTo") != null) { %>
			<tr>
				<th>Request ID:</th>
				<td><input type="text" name="InResponseTo"
					value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("InResponseTo").toString()) %>" class="inputText" /></td>
			</tr>
			<% } %>
			<tr>
				<th>Issuer:</th>
				<td><input type="text" name="Issuer" class="inputText" /></td>
			</tr>
			<tr>
				<th>User Name:</th>
				<td><input type="text" name="User" class="inputText" /></td>
			</tr>
			<tr>
				<th>Destination:</th>
				<td><input type="text" name="Destination" class="inputText" />
				</td>
			</tr>
			<tr>
				<th>Audience URI:</th>
				<td><input type="text" name="AudienceURI" class="inputText" />
				</td>
			</tr>
			<%
				if (request.getAttribute("RelayState") != null) {
			%>
			<tr>
				<th>Relay State:</th>
				<td><input type="text" name="RelayState"
					value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("RelayState").toString()) %>" class="inputText" />
				</td>
			</tr>
			<%
				}
			%>
			<tr id="company">
				<th>Company:</th>
				<td><input type="text" name="Company" value="test"
					class="inputText" /></td>
			</tr>
			<tr>
				<th>Encrypt Name ID:</th>
				<td><input type="checkbox" name="EncryptNameID" /><input
					type="radio" name="EncryptNameIDKeyType" value="INLINE"
					checked="checked" />Inline<input type="radio"
					name="EncryptNameIDKeyType" value="PEER" />Peer</td>
			</tr>
			<tr>
				<th>Encrypt Attribute:</th>
				<td><input type="checkbox" name="EncryptAttribute" /><input
					type="radio" name="EncryptAttributeKeyType" value="INLINE"
					checked="checked" />Inline<input type="radio"
					name="EncryptAttributeKeyType" value="PEER" />Peer</td>
			</tr>
			<tr>
				<th>Encrypt Assertion:</th>
				<td><input type="checkbox" name="EncryptAssertion"
					checked="checked" /><input type="radio"
					name="EncryptAssertionKeyType" value="INLINE" checked="checked" />Inline
					<input type="radio" name="EncryptAssertionKeyType" value="PEER" />Peer
				</td>
			</tr>
			<tr>
				<th>Sign Assertion:</th>
				<td><input type="checkbox" name="SignAssertion"
					checked="checked" /></td>
			</tr>
			<tr>
				<th>Sign Response:</th>
				<td><input type="checkbox" name="SignResponse"
					checked="checked" /></td>
			</tr>
		</table>
	</form>
</body>
</html>