<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>login</title>
</head>
<body>
	<form action="<%=StringEscapeUtils.escapeHtml(request.getAttribute("Destination").toString()) %>" method="get">
		<table width="100%" border="1">
			<tr>
				<th>Login:</th>
				<td><input type="submit" name="Submit" value="Login" /></td>
			</tr>
			<%
				if (request.getAttribute("Company") != null) {
			%>
			<tr>
				<th>Company:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("Company").toString()) %><input type="hidden"
					name="company" value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("Company").toString()) %>" /></td>
			</tr>
			<%
				}
			%>
			<tr>
				<th>SAML Artifact:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SAMLArtifact").toString()) %><input
					type="hidden" name="SAMLart"
					value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("SAMLArtifact").toString()) %>" /></td>
			</tr>
			<%
				if (request.getAttribute("RelayState") != null) {
			%>
			<tr>
				<th>Relay State:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("RelayState").toString()) %><input type="hidden"
					name="RelayState" value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("RelayState").toString()) %>" /></td>
			</tr>
			<%
				}
			%>
		</table>
	</form>
</body>
</html>