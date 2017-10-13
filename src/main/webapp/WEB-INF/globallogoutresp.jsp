<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>logout</title>
</head>
<body>
	<table width="100%" border="1">
		<tr>
			<th>SAML Response XML:</th>
			<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SAMLResponse").toString()) %></td>
		</tr>
		<%
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
		<%
			if (request.getAttribute("RelayState") != null) {
		%>
		<tr>
			<th>Relay State:</th>
			<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("RelayState").toString()) %></td>
		</tr>
		<%
			}
		%>
	</table>
</body>
</html>