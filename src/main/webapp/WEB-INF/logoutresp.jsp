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
	<form action="<%=StringEscapeUtils.escapeHtml(request.getAttribute("Destination").toString()) %>" method="get">
		<table width="100%" border="1">
			<tr>
				<th>Logout:</th>
				<td><input type="submit" name="Submit" value="Logout" /></td>
			</tr>
			<tr>
				<th>SAML Response XML:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("ResponseXML").toString()) %></td>
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
				<th>SAML Response Code:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("ResponseCode").toString()) %><input
					type="hidden" name="SAMLResponse"
					value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("ResponseCode").toString()) %>" /></td>
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

				if (request.getAttribute("Sign") != null) {
			%>
			<tr>
				<th>Signature Algorithm:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SignAlg").toString()) %><input type="hidden"
					name="SigAlg" value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("SignAlg").toString()) %>" /></td>
			</tr>
			<tr>
				<th>Signature:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("Sign").toString()) %><input type="hidden"
					name="Signature" value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("Sign").toString()) %>" /></td>
			</tr>
			<%
				}
			%>
		</table>
	</form>
</body>
</html>