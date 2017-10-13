<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>splogin</title>
</head>
<body>
	<form action="splogin" method="post">
		<table width="100%" border="1">
			<tr>
				<th>SAML Request XML:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SAMLResponse").toString()) %></td>
			</tr>
			<%
				if (request.getAttribute("ResponseSignVerified") != null) {
			%>
			<tr>
				<th>Response Signature Verified:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("ResponseSignVerified").toString()) %></td>
			</tr>
			<%
				}

				if (request.getAttribute("AssertionSignVerified") != null) {
			%>
			<tr>
				<th>Assertion Signature Verified:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("AssertionSignVerified").toString()) %></td>
			</tr>
			<%
				}
			%>
		</table>
	</form>
</body>
</html>