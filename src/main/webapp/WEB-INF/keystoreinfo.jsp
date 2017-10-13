<?xml version="1.0" encoding="UTF-8" ?>
<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>keystore information</title>
</head>
<body>
	<table width="100%" border="1">
		<tr>
			<th>Private Key</th>
			<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("PrivateKey").toString()) %></td>
		</tr>
		<tr>
			<th>Certificate</th>
			<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("Certificate").toString()) %></td>
		</tr>
	</table>
</body>
</html>