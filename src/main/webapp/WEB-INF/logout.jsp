<%@page import="org.apache.commons.lang.StringEscapeUtils"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>logout</title>
<style type="text/css">
.textArea {
	width: 99%;
	height: 400px;
}

.inputText {
	width: 500px;
}
</style>
<script type="text/javascript">
var bizxIssuer = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("Issuer").toString()) %>';
var provisioningIssuer = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("Issuer").toString()) %>';
var bizxDestination = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("BizxDestination").toString()) %>';
var provisioningDestination = '<%=StringEscapeUtils.escapeJavaScript(request.getAttribute("ProvisioningDestination").toString()) %>';
	function switchAttr(event) {
		var switchers = document.getElementsByName('SP');
		var sp;
		for (var i = 0; i < switchers.length; i++) {
			if (switchers[i].checked) {
				sp = switchers[i].value;
			}
		}

		document.getElementsByName('Issuer')[0].value = eval(sp + 'Issuer');
		document.getElementsByName('Destination')[0].value = eval(sp
				+ 'Destination');

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
	<form action="logout" method="post">
		<table width="100%" border="1">
			<tr>
				<th>Logout:</th>
				<td><input type="submit" name="Submit" value="Logout" /></td>
			</tr>
			<tr>
				<th>SAML Request XML:</th>
				<td><%=StringEscapeUtils.escapeHtml(request.getAttribute("SAMLRequest").toString()) %></td>
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
			<tr id="company">
				<th>Company:</th>
				<td><input type="text" name="Company" value="test"
					class="inputText" /></td>
			</tr>
			<tr>
				<th>SP:</th>
				<td><input type="radio" name="SP" value="bizx"
					onclick="switchAttr();" />Bizx<input type="radio" name="SP"
					value="provisioning" checked="checked" onclick="switchAttr();" />Provisioning</td>
			</tr>
			<tr>
				<th>Request ID:</th>
				<td><input type="text" name="InResponseTo"
					value="<%=StringEscapeUtils.escapeHtml(request.getAttribute("InResponseTo").toString()) %>" class="inputText" /></td>
			</tr>
			<tr>
				<th>Issuer:</th>
				<td><input type="text" name="Issuer" class="inputText" /></td>
			</tr>
			<tr>
				<th>Destination:</th>
				<td><input type="text" name="Destination" class="inputText" />
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
			<tr>
				<th>Sign Response:</th>
				<td><input type="checkbox" name="SignResponse"
					checked="checked" /></td>
			</tr>
		</table>
	</form>
</body>
</html>