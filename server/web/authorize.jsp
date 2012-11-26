<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>


<%@ page import="com.icegg.oauth20imp.implementation.Oauth2StoragePDO" %>
<%@ page import="com.icegg.oauth20imp.Oauth20" %>
<%@ page import="com.icegg.oauth20imp.common.Utility" %>
<%@ page import="com.icegg.oauth20imp.common.HttpDealer" %>
<%@ page import="com.icegg.oauth20imp.exceptions.OAuth2ServerException" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Iterator" %>

<%
	Map<String, String> auth_params = null;
try {
	Oauth20 oauth = new Oauth20(new Oauth2StoragePDO(), null);

	auth_params = oauth.getAuthorizeParams(Utility.param2Map(request));
} catch (OAuth2ServerException oauthError) {
	oauthError.printStackTrace();
	HttpDealer.sendExceptionResponse(response, oauthError);
	return;
}
%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>Authorize</title>
<script>
	if (top != self) {
		window.document.write("<div style='background:black; opacity:0.5; filter: alpha (opacity = 50); position: absolute; top:0px; left: 0px;"
		+ "width: 9999px; height: 9999px; zindex: 1000001' onClick='top.location.href=window.location.href'></div>");
	}
  </script>
</head>
<body>
<form method="post" action="authorizeCallback.jsp">
<% 
if (auth_params != null)
{
	Iterator<Map.Entry<String, String>> iter = auth_params.entrySet().iterator();
	while (iter.hasNext()) {
		Map.Entry<String, String> entry = (Map.Entry<String, String>) iter
				.next();
		String key = (String) entry.getKey();
		String val = (String) entry.getValue();

%>
    <input type="hidden"
	name="<%= Utility.percentEncode(key) %>"
	value="<%= Utility.percentEncode(val) %>" />
<%
	}
}
%>
      Do you authorize the app to do its thing?
      <p><input type="submit" name="accept" value="Yep" /> <input
	type="submit" name="accept" value="Nope" /></p>
</form>
</body>
</html>
