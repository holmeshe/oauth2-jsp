<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>


<%@ page import="com.icegg.oauth20imp.implementation.Oauth2StoragePDO" %>
<%@ page import="com.icegg.oauth20imp.Oauth20" %>
<%@ page import="com.icegg.oauth20imp.common.ConstValue" %>
<%@ page import="com.icegg.oauth20imp.common.HttpDealer" %>
<%@ page import="com.icegg.oauth20imp.exceptions.OAuth2ServerException" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Iterator" %>

<%
	Map<String, String> auth_params = null;
try {
	Oauth20 oauth = new Oauth20(new Oauth2StoragePDO(), null);

	oauth.verifyAccessToken(request.getParameter(ConstValue.TOKEN_PARAM_NAME), null);
} catch (OAuth2ServerException oauthError) {
	oauthError.printStackTrace();
	HttpDealer.sendExceptionResponse(response, oauthError);
	return;
}
%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>protected</title>
</head>
<body>
      this is secret!
</body>
</html>