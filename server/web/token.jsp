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
	try {
	System.out.println("get token!!!");
	Oauth20 oauth = new Oauth20(new Oauth2StoragePDO(), null);

	Map<String, String> token = oauth.grantAccessToken(Utility.param2Map(request));
	HttpDealer.sendToken(response, token);
} catch (OAuth2ServerException oauthError) {
	oauthError.printStackTrace();
	HttpDealer.sendExceptionResponse(response, oauthError);
}
%>
