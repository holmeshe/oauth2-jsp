<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>


<%@ page import="com.icegg.oauth20client.OauthHandler" %>

<%
	if (true)
	{
		OauthHandler.userAuthorization(response,"mysignature123");
		return;
	}
%>
