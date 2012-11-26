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
	Oauth20 oauth = new Oauth20(new Oauth2StoragePDO(), null);
try {
	String userId = request.getParameter("user_id");
	String accept = request.getParameter("accept");
	String redirect_uri = Utility.decodePercent(request.getParameter("redirect_uri"));
	if (Utility.checkStringIsNotVoid(userId) && 
		Utility.checkStringIsNotVoid(accept) && 
		Utility.checkStringIsNotVoid(redirect_uri))
	{
		boolean bAccept = false;
		if (accept != null && accept.equals("Yep"))
	bAccept = true;
		Map< String, Map<String, String> > authResult = 
	oauth.getAuthResult(bAccept, userId, Utility.param2Map(request));
		
		HttpDealer.finishClientAuthorization(redirect_uri, authResult, response);
	}

} catch (OAuth2ServerException oauthError) {
	oauthError.printStackTrace();
	HttpDealer.sendExceptionResponse(response, oauthError);
}
%>
