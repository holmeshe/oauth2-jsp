<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>


<%@ page import="com.icegg.oauth20client.OauthHandler" %>
<%@ page import="com.icegg.oauth20client.Utility" %>
<%@ page import="com.icegg.oauth20client.ConstValue" %>
<%@ page import="com.icegg.oauth20client.OauthException" %>
<%@ page import="java.util.Map" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
  	<title>test sample</title>
  </head>
  <body>
<%
Map<String, String> token;
try{
	token = OauthHandler.doCallBack(request);
	if (token != null)
	{
		
%>
    success:
    token: <%=token.get("access_token") %>			</br>
    refresh_token: <%=token.get("refresh_token")%>	</br>
    expires_in: <%=token.get("expires_in") %>		</br>
    												</br>
    test:											</br>
    <a href="<%=ConstValue.DOMAIN + ConstValue.VERIFY_ENDPOINT + "?" + "access_token=" + token.get("access_token")%>">verify token</a>
    </br>

    <a href="<%=ConstValue.LOCAL + "refresh.jsp" + "?" + "refresh_token=" + token.get("refresh_token")%>">refresh token</a>
    </br>
<%
	}
}
catch (OauthException e)
{
	e.printStackTrace();
%>
internal oauth error!
<%
	return;
}
%>
  </body>
</html>
