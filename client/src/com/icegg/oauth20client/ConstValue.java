package com.icegg.oauth20client;

public class ConstValue {
	/**
	 * Default values for configuration options.
	 * 
	 * @var public static int
	 * @see OAuth2::setDefaultOptions()
	 */
	static final public String CLIENT_ID = "101";
	static final public String CLIENT_SECRET = "123";
	
	static final public String DOMAIN = "http://192.168.232.130:8080/oauth20/";
	
	static final public String LOCAL = "http://192.168.232.130:8080/oauth_client/";
	
	static final public String CALL_BACK = "callback.jsp";
	
	//-------------don't change the value bellow--------------
	static public String AUTHORIZATION_ENDPOINT = "authorize.jsp";
	static public String ACCESS_TOKEN_ENDPOINT = "token.jsp";
	static public String VERIFY_ENDPOINT = "protected.jsp";
	
	/**
	 * HTTP status codes for successful and error states as specified by draft 20.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static final int HTTP_FOUND = 302;
	public static final  int HTTP_BAD_REQUEST = 400;
	public static final  int HTTP_UNAUTHORIZED = 401;
	public static final  int HTTP_FORBIDDEN = 403;
	public static final  int HTTP_UNAVAILABLE = 503;
}
