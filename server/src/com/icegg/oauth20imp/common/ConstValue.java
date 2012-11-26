package com.icegg.oauth20imp.common;

public class ConstValue {
	/**
	 * Default values for configuration options.
	 * 
	 * @var public static int
	 * @see OAuth2::setDefaultOptions()
	 */
	public static String DEFAULT_ACCESS_TOKEN_LIFETIME = "3600000";
	public static String DEFAULT_REFRESH_TOKEN_LIFETIME = "1209600000";
	public static String DEFAULT_AUTH_CODE_LIFETIME = "30000";
	public static String DEFAULT_WWW_REALM = "Service";
	
	/**
	 * Configurable options.
	 * 
	 * @var public static String
	 */
	public static String CONFIG_ACCESS_LIFETIME = "access_token_lifetime"; // The lifetime of access token in seconds.
	public static String CONFIG_REFRESH_LIFETIME = "refresh_token_lifetime"; // The lifetime of refresh token in seconds.
	public static String CONFIG_AUTH_LIFETIME = "auth_code_lifetime"; // The lifetime of auth code in seconds.
	public static String CONFIG_SUPPORTED_SCOPES = "supported_scopes"; // Array of scopes you want to support
	public static String CONFIG_TOKEN_TYPE = "token_type"; // Token type to respond with. Currently only "Bearer" supported.
	public static String CONFIG_WWW_REALM = "realm";
	public static String CONFIG_ENFORCE_INPUT_REDIRECT = "enforce_redirect"; // Set to true to enforce redirect_uri on input for both authorize and token steps.
	public static String CONFIG_ENFORCE_STATE = "enforce_state"; // Set to true to enforce state to be passed in authorization (see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.12)
	

	/**
	 * Regex to filter out the client identifier (described in Section 2 of IETF draft).
	 *
	 * IETF draft does not prescribe a format for these, however I"ve arbitrarily
	 * chosen alphanumeric strings with hyphens and underscores, 3-32 characters
	 * long.
	 *
	 * Feel free to change.
	 */
	public static String CLIENT_ID_REGEXP = "/^[a-z0-9-_]{3,32}$/i";
	
	/**
	 * @defgroup oauth2_section_5 Accessing a Protected Resource
	 * @{
	 *
	 * Clients access protected resources by presenting an access token to
	 * the resource server. Access tokens act as bearer tokens, where the
	 * token public static String acts as a shared symmetric secret. This requires
	 * treating the access token with the same care as other secrets (e.g.
	 * end-user passwords). Access tokens SHOULD NOT be sent in the clear
	 * over an insecure channel.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
	 */
	
	/**
	 * Used to define the name of the OAuth access token parameter
	 * (POST & GET). This is for the "bearer" token type.
	 * Other token types may use different methods and names.
	 *
	 * IETF Draft section 2 specifies that it should be called "access_token"
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-06#section-2.2
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-06#section-2.3
	 */
	public static String TOKEN_PARAM_NAME = "access_token";
	
	/**
	 * When using the bearer token type, there is a specifc Authorization header
	 * required: "Bearer"
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04#section-2.1
	 */
	public static String TOKEN_BEARER_HEADER_NAME = "Bearer";
	
	/**
	 * @}
	 */
	
	/**
	 * @defgroup oauth2_section_4 Obtaining Authorization
	 * @{
	 *
	 * When the client interacts with an end-user, the end-user MUST first
	 * grant the client authorization to access its protected resources.
	 * Once obtained, the end-user authorization grant is expressed as an
	 * authorization code which the client uses to obtain an access token.
	 * To obtain an end-user authorization, the client sends the end-user to
	 * the end-user authorization endpoint.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
	 */
	
	/**
	 * List of possible authentication response types.
	 * The "authorization_code" mechanism exclusively supports "code"
	 * and the "implicit" mechanism exclusively supports "token".
	 * 
	 * @var public static String
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.1
	 */
	public static String RESPONSE_TYPE_AUTH_CODE = "code";
	public static String RESPONSE_TYPE_ACCESS_TOKEN = "token";
	
	/**
	 * @}
	 */
	
	/**
	 * @defgroup oauth2_section_5 Obtaining an Access Token
	 * @{
	 *
	 * The client obtains an access token by authenticating with the
	 * authorization server and presenting its authorization grant (in the form of
	 * an authorization code, resource owner credentials, an assertion, or a
	 * refresh token).
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
	 */
	
	/**
	 * Grant types support by draft 20
	 */
	public static String GRANT_TYPE_AUTH_CODE = "authorization_code";
	public static String GRANT_TYPE_IMPLICIT = "token";
	public static String GRANT_TYPE_USER_CREDENTIALS = "password";
	public static String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
	public static String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
	public static String GRANT_TYPE_EXTENSIONS = "extensions";
	
	/**
	 * Regex to filter out the grant type.
	 * NB: For extensibility, the grant type can be a URI
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.5
	 */
	public static String GRANT_TYPE_REGEXP = "#^(authorization_code|token|password|client_credentials|refresh_token|http://.*)$#";
	
	/**
	 * @}
	 */
	
	/**
	 * Possible token types as defined by draft 20.
	 * 
	 * TODO: Add support for mac (and maybe other types?)
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7.1 
	 */
	public static String TOKEN_TYPE_BEARER = "bearer";
	public static String TOKEN_TYPE_MAC = "mac"; // Currently unsupported
	

	/**
	 * @defgroup self::HTTP_status HTTP status code
	 * @{
	 */
	
	/**
	 * HTTP status codes for successful and error states as specified by draft 20.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static int HTTP_FOUND = 302;
	public static int HTTP_BAD_REQUEST = 400;
	public static int HTTP_UNAUTHORIZED = 401;
	public static int HTTP_FORBIDDEN = 403;
	public static int HTTP_UNAVAILABLE = 503;
	
	/**
	 * @}
	 */
	
	/**
	 * @defgroup oauth2_error Error handling
	 * @{
	 *
	 * @todo Extend for i18n.
	 * @todo Consider moving all error related functionality into a separate class.
	 */
	
	/**
	 * The request is missing a required parameter, includes an unsupported
	 * parameter or parameter value, or is otherwise malformed.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static String ERROR_INVALID_REQUEST = "invalid_request";
	
	/**
	 * The client identifier provided is invalid.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static String ERROR_INVALID_CLIENT = "invalid_client";
	
	/**
	 * The client is not authorized to use the requested response type.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static String ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client";
	
	/**
	 * The redirection URI provided does not match a pre-registered value.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2.4
	 */
	public static String ERROR_REDIRECT_URI_MISMATCH = "redirect_uri_mismatch";
	
	/**
	 * The end-user or authorization server denied the request.
	 * This could be returned, for example, if the resource owner decides to reject
	 * access to the client at a later point.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
	 */
	public static String ERROR_USER_DENIED = "access_denied";
	
	/**
	 * The requested response type is not supported by the authorization server.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
	 */
	public static String ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
	
	/**
	 * The requested scope is invalid, unknown, or malformed.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
	 */
	public static String ERROR_INVALID_SCOPE = "invalid_scope";
	
	/**
	 * The provided authorization grant is invalid, expired,
	 * revoked, does not match the redirection URI used in the
	 * authorization request, or was issued to another client.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static String ERROR_INVALID_GRANT = "invalid_grant";
	
	/**
	 * The authorization grant is not supported by the authorization server.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static String ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
	
	/**
	 * The request requires higher privileges than provided by the access token.
	 * The resource server SHOULD respond with the HTTP 403 (Forbidden) status
	 * code and MAY include the "scope" attribute with the scope necessary to
	 * access the protected resource.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 */
	public static String ERROR_INSUFFICIENT_SCOPE = "invalid_scope";
	
	public static String MYSQL_IP = "localhost";
	public static String MYSQL_PORT = "3306";
	public static String MYSQL_USR = "root";
	public static String MYSQL_PASS = "123";
}
