package com.icegg.oauth20imp;


import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import com.icegg.oauth20imp.common.ConstValue;
import com.icegg.oauth20imp.common.Utility;
import com.icegg.oauth20imp.exceptions.*; //require "OAuth2ServerException.php";

import com.icegg.oauth20imp.exceptions.OAuth2AuthenticateException;
import com.icegg.oauth20imp.interfaces.*;

public class Oauth20 {

	protected Map<String, String> conf = new HashMap<String, String>();

	/**
	 * Storage engine for authentication server
	 * 
	 * @var IOAuth2Storage
	 */
	protected IOauth2Storage storage;

	Random rn;

	/**
	 * @}
	 */

	/**
	 * Creates an OAuth2.0 server-side instance.
	 * 
	 * @param config
	 *            - An associative array as below of config options. See
	 *            CONFIG_* constants.
	 */
	public Oauth20(IOauth2Storage p_storage, Map<String, String> p_config) {
		this.storage = p_storage;

		// Configuration options
		this.setDefaultOptions();
		if (p_config != null) {
			Iterator<Map.Entry<String, String>> iter = p_config.entrySet()
					.iterator();
			while (iter.hasNext()) {
				Map.Entry<String, String> entry = (Map.Entry<String, String>) iter
						.next();
				String key = (String) entry.getKey();
				String val = (String) entry.getValue();
				this.setVariable(key, val);
			}
		}

		rn = new Random(System.currentTimeMillis());
	}

	/**
	 * Default configuration options are specified here.
	 */
	protected void setDefaultOptions() {
		conf.put(ConstValue.CONFIG_ACCESS_LIFETIME,
				ConstValue.DEFAULT_ACCESS_TOKEN_LIFETIME);
		conf.put(ConstValue.CONFIG_REFRESH_LIFETIME,
				ConstValue.DEFAULT_REFRESH_TOKEN_LIFETIME);
		conf.put(ConstValue.CONFIG_AUTH_LIFETIME,
				ConstValue.DEFAULT_AUTH_CODE_LIFETIME);
		conf.put(ConstValue.CONFIG_WWW_REALM, ConstValue.DEFAULT_WWW_REALM);
		conf.put(ConstValue.CONFIG_TOKEN_TYPE, ConstValue.TOKEN_TYPE_BEARER);
		conf.put(ConstValue.CONFIG_ENFORCE_INPUT_REDIRECT, "false");
		conf.put(ConstValue.CONFIG_ENFORCE_STATE, "false");
		conf.put(ConstValue.CONFIG_SUPPORTED_SCOPES, "");
	}

	public String getVariable(String p_name, String p_default) {
		return Utility.checkStringIsNotVoid(this.conf.get(p_name)) ? this.conf
				.get(p_name.toLowerCase()) : p_default;
	}

	/**
	 * Sets a persistent variable.
	 * 
	 * @param name
	 *            The name of the variable to set.
	 * @param value
	 *            The value to set.
	 */
	public void setVariable(String name, String value) {
		this.conf.put(name.toLowerCase(), value);
	}

	// Resource protecting (Section 5).

	/**
	 * Check that a valid access token has been provided. The token is returned
	 * (as an associative array) if valid.
	 * 
	 * The scope parameter defines any required scope that the token must have.
	 * If a scope param is provided and the token does not have the required
	 * scope, we bounce the request.
	 * 
	 * Some implementations may choose to return a subset of the protected
	 * resource (i.e. "public" data) if the user has not provided an access
	 * token or if the access token is invalid or expired.
	 * 
	 * The IETF spec says that we should send a 401 Unauthorized header and bail
	 * immediately so that"s what the defaults are set to. You can catch the
	 * exception thrown and behave differently if you like (log errors, allow
	 * public access for missing tokens, etc)
	 * 
	 * @param scope
	 *            A space-separated string of required scope(s), if you want to
	 *            check for scope.
	 * @return array Token
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
	 * 
	 * @ingroup oauth2_section_7
	 */
	public Map<String, String> verifyAccessToken(String token_param, /* optional */
			String scope) {
		String tokenType = this.getVariable(ConstValue.CONFIG_TOKEN_TYPE, "");
		String realm = this.getVariable(ConstValue.CONFIG_WWW_REALM, "");

		if (!Utility.checkStringIsNotVoid(token_param)) { // Access token was
															// not provided
			throw new OAuth2AuthenticateException(
					ConstValue.HTTP_BAD_REQUEST,
					tokenType,
					realm,
					ConstValue.ERROR_INVALID_REQUEST,
					"The request is missing a required parameter: access_token",
					scope);
		}

		// Get the stored token data (from the implementing subclass)
		Map<String, String> token = this.storage.getAccessToken(token_param);
		if (token == null) {
			throw new OAuth2AuthenticateException(ConstValue.HTTP_UNAUTHORIZED,
					tokenType, realm, ConstValue.ERROR_INVALID_GRANT,
					"The access token provided is invalid.", scope);
		}

		// Check we have a well formed token
		if (!Utility.checkStringIsNotVoid(token.get("expires"))
				|| !Utility.checkStringIsNotVoid(token.get("client_id"))) {
			throw new OAuth2AuthenticateException(ConstValue.HTTP_UNAUTHORIZED,
					tokenType, realm, ConstValue.ERROR_INVALID_GRANT,
					"Malformed token (missing 'expires' or 'client_id')", scope);
		}

		// Check token expiration (expires is a mandatory paramter)
		if (Utility.checkStringIsNotVoid(token.get("expires"))
				&& System.currentTimeMillis() > Long.parseLong(token
						.get("expires"))) {
			throw new OAuth2AuthenticateException(ConstValue.HTTP_UNAUTHORIZED,
					tokenType, realm, ConstValue.ERROR_INVALID_GRANT,
					"The access token provided has expired.", scope);
		}

		// Check scope, if provided
		// If token doesn"t have a scope, it"s NULL/empty, or it"s insufficient,
		// then throw an error
		if (Utility.checkStringIsNotVoid(scope)
				&& ((!Utility.checkStringIsNotVoid(token.get("scope")) || !this
						.checkScope(scope, token.get("scope"))))) {
			throw new OAuth2AuthenticateException(
					ConstValue.HTTP_FORBIDDEN,
					tokenType,
					realm,
					ConstValue.ERROR_INSUFFICIENT_SCOPE,
					"The request requires higher privileges than provided by the access token.",
					scope);
		}

		return token;
	}

	/** @codeCoverageIgnoreEnd */

	/**
	 * Check if everything in required scope is contained in available scope.
	 * 
	 * @param required_scope
	 *            Required scope to be check with.
	 * 
	 * @return TRUE if everything in required scope is contained in available
	 *         scope, and False if it isn"t.
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
	 * 
	 * @ingroup oauth2_section_7
	 */
	// undone
	private boolean checkScope(String required_scope, String available_scope) {
		// The required scope should match or be a subset of the available scope

		return false;
	}

	// Access token granting (Section 4).

	/**
	 * Grant or deny a requested access token. This would be called from the
	 * "/token" endpoint as defined in the spec. Obviously, you can call your
	 * endpoint whatever you want.
	 * 
	 * @param inputData
	 *            - The draft specifies that the parameters should be retrieved
	 *            from POST, but you can override to whatever method you like.
	 * @throws OAuth2ServerException
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.6
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-4.1.3
	 * 
	 * @ingroup oauth2_section_4
	 */
	public Map<String, String> grantAccessToken(Map<String, String> inputs) {
		// Grant Type must be specified.
		Map<String, String> stored;

		if (!Utility.checkStringIsNotVoid(inputs.get("grant_type"))) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_INVALID_REQUEST,
					"Invalid grant_type parameter or parameter missing");
		}

		if (!this.storage.checkClientCredentials(inputs.get("client_id"), inputs.get("client_secret"))) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_INVALID_CLIENT,
					"The client credentials are invalid");
		}

		if (!this.storage.checkRestrictedGrantType(inputs.get("client_id"), inputs.get("grant_type"))) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_UNAUTHORIZED_CLIENT,
					"The grant type is unauthorized for this client_id");
		}

		// Do the granting
		if (ConstValue.GRANT_TYPE_AUTH_CODE.equals(inputs.get("grant_type"))) {
			if (!Utility.checkStringIsNotVoid(inputs.get("code"))) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_INVALID_REQUEST,
						"Missing parameter 'code' is required");
			}

			if (Utility.checkStringIsTrue(this.getVariable(
					ConstValue.CONFIG_ENFORCE_INPUT_REDIRECT, "false"))
					&& !Utility.checkStringIsNotVoid(inputs.get("redirect_uri"))) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_INVALID_REQUEST,
						"The redirect URI parameter is required.");
			}

			stored = this.storage.getAuthCode(inputs.get("code"));

			// Check the code exists
			if (stored == null || !inputs.get("client_id").equals(stored.get("client_id"))) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_INVALID_GRANT,
						"Code is inconsistent");
			}

			// Validate the redirect URI. If a redirect URI has been provided on
			// input, it must be validated
			if (Utility.checkStringIsNotVoid(inputs.get("redirect_uri"))
					&& !this.validateRedirectUri(inputs.get("redirect_uri"), 
							stored.get("redirect_uri"))) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_REDIRECT_URI_MISMATCH,
						"The redirect URI is missing or do not match stored:"+ stored
						.get("redirect_uri") + " param:" + inputs.get("redirect_uri"));
			}

			if (Long.parseLong(stored.get("expires")) < System
					.currentTimeMillis()) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_INVALID_GRANT,
						"The authorization code has expired");
			}
		} else if (ConstValue.GRANT_TYPE_REFRESH_TOKEN.equals(inputs.get("grant_type"))) {
			if (!Utility.checkStringIsNotVoid(inputs.get("refresh_token"))) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_INVALID_REQUEST,
						"No 'refresh_token' parameter found");
			}

			stored = this.storage.getRefreshToken(inputs.get("refresh_token"));

			if (stored == null || !inputs.get("client_id").equals(stored.get("client_id"))) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_INVALID_GRANT, "Invalid refresh token");
			}

			if (Long.parseLong(stored.get("expires")) < System
					.currentTimeMillis()) {
				throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
						ConstValue.ERROR_INVALID_GRANT,
						"Refresh token has expired");
			}
		} else {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_INVALID_REQUEST,
					"Invalid grant_type parameter or parameter missing");
		}

		// Check scope, if provided
		if (Utility.checkStringIsNotVoid(inputs.get("scope"))
				&& (!Utility.checkStringIsNotVoid(stored.get("scope"))
				|| !this.checkScope(inputs.get("scope"), stored.get("scope")))) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_INVALID_SCOPE,
					"An unsupported scope was requested.");
		}

		String user_id = Utility.checkStringIsNotVoid((stored.get("user_id"))) ? stored
				.get("user_id")
				: null;
		Map<String, String> token = this.createAccessToken(inputs.get("client_id"), user_id,
				stored.get("scope"));

		return token;
	}

	// End-user/client Authorization (Section 2 of IETF Draft).

	/**
	 * Pull the authorization request data out of the HTTP request. - The
	 * redirect_uri is OPTIONAL as per draft 20. But your implementation can
	 * enforce it by setting CONFIG_ENFORCE_INPUT_REDIRECT to true. - The state
	 * is OPTIONAL but recommended to enforce CSRF. Draft 21 states, however,
	 * that CSRF protection is MANDATORY. You can enforce this by setting the
	 * CONFIG_ENFORCE_STATE to true.
	 * 
	 * @param inputData
	 *            - The draft specifies that the parameters should be retrieved
	 *            from GET, but you can override to whatever method you like.
	 * @return The authorization parameters so the authorization server can
	 *         prompt the user for approval if valid.
	 * 
	 * @throws OAuth2ServerException
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.12
	 * 
	 * @ingroup oauth2_section_3
	 */
	public Map<String, String> getAuthorizeParams(Map<String, String> input) {
		// Make sure a valid client id was supplied (we can not redirect because
		// we were unable to verify the URI)
		if (input == null
				|| !Utility.checkStringIsNotVoid(input.get("client_id"))) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_INVALID_CLIENT, "No client id supplied");		// We
		}																			// don"t
		// Get client details														// have
		Map<String, String> stored = this.storage.getClientDetails(input			// a
				.get("client_id"));													// good
		if (stored == null) {														// URI
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,			// to
					ConstValue.ERROR_INVALID_CLIENT, "Client id does not exist");	// use
		}																			// so
																					// we 
																					// can
		String param_redirect_uri = Utility.decodePercent(input.get("redirect_uri"));
																					// only
		// Make sure a valid redirect_uri was supplied. If specified, it must		// send
		// match the stored URI.													// the
		// @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2		// error
		// @see																		// to
		// http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1		// the
		// @see																		// browser
		// http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
		if (!Utility.checkStringIsNotVoid(stored.get("redirect_uri"))) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_REDIRECT_URI_MISMATCH,
					"No redirect URL was stored.");
		}
		if (Utility.checkStringIsTrue(this.getVariable(
				ConstValue.CONFIG_ENFORCE_INPUT_REDIRECT, "false"))
				&& !Utility.checkStringIsNotVoid(param_redirect_uri)) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_REDIRECT_URI_MISMATCH,
					"The redirect URI is mandatory and was not supplied.");
		}
		// Only need to validate if redirect_uri provided on input and stored.
		if (Utility.checkStringIsNotVoid(stored.get("redirect_uri"))
				&& Utility.checkStringIsNotVoid(param_redirect_uri)
				&& !this.validateRedirectUri(param_redirect_uri, stored
						.get("redirect_uri"))) {
			throw new OAuth2ServerException(ConstValue.HTTP_BAD_REQUEST,
					ConstValue.ERROR_REDIRECT_URI_MISMATCH,
					"The redirect URI provided is missing or does not match: stored:" + stored
					.get("redirect_uri") + " param:" + param_redirect_uri);
		}

		// Select the redirect URI
		input.put("redirect_uri", Utility.checkStringIsNotVoid(param_redirect_uri)
				? param_redirect_uri : stored
				.get("redirect_uri"));

		// type and client_id are required
		if (!Utility.checkStringIsNotVoid(input.get("response_type"))) {
			throw new Oauth2RedirectException(input.get("redirect_uri"),	//yeah! we have the verified URI
					ConstValue.ERROR_INVALID_REQUEST,
					"Invalid or missing response type.", input.get("state"));
		}

		if (!input.get("response_type").equals(
				ConstValue.RESPONSE_TYPE_AUTH_CODE)
				&& !input.get("response_type").equals(
						ConstValue.RESPONSE_TYPE_ACCESS_TOKEN)) {
			throw new Oauth2RedirectException(input.get("redirect_uri"),
					ConstValue.ERROR_UNSUPPORTED_RESPONSE_TYPE, "Please check your params", input
							.get("state"));
		}

		// Validate that the requested scope is supported
		if (Utility.checkStringIsNotVoid(input.get("scope"))
				&& !this.checkScope(input.get("scope"), this.getVariable(
						ConstValue.CONFIG_SUPPORTED_SCOPES, ""))) {
			throw new Oauth2RedirectException(input.get("redirect_uri"),
					ConstValue.ERROR_INVALID_SCOPE,
					"An unsupported scope was requested.", input.get("state"));
		}

		// Validate state parameter exists (if configured to enforce this)
		if (!Utility.checkStringIsTrue(this.getVariable(
				ConstValue.CONFIG_ENFORCE_STATE, "false"))
				&& !Utility.checkStringIsNotVoid(input.get("state"))) {
			throw new Oauth2RedirectException(input.get("redirect_uri"),
					ConstValue.ERROR_INVALID_REQUEST,
					"The state parameter is required.", null);
		}

		// Return retrieved client details together with input
		Iterator<Map.Entry<String, String>> iter = stored.entrySet().iterator();
		while (iter.hasNext()) {
			Map.Entry<String, String> entry = (Map.Entry<String, String>) iter
					.next();
			String key = (String) entry.getKey();
			String val = (String) entry.getValue();
			input.put(key, val);
		}
		
		Random ra = new Random();
		input.put("user_id", "" + ra.nextInt());
		
		return input;
	}

	/**
	 * Redirect the user appropriately after approval.
	 * 
	 * After the user has approved or denied the access request the
	 * authorization server should call this function to redirect the user
	 * appropriately.
	 * 
	 * @param is_authorized
	 *            TRUE or FALSE depending on whether the user authorized the
	 *            access.
	 * @param user_id
	 *            Identifier of user who authorized the client
	 * @param params
	 *            An associative array as below: - response_type: The requested
	 *            response: an access token, an authorization code, or both. -
	 *            client_id: The client identifier as described in Section 2. -
	 *            redirect_uri: An absolute URI to which the authorization
	 *            server will redirect the user-agent to when the end-user
	 *            authorization step is completed. - scope: (optional) The scope
	 *            of the access request expressed as a list of space-delimited
	 *            strings. - state: (optional) An opaque value used by the
	 *            client to maintain state between the request and callback.
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
	 * 
	 * @ingroup oauth2_section_4
	 */

	// same params as above
	public Map< String, Map<String, String> > getAuthResult(
			boolean is_authorized, String user_id, Map<String, String> params) {

		// We repeat this, because we need to re-validate. In theory, this could
		// be POSTed
		// by a 3rd-party (because we are not internally enforcing NONCEs, etc)

		params = this.getAuthorizeParams(params);
		params.put("scope", null);
		if (!is_authorized) {
			throw new Oauth2RedirectException(Utility.decodePercent(params.get("redirect_uri")),
					ConstValue.ERROR_USER_DENIED,
					"The user denied access to your application", null);
		}

		Map<String, Map<String, String>> result = new HashMap<String, Map<String, String>>();

		Map<String, String> maptmp = new HashMap<String, String>();
		if (!Utility.checkStringIsNotVoid(params.get("state"))) {
			maptmp.put("state", params.get("state"));
		}

		if (ConstValue.RESPONSE_TYPE_AUTH_CODE.equals(params
				.get("response_type"))) {
			maptmp.put("code", this.createAuthCode(params.get("client_id"),
					params.get("user_id"), params.get("redirect_uri"), params
							.get("scope")));
		} else if (ConstValue.RESPONSE_TYPE_ACCESS_TOKEN.equals(params
				.get("response_type"))) {
			result.put("fragment", this.createAccessToken(params
					.get("client_id"), params.get("user_id"), params
					.get("scope")));
		}
		
		maptmp.put("redirect_uri", params.get("redirect_uri"));
		result.put("query", maptmp);

		return result;
	}

	// Other/utility functions.


	/**
	 * Handle the creation of access token, also issue refresh token if support.
	 * 
	 * This belongs in a separate factory, but to keep it simple, I"m just
	 * keeping it here.
	 * 
	 * @param client_id
	 *            Client identifier related to the access token.
	 * @param scope
	 *            (optional) Scopes to be stored in space-separated string.
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5
	 * @ingroup oauth2_section_5
	 */
	protected Map<String, String> createAccessToken(String client_id,
			String user_id, String scope) {

		Map<String, String> token = new HashMap<String, String>();
		token.put("access_token", this.genAccessToken());
		token.put("expires_in", this.getVariable(
				ConstValue.CONFIG_ACCESS_LIFETIME,
				ConstValue.DEFAULT_ACCESS_TOKEN_LIFETIME));
		token.put("token_type", this.getVariable(ConstValue.CONFIG_TOKEN_TYPE,
				ConstValue.TOKEN_TYPE_BEARER));
		token.put("scope", scope);
		
		long expiretime = System.currentTimeMillis() + 
				Long.parseLong(
				this.getVariable(ConstValue.CONFIG_ACCESS_LIFETIME, 
						ConstValue.DEFAULT_ACCESS_TOKEN_LIFETIME));

		this.storage.setAccessToken(token.get("access_token"), client_id,
				user_id, 
				"" + expiretime,
				scope);

		// Issue a refresh token also, if we support them
		token.put("refresh_token", this.genAccessToken());
		
		expiretime = System.currentTimeMillis()
				+ Long.parseLong(this.getVariable(ConstValue.CONFIG_REFRESH_LIFETIME,
						ConstValue.DEFAULT_REFRESH_TOKEN_LIFETIME));
		
		this.storage.setRefreshToken(token.get("refresh_token"), client_id,
				user_id, ""+expiretime,
				scope);

		return token;
	}

	/**
	 * Handle the creation of auth code.
	 * 
	 * This belongs in a separate factory, but to keep it simple, I"m just
	 * keeping it here.
	 * 
	 * @param client_id
	 *            Client identifier related to the access token.
	 * @param redirect_uri
	 *            An absolute URI to which the authorization server will
	 *            redirect the user-agent to when the end-user authorization
	 *            step is completed.
	 * @param scope
	 *            (optional) Scopes to be stored in space-separated string.
	 * 
	 * @ingroup oauth2_section_4
	 */
	private String createAuthCode(String client_id, String user_id,
			String redirect_uri, String scope) {
		String code = this.genAuthCode();
		long expiretime = System.currentTimeMillis() + Long.parseLong(this.getVariable(ConstValue.CONFIG_AUTH_LIFETIME,
						ConstValue.DEFAULT_AUTH_CODE_LIFETIME));
		this.storage.setAuthCode(code, client_id, user_id, redirect_uri, "" + expiretime, scope);
		return code;
	}

	/**
	 * Generates an unique access token.
	 * 
	 * Implementing classes may want to override this function to implement
	 * other access token generation schemes.
	 * 
	 * @return An unique access token.
	 * 
	 * @ingroup oauth2_section_4
	 * @see OAuth2::genAuthCode()
	 */
	protected String genAccessToken() {
		int tokenLen = 40;

		String randomData = "" + rn.nextInt() + rn.nextInt() + rn.nextInt()
				+ rn.nextInt() + System.currentTimeMillis() + UUID.randomUUID();

		return randomData.substring(0, tokenLen);
	}

	/**
	 * Generates an unique auth code.
	 * 
	 * Implementing classes may want to override this function to implement
	 * other auth code generation schemes.
	 * 
	 * @return An unique auth code.
	 * 
	 * @ingroup oauth2_section_4
	 * @see OAuth2::genAccessToken()
	 */
	protected String genAuthCode() {
		return this.genAccessToken(); // let"s reuse the same scheme for token
										// generation
	}

	protected boolean validateRedirectUri(String inputUri, String storedUri) {
		if (!Utility.checkStringIsNotVoid(inputUri)
				|| !Utility.checkStringIsNotVoid(storedUri)) {
			return false; // if either one is missing, assume INVALID
		}
		return storedUri.equals(inputUri);
	}
}
