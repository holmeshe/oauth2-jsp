package com.icegg.oauth20imp.interfaces;

import java.util.Map;

import com.icegg.oauth20imp.common.ConstValue;

public interface IOauth2Storage {
	/**
	 * All storage engines need to implement this interface in order to use
	 * OAuth2 server
	 * 
	 * @author David Rochwerger <catch.dave@gmail.com>
	 */
	/**
	 * Make sure that the client credentials is valid.
	 * 
	 * @param $client_id
	 *            Client identifier to be check with.
	 * @param $client_secret
	 *            (optional) If a secret is required, check that they've given
	 *            the right one.
	 * 
	 * @return TRUE if the client credentials are valid, and MUST return FALSE
	 *         if it isn't.
	 * @endcode
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1
	 * 
	 * @ingroup oauth2_section_3
	 */
	public boolean checkClientCredentials(String client_id, /* optional */
			String $client_secret);

	/**
	 * Get client details corresponding client_id.
	 * 
	 * OAuth says we should store request URIs for each registered client.
	 * Implement this function to grab the stored URI for a given client id.
	 * 
	 * @param $client_id
	 *            Client identifier to be check with.
	 * 
	 * @return array Client details. Only mandatory item is the
	 *         "registered redirect URI", and MUST return FALSE if the given
	 *         client does not exist or is invalid.
	 * 
	 * @ingroup oauth2_section_4
	 */
	public Map<String, String> getClientDetails(String client_id);

	/**
	 * Look up the supplied oauth_token from storage.
	 * 
	 * We need to retrieve access token data as we create and verify tokens.
	 * 
	 * @param $oauth_token
	 *            oauth_token to be check with.
	 * 
	 * @return An associative array as below, and return NULL if the supplied
	 *         oauth_token is invalid: - client_id: Stored client identifier. -
	 *         expires: Stored expiration in unix timestamp. - scope: (optional)
	 *         Stored scope values in space-separated string.
	 * 
	 * @ingroup oauth2_section_7
	 */
	public Map<String, String> getAccessToken(String oauth_token);

	/**
	 * Store the supplied access token values to storage.
	 * 
	 * We need to store access token data as we create and verify tokens.
	 * 
	 * @param $oauth_token
	 *            oauth_token to be stored.
	 * @param $client_id
	 *            Client identifier to be stored.
	 * @param $user_id
	 *            User identifier to be stored.
	 * @param $expires
	 *            Expiration to be stored.
	 * @param $scope
	 *            (optional) Scopes to be stored in space-separated string.
	 * 
	 * @ingroup oauth2_section_4
	 */
	public void setAccessToken(String oauth_token, String client_id,
			String user_id, String expires, /* optional */String scope);

	/**
	 * Check restricted grant types of corresponding client identifier.
	 * 
	 * If you want to restrict clients to certain grant types, override this
	 * function.
	 * 
	 * @param $client_id
	 *            Client identifier to be check with.
	 * @param $grant_type
	 *            Grant type to be check with, would be one of the values
	 *            contained in OAuth2::GRANT_TYPE_REGEXP.
	 * 
	 * @return TRUE if the grant type is supported by this client identifier,
	 *         and FALSE if it isn't.
	 * 
	 * @ingroup oauth2_section_4
	 */
	public boolean checkRestrictedGrantType(String client_id, String grant_type);
	
	static String RESPONSE_TYPE_CODE = ConstValue.RESPONSE_TYPE_AUTH_CODE;

	/**
	 * Fetch authorization code data (probably the most common grant type).
	 *
	 * Retrieve the stored data for the given authorization code.
	 *
	 * Required for OAuth2::GRANT_TYPE_AUTH_CODE.
	 *
	 * @param $code
	 * Authorization code to be check with.
	 *
	 * @return
	 * An associative array as below, and NULL if the code is invalid:
	 * - client_id: Stored client identifier.
	 * - redirect_uri: Stored redirect URI.
	 * - expires: Stored expiration in unix timestamp.
	 * - scope: (optional) Stored scope values in space-separated string.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1
	 *
	 * @ingroup oauth2_section_4
	 */
	public Map<String, String> getAuthCode(String code);

	/**
	 * Take the provided authorization code values and store them somewhere.
	 *
	 * This function should be the storage counterpart to getAuthCode().
	 *
	 * If storage fails for some reason, we're not currently checking for
	 * any sort of success/failure, so you should bail out of the script
	 * and provide a descriptive fail message.
	 *
	 * Required for OAuth2::GRANT_TYPE_AUTH_CODE.
	 *
	 * @param $code
	 * Authorization code to be stored.
	 * @param $client_id
	 * Client identifier to be stored.
	 * @param $user_id
	 * User identifier to be stored.
	 * @param $redirect_uri
	 * Redirect URI to be stored.
	 * @param $expires
	 * Expiration to be stored.
	 * @param $scope
	 * (optional) Scopes to be stored in space-separated string.
	 *
	 * @ingroup oauth2_section_4
	 */
	public void setAuthCode(String code, String client_id, String user_id, String redirect_uri, String expires, String scope);

	/**
	 * Grant refresh access tokens.
	 *
	 * Retrieve the stored data for the given refresh token.
	 *
	 * Required for OAuth2::GRANT_TYPE_REFRESH_TOKEN.
	 *
	 * @param $refresh_token
	 * Refresh token to be check with.
	 *
	 * @return
	 * An associative array as below, and NULL if the refresh_token is
	 * invalid:
	 * - client_id: Stored client identifier.
	 * - expires: Stored expiration unix timestamp.
	 * - scope: (optional) Stored scope values in space-separated string.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-6
	 *
	 * @ingroup oauth2_section_6
	 */
	public Map<String, String> getRefreshToken(String refresh_token);

	/**
	 * Take the provided refresh token values and store them somewhere.
	 *
	 * This function should be the storage counterpart to getRefreshToken().
	 *
	 * If storage fails for some reason, we're not currently checking for
	 * any sort of success/failure, so you should bail out of the script
	 * and provide a descriptive fail message.
	 *
	 * Required for OAuth2::GRANT_TYPE_REFRESH_TOKEN.
	 *
	 * @param $refresh_token
	 * Refresh token to be stored.
	 * @param $client_id
	 * Client identifier to be stored.
	 * @param $expires
	 * expires to be stored.
	 * @param $scope
	 * (optional) Scopes to be stored in space-separated string.
	 *
	 * @ingroup oauth2_section_6
	 */
	public void setRefreshToken(String refresh_token, String client_id, String user_id, String expires, String scope);

}
