package com.icegg.oauth20imp.exceptions;

import java.util.HashMap;
import java.util.Map;

import com.icegg.oauth20imp.common.ConstValue;
import com.icegg.oauth20imp.common.Utility;

public class Oauth2RedirectException extends OAuth2ServerException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	/**
	 * Redirect the end-user's user agent with error message.
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1
	 * 
	 * @ingroup oauth2_error
	 */

	protected String redirectUri;

	/**
	 * @param $redirect_uri
	 *            An absolute URI to which the authorization server will
	 *            redirect the user-agent to when the end-user authorization
	 *            step is completed.
	 * @param $error
	 *            A single error code as described in Section 4.1.2.1
	 * @param $error_description
	 *            (optional) A human-readable text providing additional
	 *            information, used to assist in the understanding and
	 *            resolution of the error occurred.
	 * @param $state
	 *            (optional) REQUIRED if the "state" parameter was present in
	 *            the client authorization request. Set to the exact value
	 *            received from the client.
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
	 * 
	 * @ingroup oauth2_error
	 */
	public Oauth2RedirectException(String redirect_uri, String error,
			String error_description, String state) {
		super(ConstValue.HTTP_FOUND, error, error_description);

		headers.clear();
		this.redirectUri = redirect_uri;
		if (Utility.checkStringIsNotVoid(state)) {
			this.errorData.put("state", state);
		}
		Map<String, Map<String, String>> params = 
				new HashMap<String, Map<String, String>>();
		params.put("query", errorData);

		headers.put("Location", Utility.buildUri(redirectUri, params));
	}

}
