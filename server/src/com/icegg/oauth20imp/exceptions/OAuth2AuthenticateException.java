package com.icegg.oauth20imp.exceptions;

import java.util.Iterator;
import java.util.Map;

import com.icegg.oauth20imp.common.Utility;

public class OAuth2AuthenticateException extends OAuth2ServerException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	/**
	 * Send an error header with the given realm and an error, if provided.
	 * Suitable for the bearer token type.
	 * 
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04#section-2.4
	 * 
	 * @ingroup oauth2_error
	 */

	protected String header;

	/**
	 * 
	 * @param $http_status_code
	 *            HTTP status code message as predefined.
	 * @param $error
	 *            The "error" attribute is used to provide the client with the
	 *            reason why the access request was declined.
	 * @param $error_description
	 *            (optional) The "error_description" attribute provides a
	 *            human-readable text containing additional information, used to
	 *            assist in the understanding and resolution of the error
	 *            occurred.
	 * @param $scope
	 *            A space-delimited list of scope values indicating the required
	 *            scope of the access token for accessing the requested
	 *            resource.
	 */
	public OAuth2AuthenticateException(int httpCode, String tokenType,
			String realm, String error, String error_description, String scope) {
		super(httpCode, error, error_description);

		if (Utility.checkStringIsNotVoid(scope)) {
			this.errorData.put("scope", scope);
		}

		headers.clear();
		String header = tokenType + "realm=\"" + realm + "\"";
		// Build header

		Iterator<Map.Entry<String, String>> iter = errorData.entrySet()
				.iterator();
		while (iter.hasNext()) {
			Map.Entry<String, String> entry = (Map.Entry<String, String>) iter
					.next();
			String key = (String) entry.getKey();
			String val = (String) entry.getValue();
			header += ", " + key + "=\"" + val + "\"";
		}
		headers.put("WWW-Authenticate", header);
	}
}
