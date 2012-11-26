package com.icegg.oauth20imp.exceptions;

import java.util.HashMap;
import java.util.Map;

import com.icegg.oauth20imp.common.JsonSerializer;
import com.icegg.oauth20imp.common.Utility;

public class OAuth2ServerException extends RuntimeException {

	protected Map<String, String> headers;
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	/**
	 * OAuth2 errors that require termination of OAuth2 due to an error.
	 * 
	 */
	protected int httpCode;
	protected Map<String, String> errorData = new HashMap<String, String>();

	/**
	 * @param $http_status_code
	 *            HTTP status code message as predefined.
	 * @param $error
	 *            A single error code.
	 * @param $error_description
	 *            (optional) A human-readable text providing additional
	 *            information, used to assist in the understanding and
	 *            resolution of the error occurred.
	 */
	public OAuth2ServerException(int http_status_code, String error,
			String error_description) {
		this.httpCode = http_status_code;

		this.errorData.put("error", error);
		if (Utility.checkStringIsNotVoid(error_description)) {
			this.errorData.put("error_description", error_description);
		}
		
		headers = new HashMap<String, String>();
		headers.put("Content-Type", "application/json");
		headers.put("Cache-Control", "no-store");
	}
	
	public Map<String, String> getHeaderFields()
	{
		return headers;
	}

	/**
	 * @return string
	 */
	public String getDescription() {
		return Utility.checkStringIsNotVoid(this.errorData
				.get("error_description")) ? this.errorData
				.get("error_description") : null;
	}

	/**
	 * @return string
	 */
	public int getHttpCode() {
		return this.httpCode;
	}

	/**
	 * @see Exception::__toString()
	 */
	public String toString() {
		return JsonSerializer.serialize(this.errorData);
	}
}
