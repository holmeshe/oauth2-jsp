package com.icegg.oauth20imp.common;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import com.icegg.oauth20imp.exceptions.OAuth2ServerException;

public class HttpDealer {

	/**
	 * redirect to client with code
	 *
	 *
	 */
	public static void finishClientAuthorization(String uri,
			Map<String, Map<String, String>> params, HttpServletResponse rspn) {
			rspn.setStatus(ConstValue.HTTP_FOUND);

			rspn.addHeader("Location", Utility.buildUri(uri, params));


	}
	
	protected static void sendJsonHeaders(HttpServletResponse response) {
		response.addHeader("Content-Type", "application/json");
		response.addHeader("Cache-Control", "no-store");
	}


	
	protected static void sendExceptionHeaders(
			HttpServletResponse response, OAuth2ServerException e) {
		Iterator<Map.Entry<String, String>> iter = e.getHeaderFields().entrySet().iterator();
		while (iter.hasNext()) {
			Map.Entry<String, String> entry = (Map.Entry<String, String>) iter
					.next();
			String key = (String) entry.getKey();
			String val = (String) entry.getValue();
			response.addHeader(key, val);
		}
	}
	
	/**
	 * Send out error message in JSON.
	 *
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.1
	 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
	 *
	 * @ingroup oauth2_error
	 */
	public static void sendExceptionResponse(
			HttpServletResponse response, 
			OAuth2ServerException e) {
		response.setStatus(e.getHttpCode());
		sendExceptionHeaders(response, e);
		if (e.getHttpCode() != ConstValue.HTTP_FOUND)
		{
			try {
					java.io.PrintWriter writer = response.getWriter();
					writer.write(e.toString());
					writer.flush();
					writer.close();
				
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

	/**
	 * Send out token in JSON.
	 */
	public static void sendToken(
			HttpServletResponse response, 
			Map<String, String> token)
	{
		
		java.io.PrintWriter writer;
		sendJsonHeaders(response);
		try {
			writer = response.getWriter();
			writer.write(JsonSerializer.serialize(token));
			writer.flush();
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
