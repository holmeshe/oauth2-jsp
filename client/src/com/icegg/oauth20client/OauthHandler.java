package com.icegg.oauth20client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class OauthHandler {
	public static void userAuthorization(
			HttpServletResponse response,
			String state)
	{
		Map<String, String> query = new HashMap<String, String>();
		query.put("client_id", ConstValue.CLIENT_ID);
		query.put("response_type", "code");
		query.put("state", state);
		query.put("redirect_uri", Utility.percentEncode(ConstValue.LOCAL + ConstValue.CALL_BACK));
		
		Map<String, Map<String, String>> params = new HashMap<String, Map<String, String>>();
		params.put("query", query);
		
		String requestUri = ConstValue.DOMAIN + ConstValue.AUTHORIZATION_ENDPOINT;
		
		response.setStatus(ConstValue.HTTP_FOUND);
		response.addHeader("Location", Utility.buildUri(requestUri, params));
	}
	
	public static Map<String, String> doCallBack(HttpServletRequest request)
	{
		String error = request.getParameter("error");
		if (Utility.checkStringIsNotVoid(error))
		{
			// here we deal with the redirection exception, and inform the caller
			String desc = request.getParameter("error_description");
			throw new OauthException(error, desc);
		}
		
		Map<String, String> query = new HashMap<String, String>();
		query.put("client_id", ConstValue.CLIENT_ID);
		query.put("client_secret", ConstValue.CLIENT_SECRET);
		query.put("grant_type", "authorization_code");
		query.put("redirect_uri", request.getParameter("redirect_uri"));
		query.put("code", request.getParameter("code"));
		
		Map<String, Map<String, String>> params = new HashMap<String, Map<String, String>>();
		params.put("query", query);
		
		String requestUri = ConstValue.DOMAIN + ConstValue.ACCESS_TOKEN_ENDPOINT;

		HttpURLConnection con = null;
		try {
			URL serv = new URL(Utility.buildUri(requestUri, params));
			con = (HttpURLConnection)serv.openConnection();
			con.connect();
			
			InputStream in = con.getInputStream();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buff = new byte[1024];
			int n = 0;
			while ((n = in.read(buff)) != -1)
			{
				out.write(buff, 0, n);
			}
			
			String str = new String(out.toByteArray(), "utf-8");

			return Utility.parserToMap(str);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			// an error happened, check if is there any information there
			if (con != null)
			{
				//read the error information generated from the oauth server
				InputStream in = con.getErrorStream();
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				byte[] buff = new byte[1024];
				int n = 0;
				try {
					while ((n = in.read(buff)) != -1)
					{
						out.write(buff, 0, n);
					}
					String str = new String(out.toByteArray(), "utf-8");
					Map<String, String> errorInfo =  Utility.parserToMap(str);
					//inform the caller
					throw new OauthException(errorInfo.get("error"), errorInfo.get("error_description"));
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
			else
			{
				e.printStackTrace();
			}
		}
		return null;
	}
	
	public static Map<String, String> doRefresh(HttpServletRequest request)
	{	
		Map<String, String> query = new HashMap<String, String>();
		query.put("client_id", ConstValue.CLIENT_ID);
		query.put("client_secret", ConstValue.CLIENT_SECRET);
		query.put("grant_type", "refresh_token");
		query.put("redirect_uri", ConstValue.LOCAL + ConstValue.CALL_BACK);
		query.put("refresh_token", request.getParameter("refresh_token"));
		
		Map<String, Map<String, String>> params = new HashMap<String, Map<String, String>>();
		params.put("query", query);
		
		String requestUri = ConstValue.DOMAIN + ConstValue.ACCESS_TOKEN_ENDPOINT;

		HttpURLConnection con = null;
		try {
			URL serv = new URL(Utility.buildUri(requestUri, params));
			con = (HttpURLConnection)serv.openConnection();
			con.connect();
			
			InputStream in = con.getInputStream();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buff = new byte[1024];
			int n = 0;
			while ((n = in.read(buff)) != -1)
			{
				out.write(buff, 0, n);
			}
			
			String str = new String(out.toByteArray(), "utf-8");

			return Utility.parserToMap(str);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			// an error happened, check if is there any information there
			if (con != null)
			{
				//read the error information generated from the oauth server
				InputStream in = con.getErrorStream();
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				byte[] buff = new byte[1024];
				int n = 0;
				try {
					while ((n = in.read(buff)) != -1)
					{
						out.write(buff, 0, n);
					}
					String str = new String(out.toByteArray(), "utf-8");
					Map<String, String> errorInfo =  Utility.parserToMap(str);
					//inform the caller
					throw new OauthException(errorInfo.get("error"), errorInfo.get("error_description"));
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
			else
			{
				e.printStackTrace();
			}
		}
		return null;
	}
}
