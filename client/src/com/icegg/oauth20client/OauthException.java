package com.icegg.oauth20client;


public class OauthException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	
	String error;
	String desc;
	
	public OauthException(String error, String error_description) {
		this.error = error;
		this.desc = error_description;
	}
	
	public String toString()
	{
		return "OauthException error:" + error + " description:" + desc;
	}
}
