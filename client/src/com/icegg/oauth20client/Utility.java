package com.icegg.oauth20client;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONException;
import org.json.JSONObject;

public class Utility {
	public static final String ENCODING = "UTF-8";

	public static boolean checkStringIsNotVoid(String v) {
		if (v == null)
			return false;

		String ck = v.trim();
		if (ck.length() == 0)
			return false;

		return true;
	}

	public static boolean checkStringIsTrue(String v) {
		if (v == null || !v.equals("true"))
			return false;

		return true;
	}

	public static boolean checkArrayIsNotVoid(List<String> l) {
		if (l == null || l.size() == 0)
			return false;

		return true;
	}

	public String map2Json(Map<String, String> inMap) {

		return "";
	}

	public static Map<String, String> param2Map(HttpServletRequest req) {
		Map<String, String> map = new HashMap<String, String>();
		Enumeration<String> paramNames = req.getParameterNames();
		while (paramNames.hasMoreElements()) {

			String paramName = paramNames.nextElement();

			String[] paramValues = req.getParameterValues(paramName);

			System.out.println(paramName + ":" + paramValues.length);
			if (paramValues.length == 1) {
				String paramValue = paramValues[0];
				System.out.println(paramName + ":" + paramValue);
				if (paramValue.length() != 0) {
					map.put(paramName, paramValue);
				}
			}
		}
		return map;
	}

	public static String stringToHTMLString(String string) {
		StringBuffer sb = new StringBuffer(string.length());
		// true if last char was blank
		boolean lastWasBlankChar = false;
		int len = string.length();
		char c;

		for (int i = 0; i < len; i++) {
			c = string.charAt(i);
			if (c == ' ') {
				// blank gets extra work,
				// this solves the problem you get if you replace all
				// blanks with &nbsp;, if you do that you loss
				// word breaking
				if (lastWasBlankChar) {
					lastWasBlankChar = false;
					sb.append("&nbsp;");
				} else {
					lastWasBlankChar = true;
					sb.append(' ');
				}
			} else {
				lastWasBlankChar = false;
				//
				// HTML Special Chars
				if (c == '"')
					sb.append("&quot;");
				else if (c == '&')
					sb.append("&amp;");
				else if (c == '<')
					sb.append("&lt;");
				else if (c == '>')
					sb.append("&gt;");
				else if (c == '\n')
					// Handle Newline
					sb.append("&lt;br/&gt;");
				else {
					int ci = 0xffff & c;
					if (ci < 160)
						// nothing special only 7 Bit
						sb.append(c);
					else {
						// Not 7 Bit use the unicode system
						sb.append("&#");
						sb.append(new Integer(ci).toString());
						sb.append(';');
					}
				}
			}
		}
		return sb.toString();
	}

	public static String toQueryString(Map<?, ?> data)
			throws UnsupportedEncodingException {
		StringBuffer queryString = new StringBuffer();
		for (Map.Entry<?, ?> pair : data.entrySet()) {
			queryString.append(URLEncoder.encode((String) pair.getKey(),
					"UTF-8")
					+ "=");
			queryString.append(URLEncoder.encode((String) pair.getValue(),
					"UTF-8")
					+ "&");
		}

		return queryString.toString();
	}

	public static String percentEncode(String s) {
		if (s == null) {
			return "";
		}
		try {
			return URLEncoder.encode(s, ENCODING)
					// OAuth encodeURLEncoders some characters differently:
					.replace("+", "%20").replace("*", "%2A")
					.replace("%7E", "~");
			// This could be done faster with more hand-crafted code.
		} catch (UnsupportedEncodingException wow) {
			throw new RuntimeException(wow.getMessage(), wow);
		}
	}

	public static String decodePercent(String s) {
		try {
			String ss = URLDecoder.decode(s, ENCODING);
			ss = ss.replaceAll(" ", "+");
			return ss;
			// This implements http://oauth.pbwiki.com/FlexibleDecoding
		} catch (java.io.UnsupportedEncodingException wow) {
			throw new RuntimeException(wow.getMessage(), wow);
		}
	}

	/**
	 * Build the absolute URI based on supplied URI and parameters.
	 * 
	 * @param $uri
	 *            An absolute URI.
	 * @param $params
	 *            Parameters to be append as GET.
	 * 
	 * @return An absolute URI with supplied parameters.
	 * 
	 * @ingroup oauth2_section_4
	 */
	static public String buildUri(String uri,
			Map<String, Map<String, String>> params) {
		URI uRI;
		try {

			uRI = new URI(uri);
			Map<String, String> mapURI = new HashMap<String, String>();
			System.out.println("Client:scheme:" + uRI.getScheme());
			System.out.println("Client:user:" + uRI.getUserInfo());
			System.out.println("Client:pass:" + uRI.getAuthority());
			System.out.println("Client:host:" + uRI.getHost());
			System.out.println("Client:port:" + uRI.getPort());
			System.out.println("Client:path:" + uRI.getPath());
			System.out.println("Client:query:" + uRI.getQuery());
			System.out.println("Client:fragment:" + uRI.getFragment());
			mapURI.put("scheme", uRI.getScheme());
			mapURI.put("user", uRI.getUserInfo());
			mapURI.put("pass", uRI.getAuthority());
			mapURI.put("host", uRI.getHost());
			mapURI.put("port", uRI.getPort() != -1 ? "" + uRI.getPort() : null);
			mapURI.put("path", uRI.getPath());
			mapURI.put("query", uRI.getQuery());
			mapURI.put("fragment", uRI.getFragment());

			Iterator<Map.Entry<String, Map<String, String>>> iter = params
					.entrySet().iterator();
			while (iter.hasNext()) {
				Map.Entry<String, Map<String, String>> entry = (Map.Entry<String, Map<String, String>>) iter
						.next();
				String key = (String) entry.getKey();
				Map<String, String> val = entry.getValue();
				System.out.println("Client:param:" + key + ":"
						+ Utility.toQueryString(val));
				if (Utility.checkStringIsNotVoid((mapURI.get(key)))) {
					mapURI.put(key, mapURI.get(key) + "&"
							+ Utility.toQueryString(val));
				} else {
					mapURI.put(key, Utility.toQueryString(val));
				}

			}

			// Put humpty dumpty back together
			String res = (Utility.checkStringIsNotVoid((mapURI.get("scheme"))) ? mapURI
					.get("scheme")
					+ "://"
					: "")
					+ (Utility.checkStringIsNotVoid((mapURI.get("user"))) ? mapURI
							.get("user")
							+ (Utility.checkStringIsNotVoid(mapURI.get("pass")) ? ":"
									+ mapURI.get("pass")
									: "") + "@"
							: "")
					+ (Utility.checkStringIsNotVoid(mapURI.get("host")) ? mapURI
							.get("host")
							: "")
					+ (Utility.checkStringIsNotVoid(mapURI.get("port")) ? ":"
							+ mapURI.get("port") : "")
					+ (Utility.checkStringIsNotVoid(mapURI.get("path")) ? mapURI
							.get("path")
							: "")
					+ (Utility.checkStringIsNotVoid(mapURI.get("query")) ? "?"
							+ mapURI.get("query") : "")
					+ (Utility.checkStringIsNotVoid(mapURI.get("fragment")) ? "#"
							+ mapURI.get("fragment")
							: "");

			System.out.println("Client:" + res);
			return res;
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	public static Map<String, String> parserToMap(String s) {
		Map<String, String> map = new HashMap<String, String>();
		JSONObject json;
		try {
			json = new JSONObject(s);
			Iterator keys = json.keys();
			while (keys.hasNext()) {
				String key = (String) keys.next();
				String value = json.get(key).toString();
				if (value.startsWith("{") && value.endsWith("}")) {

				} else {
					map.put(key, value);
				}

			}
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return map;
	}
}
