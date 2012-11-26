package com.icegg.oauth20imp.implementation;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

import com.icegg.oauth20imp.common.ConstValue;
import com.icegg.oauth20imp.common.Utility;
import com.icegg.oauth20imp.interfaces.IOauth2Storage;

public class Oauth2StoragePDO implements IOauth2Storage {

	static {
		try {
			Class.forName("org.gjt.mm.mysql.Driver");

		} catch (ClassNotFoundException ce) {
			ce.printStackTrace();
		}
	}
	/**
	 * @#+ Centralized table names
	 * 
	 * @var string
	 */

	private String TABLE_CLIENTS = "clients";
	private String TABLE_CODES = "auth_codes";
	private String TABLE_TOKENS = "access_tokens";
	private String TABLE_REFRESH = "refresh_tokens";

	private String sqlAddClient = "INSERT INTO "
			+ TABLE_CLIENTS
			+ " (client_id, client_secret, redirect_uri) VALUES ('%1$s', '%2$s', '%3$s')";

	private String sqlChkClient = "SELECT client_secret FROM " + TABLE_CLIENTS + " WHERE client_id = '%1$s'";

	private String sqlGetClientDetails = "SELECT redirect_uri FROM " + TABLE_CLIENTS
			+ " WHERE client_id = %1$s";

	private String sqlSetCode = "INSERT INTO "
			+ TABLE_CODES
			+ " (code, client_id, user_id, redirect_uri, expires, scope) VALUES ('%1$s', %2$s, %3$s, '%4$s', '%5$s', '%6$s')";

	private String sqlGetCode = "SELECT code, client_id, user_id, redirect_uri, expires, scope FROM "
			+ TABLE_CODES + " WHERE code = '%1$s'";

	private String sqlSetToken = "INSERT INTO %1$s (%2$s, client_id, user_id, expires, scope) VALUES ('%3$s', %4$s, %5$s, '%6$s', '%7$s')";

	private String sqlGetToken = "SELECT %1$s, client_id, expires, scope, user_id FROM %2$s WHERE %3$s = '%4$s'";


	private String sqlUrl = "jdbc:mysql://%1$s:%2$s/db_oauth20?user=%3$s&password=%4$s&useUnicode=true&characterEncoding=utf8";
	
	private String url;
	
	public String SALT = "CHANGE_ME!";

	/** @#- */

	/**
	 * Implements OAuth2::__construct().
	 */
	public Oauth2StoragePDO() {
		url = String.format(
		sqlUrl, ConstValue.MYSQL_IP, 
		ConstValue.MYSQL_PORT, ConstValue.MYSQL_USR, ConstValue.MYSQL_PASS);
		System.out.println(url);
	}
	

	/**
	 * Little helper function to add a new client to the database.
	 * 
	 * Do NOT use this in production! This sample code stores the secret in
	 * plaintext!
	 * 
	 * @param $client_id
	 *            Client identifier to be stored.
	 * @param $client_secret
	 *            Client secret to be stored.
	 * @param $redirect_uri
	 *            Redirect URI to be stored.
	 */
	public void addClient(String client_id, String client_secret,
			String redirect_uri) {
		
		try {
			Connection conn = DriverManager.getConnection(url);
			try {
				String sql = String.format(sqlAddClient, client_id, client_secret,
						redirect_uri);
				Statement stmt = conn.createStatement();

				System.out.println(sql);
				stmt.execute(sql);
				
				conn.close();

			} catch (SQLException e) {
				e.printStackTrace();
				conn.close();
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	}

	/**
	 * Implements IOAuth2Storage::checkClientCredentials().
	 * 
	 */
	public boolean checkClientCredentials(String client_id, String client_secret) {
		try {
			Connection conn = DriverManager.getConnection(url);
			try {
			
				String sql = String.format(sqlChkClient, client_id);
				Statement stmt = conn.createStatement();
	
				System.out.println(sql);
				ResultSet rs = stmt.executeQuery(sql);
				if (!rs.next()) {
					conn.close();
					return false;
				}
				String secret = rs.getString("client_secret");
				conn.close();
				
				System.out.println(client_secret + ":" + secret);
				if (!Utility.checkStringIsNotVoid(client_secret))
				{
					conn.close();
					return !Utility.checkStringIsNotVoid(secret);
				}
	
				return client_secret.equals(secret);
			} catch (SQLException e) {
				System.out.println("sql error!");
				e.printStackTrace();
				conn.close();
				return false;
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			System.out.println("sql error 1!");
			e1.printStackTrace();
			return false;
		}
	}

	/**
	 * Implements IOAuth2Storage::getRedirectUri().
	 */
	public Map<String, String> getClientDetails(String client_id) {
		try {
			Connection conn = DriverManager.getConnection(url);
			try {
				String sql = String.format(sqlGetClientDetails, client_id);
				Statement stmt = conn.createStatement();
	
				System.out.println(sql);
				ResultSet rs = stmt.executeQuery(sql);
				if (!rs.next()) {
					conn.close();
					return null;
				}
	
				Map<String, String> res = new HashMap<String, String>();
				res.put("redirect_uri", rs.getString("redirect_uri"));
				conn.close();
				return res;
			} catch (SQLException e) {
				e.printStackTrace();
				conn.close();
				return null;
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
	}

	/**
	 * Implements IOAuth2Storage::getAccessToken().
	 */
	public Map<String, String> getAccessToken(String oauth_token) {
		return getToken(oauth_token, false);
	}

	/**
	 * @see IOAuth2Storage::getRefreshToken()
	 */
	public Map<String, String> getRefreshToken(String refresh_token) {
		return this.getToken(refresh_token, true);
	}

	/**
	 * Implements IOAuth2Storage::setAccessToken().
	 */
	public void setAccessToken(String oauth_token, String client_id,
			String user_id, String expires, String scope) {
		this.setToken(oauth_token, client_id, user_id, expires, scope, false);
	}

	/**
	 * @see IOAuth2Storage::setRefreshToken()
	 */
	public void setRefreshToken(String refresh_token, String client_id,
			String user_id, String expires, String scope) {
		this.setToken(refresh_token, client_id, user_id, expires, scope, true);
	}

	/**
	 * Implements IOAuth2Storage::getAuthCode().
	 */
	public Map<String, String> getAuthCode(String code) {
		try {
			Connection conn = DriverManager.getConnection(url);
			try {
				String sql = String.format(sqlGetCode, code);
				Statement stmt = conn.createStatement();
	
				ResultSet rs = stmt.executeQuery(sql);
				if (!rs.next()) {
					conn.close();
					return null;
				}
	
				Map<String, String> res = new HashMap<String, String>();
				res.put("code", rs.getString("code"));
				res.put("client_id", rs.getString("client_id"));
				res.put("user_id", rs.getString("user_id"));
				res.put("redirect_uri", rs.getString("redirect_uri"));
				res.put("expires", rs.getString("expires"));
				res.put("scope", rs.getString("scope"));
	
				conn.close();
				return res;
			} catch (SQLException e) {
				e.printStackTrace();
				conn.close();
				return null;
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
	}

	/**
	 * Implements IOAuth2Storage::setAuthCode().
	 */
	public void setAuthCode(String code, String client_id, String user_id,
			String redirect_uri, String expires, String scope) {
		try {
			Connection conn = DriverManager.getConnection(url);
			try {
				String sql = String.format(sqlSetCode, code, client_id, user_id,
						redirect_uri, expires, scope);
				Statement stmt = conn.createStatement();
	
				System.out.println(sql);
				stmt.execute(sql);
			} catch (SQLException e) {
				e.printStackTrace();
				conn.close();
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}

	/**
	 * @see IOAuth2Storage::checkRestrictedGrantType()
	 */
	public boolean checkRestrictedGrantType(String client_id, String grant_type) {
		return true; // Not implemented
	}

	/**
	 * Creates a refresh or access token
	 * 
	 * @param string
	 *            $token - Access or refresh token id
	 * @param string
	 *            $client_id
	 * @param mixed
	 *            $user_id
	 * @param int $expires
	 * @param string
	 *            $scope
	 * @param bool
	 *            $isRefresh
	 */
	protected void setToken(String token, String client_id, String user_id,
			String expires, String scope, boolean isRefresh) {
		try {
			Connection conn = DriverManager.getConnection(url);
			try {
				String tableName = isRefresh ? TABLE_REFRESH : TABLE_TOKENS;
				String tokenname = isRefresh ? "refresh_token" : "oauth_token";
				String sql = String.format(sqlSetToken, tableName,tokenname, token, client_id,
						user_id, expires, scope);
				Statement stmt = conn.createStatement();
	
				System.out.println(sql);
				stmt.execute(sql);
			} catch (SQLException e) {
				e.printStackTrace();
				conn.close();
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}

	/**
	 * Retrieves an access or refresh token.
	 * 
	 * @param string
	 *            $token
	 * @param bool
	 *            $refresh
	 */
	protected Map<String, String> getToken(String token, boolean isRefresh) {
		try {
			Connection conn = DriverManager.getConnection(url);
			try {
				String tableName = isRefresh ? TABLE_REFRESH : TABLE_TOKENS;
				String tokenName = isRefresh ? "refresh_token" : "oauth_token";
	
				String sql = String
						.format(sqlGetToken, tokenName, tableName, tokenName, token);
				Statement stmt = conn.createStatement();
	
				ResultSet rs = stmt.executeQuery(sql);
				if (!rs.next()) {
					conn.close();
					return null;
				}
	
				Map<String, String> res = new HashMap<String, String>();
				res.put(tokenName, rs.getString(tokenName));
				res.put("client_id", rs.getString("client_id"));
				res.put("expires", rs.getString("expires"));
				res.put("scope", rs.getString("scope"));
				res.put("user_id", rs.getString("user_id"));
	
				return res;
			} catch (SQLException e) {
				e.printStackTrace();
				conn.close();
				return null;
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
	}

}
