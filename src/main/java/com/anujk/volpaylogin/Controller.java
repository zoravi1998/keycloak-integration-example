/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.anujk.volpaylogin;

import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.constants.ServiceUrlConstants;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.Set;
import org.json.JSONObject;

/**
 * Controller simplifies access to the server environment from the JSP.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2015 Red Hat Inc.
 */
public class Controller {

	String name = "DEMOUSER", role = "admin", url = "/volpayui", tenant = "MASTER", locale = "en-US", timezone = "UTC",
			timeout = "20", realm = "volpay", clientname = "volpaylogin";
	Cookie cookie[];

	public boolean isLoggedIn(HttpServletRequest req) {
		return getSession(req) != null;
	}

	public void handleLogout(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

		if (isLogoutAction(req)) {

			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
				}

				public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
				}
			} };

			try {
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			} catch (Exception e) {
				System.out.println(e);
			}
			
			Cookie cookies[] = req.getCookies();
			for (Cookie cookie : cookies) {
				cookie.setMaxAge(0);
				cookie.setValue(null);
				cookie.setPath("/");
				res.addCookie(cookie);
			}
			req.logout();
			res.sendRedirect(req.getContextPath());
		}
	}

	public boolean isLogoutAction(HttpServletRequest req) {
		return getAction(req).equals("logout");
	}

	public String getAccountUri(HttpServletRequest req) {
		KeycloakSecurityContext session = getSession(req);
		String baseUrl = getAuthServerBaseUrl(req);
		String realm = session.getRealm();
		return KeycloakUriBuilder.fromUri(baseUrl).path(ServiceUrlConstants.ACCOUNT_SERVICE_PATH)
				.queryParam("referrer", "authz-servlet").queryParam("referrer_uri", getReferrerUri(req)).build(realm)
				.toString();
	}

	public void readConfig() {
		JSONObject jsonObject;
		try {
			//using 
			InputStream resourceAsStream = (InputStream) Controller.class.getClassLoader()
					.getResourceAsStream("config.json");
			BufferedReader reader = new BufferedReader(new InputStreamReader(resourceAsStream));
			String s;
			StringBuilder json = new StringBuilder();

			while ((s = reader.readLine()) != null) {
				json.append(s);
			}
			jsonObject = new JSONObject(json.toString());
			realm = (String) jsonObject.get("realm");
			clientname = (String) jsonObject.get("client-name");
			url = (String) jsonObject.get("url");
			tenant = (String) jsonObject.get("tenant");
			locale = (String) jsonObject.get("locale");
			timezone = (String) jsonObject.get("timezone");
			timeout = (String) jsonObject.get("timeout");
			//System.out.println(url + "\n" + tenant + "\n" + locale + "\n" + timezone + "\n" + timeout + "\n" + realm
			//		+ "\n" + clientname);
		} catch (Exception e) {
			System.out.println(e);
		}
	}

	public void setCookies(HttpServletRequest request, HttpServletResponse response) {
		//System.out.println("Setting cookies");
		try {
			// getting values for the cookies from Keycloak
			Identity it = new Identity(getSession(request), this.clientname);
			if (it.getName() != null) {
				this.name = it.getName();
			}

			Set<String> roles = it.getRoles(request);
			if (roles != null) {
				String[] myArray = new String[roles.size()];
				roles.toArray(myArray);
				this.role = myArray[0];
			}

			// read configuration from json File
			readConfig();
			// creating cookies
			cookie = new Cookie[6];
			cookie[0] = new Cookie("jwttenant", this.tenant);
			cookie[1] = new Cookie("jwtuser", this.name);
			cookie[2] = new Cookie("jwtrole", this.role);
			cookie[3] = new Cookie("jwtlocale", this.locale);
			cookie[4] = new Cookie("jwttimezone", this.timezone);
			cookie[5] = new Cookie("jwttimeout", this.timeout);

			for (int i = 0; i < 6; i++) {
				cookie[i].setPath("/");
				cookie[i].setMaxAge(-1);
				response.addCookie(cookie[i]);
			}
			// String uri = "<script>window.open ('" + this.url + "','_blank');</script>";
			// response.getWriter().write(uri);
			// response.getWriter().flush();
			response.sendRedirect(url);
		} catch (Exception e) {
			System.out.println(e);
		}

	}

	private String getReferrerUri(HttpServletRequest req) {
		StringBuffer uri = req.getRequestURL();
		String q = req.getQueryString();
		if (q != null) {
			uri.append("?").append(q);
		}
		return uri.toString();
	}

	private String getAuthServerBaseUrl(HttpServletRequest req) {
		try {
			AdapterDeploymentContext deploymentContext = (AdapterDeploymentContext) req.getServletContext()
					.getAttribute(AdapterDeploymentContext.class.getName());
			KeycloakDeployment deployment = deploymentContext.resolveDeployment(null);
			return deployment.getAuthServerBaseUrl();
		} catch (Exception e) {
			System.out.println(e);
		}
		return null;
	}

	private KeycloakSecurityContext getSession(HttpServletRequest req) {
		return (KeycloakSecurityContext) req.getAttribute(KeycloakSecurityContext.class.getName());
	}

	private String getAction(HttpServletRequest req) {
		if (req.getParameter("action") == null)
			return "";
		return req.getParameter("action");
	}

	/*
	 * public static void main(String[] args) { Controller c = new Controller();
	 * c.readConfig(); }
	 */

}
