 <%--
  ~  Copyright 2016 Red Hat, Inc. and/or its affiliates
  ~  and other contributors as indicated by the @author tags.
  ~
  ~  Licensed under the Apache License, Version 2.0 (the "License");
  ~  you may not use this file except in compliance with the License.
  ~  You may obtain a copy of the License at
  ~
  ~  http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~  Unless required by applicable law or agreed to in writing, software
  ~  distributed under the License is distributed on an "AS IS" BASIS,
  ~  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ~  See the License for the specific language governing permissions and
  ~  limitations under the License.
  ~
  --%>
<%@page import="org.keycloak.AuthorizationContext" %>
<%@ page import="org.keycloak.KeycloakSecurityContext" %>
<%@ page import="org.keycloak.common.util.KeycloakUriBuilder" %>
<%@ page import="org.keycloak.constants.ServiceUrlConstants" %>
<%@ page import="org.keycloak.representations.idm.authorization.Permission" %>

<%
    KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    AuthorizationContext authzContext = keycloakSecurityContext.getAuthorizationContext();
%>
<jsp:useBean id="controller" class="com.anujk.volpaylogin.Controller"
	scope="request" />
<html>
<head>
<title>Home Page</title>
</head>
<body>
	<h2>Welcome!</h2>

	<%
	controller.handleLogout(request, response);
	%>
	<%
	controller.setCookies(request, response);
	%>
	<c:set var="isLoggedIn" value="<%=controller.isLoggedIn(request)%>" />
	<c:if test="${isLoggedIn}">
		<div id="authenticated" style="display: block" class="menu">
			<button name="logoutBtn"
				onclick="location.href = '<%=request.getContextPath()%>/index.jsp?action=logout'">Logout</button>
		</div>
	</c:if>
</body>
</html>
