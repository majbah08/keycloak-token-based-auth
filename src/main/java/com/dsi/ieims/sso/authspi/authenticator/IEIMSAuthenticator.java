package com.dsi.ieims.sso.authspi.authenticator;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.UserStorageManager;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import javax.naming.AuthenticationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;

@Slf4j public class IEIMSAuthenticator implements Authenticator {

    @Override public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        if (!hasValidJwt(authenticationFlowContext)) {
            authenticationFlowContext.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }

        String userName = retrieveQueryParameter(authenticationFlowContext, "user_name");
        UserModel userModel = null;
        if (!userName.isBlank()) {
            userModel = authenticationFlowContext.getSession().users().getUserByUsername(authenticationFlowContext.getRealm(), userName);
        }
        KeycloakSession session = authenticationFlowContext.getSession();
        RealmModel realm = authenticationFlowContext.getRealm();

        if (userModel == null || userModel.getUsername() == null) {
            log.info("user not found in realm");
            UserModel user = session.users().addUser(realm, userName);
            user.setEnabled(true);
            user.setUsername(userName);

            authenticationFlowContext.setUser(user);
            authenticationFlowContext.getAuthenticationSession().setAuthenticatedUser(user);
            authenticationFlowContext.getEvent().user(user);
            authenticationFlowContext.getEvent().success();
            authenticationFlowContext.newEvent().event(EventType.LOGIN);

            authenticationFlowContext.getEvent()
                    .client(authenticationFlowContext.getAuthenticationSession().getClient()
                            .getClientId()).detail(Details.REDIRECT_URI,
                            authenticationFlowContext.getAuthenticationSession().getRedirectUri())
                    .detail(Details.AUTH_METHOD,
                            authenticationFlowContext.getAuthenticationSession().getProtocol());

            String authType = authenticationFlowContext.getAuthenticationSession()
                    .getAuthNote(Details.AUTH_TYPE);
            if (authType != null) {
                authenticationFlowContext.getEvent().detail(Details.AUTH_TYPE, authType);
            }

        }else {
            log.info("user found in realm");
            authenticationFlowContext.getAuthenticationSession().setAuthenticatedUser(userModel);
        }
        authenticationFlowContext.success();

    }

    @Override public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override public boolean requiresUser() {
        return false;
    }

    @Override public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel,
            UserModel userModel) {
        return false;
    }

    @Override public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel,
            UserModel userModel) {

    }

    @Override public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Authenticator.super.getRequiredActions(session);
    }

    @Override public boolean areRequiredActionsEnabled(KeycloakSession session, RealmModel realm) {
        return Authenticator.super.areRequiredActionsEnabled(session, realm);
    }

    @Override public void close() {

    }

    protected boolean hasValidJwt(AuthenticationFlowContext context) {

        String jwt = retrieveQueryParameter(context, "auth_token");

        boolean result = jwt != null;
        if (result) {
            RestTemplate restTemplate = new RestTemplate();
            String resourceUrl = "https://login.ipemis.qa.innovatorslab.net/login";
            ResponseEntity<String> response = restTemplate.getForEntity(resourceUrl, String.class);
            result = false;
            if (response.getStatusCode().equals(HttpStatus.OK)) {
                log.error("auth ok");
                result = true;
            }
        }

        return result;
    }

    protected String retrieveQueryParameter(AuthenticationFlowContext context, String param) {
        MultivaluedMap<String, String> inputData =
                context.getUriInfo().getQueryParameters();
        String value = inputData.getFirst(param);
        return value != null ? value : "";
    }

    protected String retrieveRequestHeader(AuthenticationFlowContext context, String header) {
        MultivaluedMap<String, String> inputData =
                context.getHttpRequest().getHttpHeaders().getRequestHeaders();
        String value = inputData.getFirst(header);
        return value != null ? value : "";
    }

}
