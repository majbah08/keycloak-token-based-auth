package com.dsi.ieims.sso.authspi.authenticator;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.naming.AuthenticationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;

@Slf4j
public class IEIMSAuthenticator implements Authenticator {
    @Override public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        authenticationFlowContext.challenge(Response.noContent().build());
    }

    @Override public void action(AuthenticationFlowContext authenticationFlowContext) {
        if (hasValidJwt(authenticationFlowContext)){
            authenticationFlowContext.success();
            return;
        }
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

        String jwt = context.getHttpRequest().getUri().getQueryParameters().getFirst("IPEMIS-TOKEN");
        boolean result = jwt != null;
        if (result) {
            System.out.println("BAuthenticating user");
        }
        return result;
    }

    protected String retrieveParameter(AuthenticationFlowContext context, String param) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        String value = inputData.getFirst(param);
        return value != null ? value : "";
    }


}
