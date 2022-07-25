package com.dsi.ieims.sso.authspi.authenticator;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

@Slf4j
public class IEIMSAuthenticatorFactory implements AuthenticatorFactory,
        ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "ieims-authenticator";
    private static final IEIMSAuthenticator SINGLETON = new IEIMSAuthenticator();

    @Override public String getDisplayType() {
        return null;
    }

    @Override public String getReferenceCategory() {
        return null;
    }

    @Override public boolean isConfigurable() {
        return false;
    }

    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[0];
    }

    @Override public boolean isUserSetupAllowed() {
        return false;
    }

    @Override public String getHelpText() {
        return null;
    }

    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    @Override public void init(Config.Scope scope) {

    }

    @Override public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override public void close() {

    }

    @Override public String getId() {
        return PROVIDER_ID;
    }

}
