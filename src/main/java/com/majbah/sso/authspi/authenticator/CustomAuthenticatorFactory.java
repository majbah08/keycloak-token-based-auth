package com.majbah.sso.authspi.authenticator;

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
public class CustomAuthenticatorFactory implements AuthenticatorFactory,
        ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "custom-authenticator";
    private static final CustomAuthenticator SINGLETON = new CustomAuthenticator();

    @Override public String getDisplayType() {
        return "Custom Authenticator";
    }

    @Override public String getReferenceCategory() {
        return null;
    }

    @Override public boolean isConfigurable() {
        return true;
    }

    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{ AuthenticationExecutionModel.Requirement.REQUIRED };
    }

    @Override public boolean isUserSetupAllowed() {
        return true;
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
