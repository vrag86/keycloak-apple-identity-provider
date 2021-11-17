package info.vrag.keycloak.provider.apple;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class AppleIdentityProviderFactory
        extends AbstractIdentityProviderFactory<AppleIdentityProvider>
        implements SocialIdentityProviderFactory<AppleIdentityProvider> {

    public static final String PROVIDER_ID = "apple";
    private static final String PROVIDER_NAME = "Apple";

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public AppleIdentityProvider create(KeycloakSession session, IdentityProviderModel identityProviderModel) {
        return new AppleIdentityProvider(session, new AppleIdentityProviderConfig(identityProviderModel));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new AppleIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
