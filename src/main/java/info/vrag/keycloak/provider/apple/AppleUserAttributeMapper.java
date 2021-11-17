package info.vrag.keycloak.provider.apple;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

public class AppleUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    private static final String[] COMPATIBLE_PROVIDERS = new String[]{AppleIdentityProviderFactory.PROVIDER_ID};
    private static final String ID = "apple-user-attribute-mapper";

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getId() {
        return ID;
    }
}
