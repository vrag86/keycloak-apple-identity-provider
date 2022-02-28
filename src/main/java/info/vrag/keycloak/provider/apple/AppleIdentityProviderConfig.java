package info.vrag.keycloak.provider.apple;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class AppleIdentityProviderConfig extends OIDCIdentityProviderConfig {

    public AppleIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public AppleIdentityProviderConfig() {}

    public boolean isEmailRequired() {
        return Boolean.parseBoolean(getConfig().getOrDefault("email_required", "false"));
    }

    @Override
    public boolean isUseJwksUrl() {
        return true;
    }

    @Override
    public String getJwksUrl() {
        return getConfig().get("jwksUrl");
    }

    public String getPrivateKey() {
        return getConfig().get("applePrivateKey");
    }

    public String getKeyId() {
        return getConfig().get("keyId");
    }

    public String getTeamId() {
        return getConfig().get("teamId");
    }

    @Override
    public boolean isValidateSignature() {
        return true;
    }
}
