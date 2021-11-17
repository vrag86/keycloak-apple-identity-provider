package info.vrag.keycloak.provider.apple;

import com.fasterxml.jackson.databind.JsonNode;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;

import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class AppleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig>{
    public static final String OAUTH2_PARAMETER_ID_TOKEN = "id_token";

    private static final String PROFILE_URL = "https://appleid.apple.com/auth/token";

    private static final String DEFAULT_SCOPE = "";

    public AppleIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
        config.setUserInfoUrl(PROFILE_URL);
    }

    public BrokeredIdentityContext getFederatedIdentity(String code) {
        SimpleHttp request = SimpleHttp.doPost(PROFILE_URL, session)
                .param("client_id", getConfig().getClientId())
                .param("client_secret", getConfig().getClientSecret())
                .param("grant_type", "authorization_code")
                .param("code", code);

        SimpleHttp.Response response = null;
        try {
            response = request.asResponse();
            if (response.getStatus() != 200) {
                throw new IdentityBrokerException("Can't perform request to [" + PROFILE_URL + "] Code: " + response.getStatus() + " Response: " + response.asString());
            }
        } catch (IOException e) {
            throw new IdentityBrokerException("Can't perform request to [" + PROFILE_URL + "]");
        }

        BrokeredIdentityContext user = getUserInfoFromResponse(response);

        return user;
    }

    private BrokeredIdentityContext getUserInfoFromResponse(SimpleHttp.Response response) {
        JsonNode jsonResponse = null;
        try {
            jsonResponse = response.asJson();
        } catch (IOException e) {
           throw new IdentityBrokerException("Can't get response as json");
        }
        JsonNode idTokenNode = jsonResponse.get(OAUTH2_PARAMETER_ID_TOKEN);
        if (idTokenNode == null) {
            throw new IdentityBrokerException("Can't get param [" + OAUTH2_PARAMETER_ID_TOKEN + "[ from response");
        }

        JWSInput jwsInput = null;
        try {
            jwsInput = new JWSInput(idTokenNode.asText());
        } catch (JWSInputException cause) {
            throw new IdentityBrokerException("Failed to parse JWT userinfo response");
        }

        JsonNode userInfo = null;
        if (verify(jwsInput)) {
            try {
                userInfo = JsonSerialization.readValue(jwsInput.getContent(), JsonNode.class);
            } catch (IOException e) {
                throw new IdentityBrokerException("Can't read userinfo from " + OAUTH2_PARAMETER_ID_TOKEN);
            }
        } else {
            throw new IdentityBrokerException("Failed to verify signature of userinfo response from [" + OAUTH2_PARAMETER_ID_TOKEN + "].");
        }

        String id = getJsonProperty(userInfo, "sub");
        String email = getJsonProperty(userInfo, "email");
        BrokeredIdentityContext user = new BrokeredIdentityContext(id);
        user.setUsername(id);
        user.setEmail(email);
        user.setFirstName(email);
        user.setIdpConfig(getConfig());
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, userInfo, getConfig().getAlias());

        return user;
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

}
