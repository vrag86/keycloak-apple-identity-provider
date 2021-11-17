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
            if (false && response.getStatus() != 200) {
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
            //jsonResponse = response.asJson();

            String trueResponse = "{\"access_token\":\"a5529c6b0451e43bc8b409c2a001635e6.0.rrtqy.j1gopLXw2Um2Bo-H9lLaew\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"rfd1f1fd805d3476c99b97ab1fdc3888d.0.rrtqy.tjd5g-HyHMHgAHThXJ0ahA\",\"id_token\":\"eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoicnUua2lub2hvZCIsImV4cCI6MTYzNzIyNzI1OSwiaWF0IjoxNjM3MTQwODU5LCJzdWIiOiIwMDEzMDguNzFiNDEzZDk5NmNkNDVmNDlmZmM2NTE4NzMyZTNkNjMuMTExNCIsImF0X2hhc2giOiJfUUVoUTJDbkczSmhpRXZVWEJTRkhRIiwiZW1haWwiOiJraW5vaG9kQGtpbm9ob2QucnUiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhdXRoX3RpbWUiOjE2MzcxNDA4MDQsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.avH98_AjdEtrE5wrNMhGIw0mU8HJm_eLt3rZgTclUwY4aok1srH31jl-CkQ0T708PQ4BFsSPHqQqb0CdXi2TqD6OEJsDM2UL1xCSQNpm7PE-JXhMMkmuhQkgBQGVTxnY4SUeAe3C_jY08vB8nJc1phjD80LXXFP1tPrUUy6HkrdV0BsagxD1NdG0npG8EUARPhLqx3sa8wNAhDNlOVYWHYjxxBmzRe28ifNymISSDpQe1eHr8WXzKB-oIwnuLMGn5SNbDyP8qvx-_1tCijljUi4Bza_f0BEEbYMGCGULMgDvSVH1TbPUpuka_xJK63h-N8eVeVP5pHpeTejADSjSqw\"}";
            ObjectMapper mapper = new ObjectMapper();
            jsonResponse = mapper.readTree(trueResponse);

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
