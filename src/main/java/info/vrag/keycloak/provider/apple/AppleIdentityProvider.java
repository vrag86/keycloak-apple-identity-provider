package info.vrag.keycloak.provider.apple;

import com.fasterxml.jackson.databind.JsonNode;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.crypto.ServerECDSASignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.security.KeyFactory;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AppleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig>{
    public static final String OAUTH2_PARAMETER_ID_TOKEN = "id_token";

    public static final String OAUTH2_PARAMETER_STORE_TOKEN = "apple_client_secret";

    private static final String PROFILE_URL = "https://appleid.apple.com/auth/token";

    private static final String DEFAULT_SCOPE = "";

    private static final long CLIENT_SECRET_LIFETIME = 15552000;     // 180 days

    private final IdentityProviderModel idp_model;
    private final AppleIdentityProviderConfig config;

    public AppleIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
        this.idp_model = session.getContext().getRealm().getIdentityProviderByAlias(getConfig().getAlias());
        this.config = (AppleIdentityProviderConfig) getConfig();
        config.setUserInfoUrl(PROFILE_URL);
    }

    public BrokeredIdentityContext getFederatedIdentity(String code) {
        SimpleHttp request = SimpleHttp.doPost(PROFILE_URL, session)
                .param("client_id", getConfig().getClientId())
                .param("client_secret", getClientSecret())
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

    private String getClientSecret() {
        int statusClientSecret = getStatusClientSecret();
        if (statusClientSecret != 1) {
            try {
                renewClientSecret();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                if (statusClientSecret == -1 || statusClientSecret == -2) {
                    throw new IdentityBrokerException("Failed to generate client secret: " + e.toString());
                }
            }
        }
        return idp_model.getConfig().get(OAUTH2_PARAMETER_STORE_TOKEN);
    }

    private void renewClientSecret() throws NoSuchAlgorithmException, InvalidKeySpecException {

        String clientSecret = null;
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        byte[] pkc8ePrivateKey = Base64.getDecoder().decode(config.getPrivateKey().replaceAll("\n", ""));
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(pkc8ePrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.ES256);
        keyWrapper.setKid(config.getKeyId());
        keyWrapper.setPrivateKey(privateKey);
        SignatureSignerContext signer = new ServerECDSASignatureSignerContext(keyWrapper);

        long currentTime = Time.currentTime();
        JsonWebToken token = new JsonWebToken();
        token.issuer(config.getTeamId());
        token.iat(currentTime);
        token.exp(currentTime + CLIENT_SECRET_LIFETIME);
        token.audience("https://appleid.apple.com");
        token.subject(config.getClientId());
        clientSecret = new JWSBuilder().jsonContent(token).sign(signer);

        idp_model.getConfig().put(OAUTH2_PARAMETER_STORE_TOKEN, clientSecret.replace("\n", ""));
        session.getContext().getRealm().updateIdentityProvider(idp_model);
    }

    private int getStatusClientSecret() {
        /*
            -2 - Token incorrect
            -1 - Token expired
            0 - Token expired half lifetime
            1 - Token correct
         */
        AccessToken token = null;
        try {
            token = TokenVerifier.create(idp_model.getConfig().get(OAUTH2_PARAMETER_STORE_TOKEN), AccessToken.class).getToken();
        } catch (VerificationException e) {
            return -2;
        }

        if (!token.getIssuer().equals(config.getTeamId())) {
            return -2;
        }

        long currentTime = Time.currentTime();
        if (token.getExp() - currentTime < 1) {
            return -1;
        }
        if ((token.getExp() - currentTime) < CLIENT_SECRET_LIFETIME / 2 ) {
            return 0;
        }
        return 1;
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
