package huidong.yin.kafkasasloauth.client;

import huidong.yin.kafkasasloauth.BasicOAuthBearerToken;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;


/**
 * Custom OAuthBearer Login CallbackHandler
 * - Retrieves JWT tokens from third-party auth server using username/password
 * - Automatically refreshes token before expiry
 *
 * Properties props = new Properties();
 * props.put("bootstrap.servers", "kafka-broker:9093");
 * props.put("security.protocol", "SASL_SSL");
 * props.put("sasl.mechanism", "OAUTHBEARER");
 *
 * // 使用自定义 OAuth 登录处理器
 * props.put("sasl.login.callback.handler.class",
 *     "com.yourpackage.CustomOAuthBearerLoginCallbackHandler");
 *
 * // JAAS 配置 - 包含认证服务器信息
 * props.put("sasl.jaas.config",
 *     "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required " +
 *     "authUrl=\"https://auth-server.com/oauth/token\" " +
 *     "username=\"your-client-id\" " +
 *     "password=\"your-client-secret\" " +
 *     "refreshWindowSeconds=\"60\";");
 */
public class CustomOAuthBearerLoginCallbackHandler implements AuthenticateCallbackHandler {

    private String authUrl;
    private String username;
    private String password;
    private long refreshWindowSeconds = 60; // refresh 60s before expiry

    private final AtomicReference<OAuthBearerToken> currentToken = new AtomicReference<>();

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        for (AppConfigurationEntry entry : jaasConfigEntries) {
            Map<String, ?> options = entry.getOptions();
            this.authUrl = (String) options.get("authUrl");
            this.username = (String) options.get("username");
            this.password = (String) options.get("password");

            if (options.containsKey("refreshWindowSeconds")) {
                this.refreshWindowSeconds = Long.parseLong((String) options.get("refreshWindowSeconds"));
            }
        }
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback) {
                OAuthBearerToken token = currentToken.get();

                if (token == null || isExpiringSoon(token)) {
                    token = retrieveTokenFromAuthServer();
                    currentToken.set(token);
                }

                ((OAuthBearerTokenCallback) callback).token(token);
            } else if (callback instanceof OAuthBearerValidatorCallback) {
                throw new UnsupportedCallbackException(callback, "Client does not validate tokens");
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    private boolean isExpiringSoon(OAuthBearerToken token) {
        long now = Instant.now().getEpochSecond();
        long expires = token.lifetimeMs() / 1000;
        return expires - now <= refreshWindowSeconds;
    }

    //todo:call oauth server to get token
    private OAuthBearerToken retrieveTokenFromAuthServer() {
        return new BasicOAuthBearerToken("", "", 0L, 0L);
    }


    @Override
    public void close() {
    }


}

