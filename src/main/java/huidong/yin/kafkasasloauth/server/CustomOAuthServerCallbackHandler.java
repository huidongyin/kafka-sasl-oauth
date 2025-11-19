package huidong.yin.kafkasasloauth.server;

import huidong.yin.kafkasasloauth.BasicOAuthBearerToken;
import huidong.yin.kafkasasloauth.JwtToken;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * AuthenticateCallbackHandler implementation for Kafka broker (HMAC-only).
 * The configure method reads JAAS AppConfigurationEntry list to find jwt.secret or secretKeyName option.
 * Deployment notes:
 * - In server.properties:
 * listener.name.sasl_ssl.oauthbearer.sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required secretKeyName="kafka.sasl.oauth.secret";
 * kafka.sasl.oauth.secret=very-strong-secret
 * - Alternatively put the secret directly into the JAAS entry as jwt.secret="..."
 * - After packaging the plugin jar and JJWT runtime jars into Kafka's libs/, restart the broker.
 */
@Slf4j
public class CustomOAuthServerCallbackHandler implements AuthenticateCallbackHandler {

    private long tokenReAuthTimeMs = -1;

    private static final String secretKeyName = "secretKeyName";
    private static final String OAUTH_BEARER = "OAUTHBEARER";


    @Override
    public void configure(Map<String, ?> configs/*Kafka客户端或broker的配置属性*/, String saslMechanism/*当前配置的SASL机制*/, List<AppConfigurationEntry> jaasConfigEntries/*JAAS配置条目列表*/) {
        // Try to resolve secret in the following order:
        // 1) Option secretKeyName in JAAS entries -> lookup that key in configs map
        // 2) If not in configs, try System.getProperty(secretKeyName)
        // 3) If not, try System.getenv(secretKeyName)
        //todo: in fact , we need get real secret value in  auth server .
        log.info("start init sasl oauth secret key ... current saslMechanism : {}", saslMechanism);
        byte[] secretBytes = null;

        if (!OAUTH_BEARER.equals(saslMechanism)) {
            throw new IllegalStateException("not support sasl : " + saslMechanism +
                    "，current handler only support OAuthBearer");
        }

        if (jaasConfigEntries != null) {
            for (AppConfigurationEntry entry : jaasConfigEntries) {

                if (!isOAuthBearerLoginModule(entry.getLoginModuleName())) {
                    continue;
                }
                Map<String, ?> opts = entry.getOptions();
                if (opts == null) continue;
                Object keyName = opts.get(secretKeyName);
                if (keyName instanceof String key) {
                    // lookup in configs map
                    Object cfgVal = (configs != null) ? configs.get(key) : null;
                    if (cfgVal instanceof String) {
                        secretBytes = ((String) cfgVal).getBytes(StandardCharsets.UTF_8);
                        log.info("success init sasl oauth secret key ... {} .", secretKeyName);
                        break;
                    }
                    // try system property
                    String sys = System.getProperty(key);
                    if (sys != null) {
                        secretBytes = sys.getBytes(StandardCharsets.UTF_8);
                        break;
                    }
                    String env = System.getenv(key);
                    if (env != null) {
                        secretBytes = env.getBytes(StandardCharsets.UTF_8);
                        break;
                    }
                }

            }
        }

        if (secretBytes == null) {
            throw new IllegalStateException("Could not resolve JWT secret. Set jwt.secret in JAAS or use secretKeyName pointing to a broker config property.");
        }

        JwtToken.initInstance(secretBytes);
        this.tokenReAuthTimeMs = JwtToken.getInstance().getDefaultTokenReAuthTimeMs();
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback) {
                handleValidatorCallback((OAuthBearerValidatorCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback, "Callback class not supported: " + callback.getClass());
            }
        }
    }

    private boolean isOAuthBearerLoginModule(String loginModuleName) {
        // Kafka标准的OAUTHBEARER登录模块
        return OAuthBearerLoginModule.class.getName().equals(loginModuleName);
    }

    private void handleValidatorCallback(OAuthBearerValidatorCallback callback) {
        String token = callback.tokenValue();
        if (token == null || token.isEmpty()) {
            log.error("Token is null or empty");
            return;
        }

        try {
            var claims = JwtToken.getInstance().getClaimsFromToken(token);
            Date exp = claims.getExpiration();
            if (exp == null) {
                log.error("invalid_token ：missing exp");
                callback.error("invalid_token ：missing exp", null, null);
                return;
            }
            long now = System.currentTimeMillis();
            if (exp.getTime() <= now) {
                log.error("invalid_token token expired");
                callback.error("invalid_token token expired", null, null);
                return;
            }
            String sub = claims.getSubject();
            if (sub == null || sub.isEmpty()) {
                log.error("invalid_token missing sub");
                callback.error("invalid_token missing sub", null, null);
                return;
            }
            Date iat = claims.getIssuedAt();
            long start = (iat == null) ? now : iat.getTime();
            BasicOAuthBearerToken t = new BasicOAuthBearerToken(token, sub, exp.getTime(), start);
            callback.token(t);
        } catch (RuntimeException e) {
            log.error("invalid_token verification failed: {}", e.getMessage(), e);
            throw new RuntimeException("invalid_token verification failed:" + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
    }
}