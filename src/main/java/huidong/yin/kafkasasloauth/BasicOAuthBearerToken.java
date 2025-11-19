package huidong.yin.kafkasasloauth;

import lombok.AllArgsConstructor;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.util.Set;

@AllArgsConstructor
public class BasicOAuthBearerToken implements OAuthBearerToken {
    private final String tokenValue;
    private final String principalName;
    private final long lifetimeMs;
    private final long startTimeMs;


    @Override
    public String value() {
        return tokenValue;
    }

    @Override
    public Set<String> scope() {
        return Set.of();
    }

    @Override
    public long lifetimeMs() {
        return lifetimeMs;
    }

    @Override
    public String principalName() {
        return principalName;
    }

    @Override
    public Long startTimeMs() {
        return startTimeMs;
    }
}