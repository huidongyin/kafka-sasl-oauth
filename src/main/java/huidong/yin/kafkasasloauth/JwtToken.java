package huidong.yin.kafkasasloauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;


/**
 * JwtToken singleton: initialized explicitly with secret bytes.
 */
public class JwtToken {
    private static volatile JwtToken INSTANCE;

    private final SecretKey hmacKey;
    private static final long tokenReAuthTimeMsDefault = 365L * 24 * 3600 * 1000L;

    private JwtToken(byte[] secret) {
        if (secret == null || secret.length == 0) throw new IllegalArgumentException("secret required");
        this.hmacKey = Keys.hmacShaKeyFor(secret);
    }

    /**
     * Initialize instance with provided secret bytes. Safe to call multiple times; first caller wins.
     */
    public static void initInstance(byte[] secret) {
        if (INSTANCE != null) return;
        synchronized (JwtToken.class) {
            if (INSTANCE != null) return;
            INSTANCE = new JwtToken(secret);
        }
    }

    public static JwtToken getInstance() {
        if (INSTANCE == null)
            throw new IllegalStateException("JwtToken not initialized. Call initInstance(secret) in configure()");
        return INSTANCE;
    }

    public Claims getClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(hmacKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            throw new RuntimeException("JWT validation failed: " + e.getMessage(), e);
        }
    }

    public long getDefaultTokenReAuthTimeMs() {
        return tokenReAuthTimeMsDefault;
    }
}