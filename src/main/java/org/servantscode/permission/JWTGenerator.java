package org.servantscode.permission;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.servantscode.commons.EnvProperty;

import java.util.Arrays;
import java.util.Date;

public class JWTGenerator {

    private static final String SIGNING_KEY = EnvProperty.get("JWT_KEY", "aJWTKey");

    public static String systemToken() {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SIGNING_KEY);
            Date now = new Date();
            long duration = 60*1000; // 1 minute

            return JWT.create()
                    .withSubject("system")
                    .withIssuedAt(now)
                    .withExpiresAt(new Date(now.getTime() + duration))
                    .withIssuer("Servant's Code")
                    .withClaim("role", "system")
                    .withClaim("userId", "0")
                    .withArrayClaim("permissions", new String[] {"*"})
                    .sign(algorithm);
        } catch (JWTCreationException e){
            throw new RuntimeException("Could not create system JWT Token", e);
        }
    }

    public static String generateJWT(Credentials creds) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SIGNING_KEY);
            Date now = new Date();
            long duration = 24*60*60*1000; // 24 hours; TODO: Parameterize this

            return JWT.create()
                    .withSubject(creds.getEmail())
                    .withIssuedAt(now)
                    .withExpiresAt(new Date(now.getTime() + duration))
                    .withIssuer("Servant's Code")
                    .withClaim("role", creds.getRole())
                    .withClaim("userId", creds.getId())
                    .withArrayClaim("permissions", creds.getPermissions())
                    .sign(algorithm);
        } catch (JWTCreationException e){
            throw new RuntimeException("Could not create JWT Token", e);
        }
    }
}
