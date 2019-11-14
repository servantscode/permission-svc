package org.servantscode.permission;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.apache.logging.log4j.ThreadContext;
import org.servantscode.commons.EnvProperty;
import org.servantscode.commons.Organization;
import org.servantscode.commons.Session;
import org.servantscode.commons.db.SessionDB;
import org.servantscode.commons.security.OrganizationContext;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import static org.servantscode.commons.security.SCSecurityContext.SYSTEM;

public class JWTGenerator {
    private static final String SIGNING_KEY = EnvProperty.get("JWT_KEY", "aJWTKey");

    private static SessionDB db = new SessionDB();

    public static String systemToken() {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SIGNING_KEY);
            Date now = new Date();
            long duration = 60*1000; // 1 minute

            return JWT.create()
                    .withSubject(SYSTEM)
                    .withIssuedAt(now)
                    .withExpiresAt(new Date(now.getTime() + duration))
                    .withIssuer("Servant's Code")
                    .withClaim("role", "system")
                    .withClaim("userId", "0")
                    .withClaim("org", OrganizationContext.getOrganization().getName())
                    .withArrayClaim("permissions", new String[] {"*"})
                    .sign(algorithm);
        } catch (JWTCreationException e){
            throw new RuntimeException("Could not create system JWT Token", e);
        }
    }

    public static String generateJWTForCheckin(Credentials creds, ZonedDateTime expiration) {
        Date expirationDate = new Date(expiration.toInstant().toEpochMilli());
        return generateJWT(creds, expirationDate);
    }

    public static String generateJWT(Credentials creds) {
        long duration = 24*60*60*1000; // 24 hours; TODO: Parameterize this
        Date expiration = new Date(new Date().getTime() + duration);
        return generateJWT(creds, expiration);
    }

    public static String generateJWT(Credentials creds, Date expiration) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SIGNING_KEY);

            Organization org = OrganizationContext.getOrganization();

            String token = JWT.create()
                    .withSubject(creds.getEmail())
                    .withIssuedAt(new Date())
                    .withExpiresAt(expiration)
                    .withIssuer("Servant's Code")
                    .withClaim("role", creds.getRole())
                    .withClaim("userId", creds.getId())
                    .withClaim("org", org.getName())
                    .withArrayClaim("permissions", creds.getPermissions())
                    .sign(algorithm);

            Session s = new Session();
            s.setPersonId(creds.getId());
            s.setOrgId(org.getId());
            s.setToken(token);
            s.setExpiration(expiration.toInstant().atZone(ZoneId.systemDefault()));
            s.setIp(ThreadContext.get("request.origin"));
            db.createSession(s);

            return token;
        } catch (JWTCreationException e){
            throw new RuntimeException("Could not create JWT Token", e);
        }
    }
}
