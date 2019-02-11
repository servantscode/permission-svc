package org.servantscode.permission.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.LoginRequest;
import org.servantscode.permission.db.LoginDB;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.util.Date;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Path("/login")
public class LoginSvc extends SCServiceBase {
    private static final Logger LOG = LogManager.getLogger(LoginSvc.class);

    LoginDB db;

    public LoginSvc() {
        db = new LoginDB();
    }

    @POST @Consumes(APPLICATION_JSON) @Produces(MediaType.TEXT_PLAIN)
    public String login(@Context HttpServletResponse resp,
                        LoginRequest request) {

        Credentials dbCreds = db.getCredentials(request.getEmail());
        if(dbCreds != null && BCrypt.checkpw(request.getPassword(), dbCreds.getHashedPassword())) {
            String creds = generateJWT(dbCreds);
            LOG.info(dbCreds.getEmail() + " logged in.");
            ThreadContext.put("user", dbCreds.getEmail());
            return creds;
        }

        throw new NotAuthorizedException("Invalid login credentials.");
    }

    // ----- Private -----
    private String generateJWT(Credentials creds) {
        try {
            Algorithm algorithm = Algorithm.HMAC256("GV^~me\\KO{]Z'hdUL?Ls[7b<EAWfC0\"2N_ (`m0&}?aK%?j#.'_p[s{Jatv2(@N5");
            Date now = new Date();
            long duration = 24*60*60*1000; // 24 hours; TODO: Parameterize this

            return JWT.create()
                    .withSubject(creds.getEmail())
                    .withIssuedAt(now)
                    .withExpiresAt(new Date(now.getTime() + duration))
                    .withIssuer("Servant's Code")
                    .withClaim("role", creds.getRole())
                    .withClaim("userId", creds.getPersonId())
                    .withArrayClaim("permissions", creds.getPermissions())
                    .sign(algorithm);
        } catch (JWTCreationException e){
            throw new RuntimeException("Could not create JWT Token", e);
        }
    }
}
