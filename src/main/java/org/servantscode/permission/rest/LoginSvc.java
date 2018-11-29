package org.servantscode.permission.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.StringUtils;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.LoginRequest;
import org.servantscode.permission.db.LoginDB;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.util.Date;

@Path("/login")
public class LoginSvc {
    private static final Logger LOG = LogManager.getLogger(LoginSvc.class);

    @POST @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.TEXT_PLAIN)
    public String login(@Context HttpServletResponse resp,
                        LoginRequest request) {
        Credentials dbCreds = new LoginDB().getCredentials(request.getEmail());
        if(BCrypt.checkpw(request.getPassword(), dbCreds.getHashedPassword())) {
            return generateJWT(dbCreds);
        }

        throw new NotAuthorizedException("Invalid login credentials.");
    }

    @PUT @Consumes(MediaType.APPLICATION_JSON)
    public void createPassword(@Context SecurityContext securityContext,
                               CreatePasswordRequest request) {

        if(!securityContext.isUserInRole("super") && !securityContext.isUserInRole("admin"))
            throw new ForbiddenException("Please speak with your admin to complete this action");

        if(request.getPersonId() <= 0)
            throw new BadRequestException("No valid person specified");
        if(StringUtils.isEmpty(request.getRole()))
            throw new BadRequestException("No valid role specified");
        if(StringUtils.isEmpty(request.getPassword())) //TODO: Password rules go here
            throw new BadRequestException("No password specified");

        String hashedPassword = BCrypt.hashpw(request.getPassword(), BCrypt.gensalt());
        new LoginDB().createLogin(request.getPersonId(), hashedPassword, request.getRole());
    }

    // ----- Private -----
    private String generateJWT(Credentials creds) {
        try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
            Date now = new Date();
            long duration = 24*60*1000; // 24 hours;

            return JWT.create()
                    .withSubject(creds.getEmail())
                    .withIssuedAt(now)
                    .withExpiresAt(new Date(now.getTime() + duration))
                    .withIssuer("Servant's Code")
                    .withClaim("role", creds.getSystemRole())
                    .sign(algorithm);
        } catch (JWTCreationException e){
            throw new RuntimeException("Could not create JWT Token", e);
        }
    }
}
