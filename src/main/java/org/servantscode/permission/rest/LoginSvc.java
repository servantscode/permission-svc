package org.servantscode.permission.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.servantscode.commons.StringUtils;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.LoginRequest;
import org.servantscode.permission.PublicCredentials;
import org.servantscode.permission.db.LoginDB;
import org.servantscode.permission.db.RoleDB;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.util.*;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.commons.StringUtils.isEmpty;

@Path("/login")
public class LoginSvc extends SCServiceBase {
    private static final Logger LOG = LogManager.getLogger(LoginSvc.class);

    @POST @Consumes(APPLICATION_JSON) @Produces(MediaType.TEXT_PLAIN)
    public String login(@Context HttpServletResponse resp,
                        LoginRequest request) {

        Credentials dbCreds = new LoginDB().getCredentials(request.getEmail());
        if(BCrypt.checkpw(request.getPassword(), dbCreds.getHashedPassword())) {
            String creds = generateJWT(dbCreds);
            LOG.info(dbCreds.getEmail() + " logged in.");
            ThreadContext.put("user", dbCreds.getEmail());
            return creds;
        }

        throw new NotAuthorizedException("Invalid login credentials.");
    }

    @POST @Path("/new") @Consumes(APPLICATION_JSON)
    public void createPassword(CreatePasswordRequest request) {

        verifyUserAccess("login.create");

        if(request.getPersonId() <= 0)
            throw new BadRequestException("No valid person specified");
        if(isEmpty(request.getRole()) || !new RoleDB().verifyRole(request.getRole()))
            throw new BadRequestException("No valid role specified");
        if(isEmpty(request.getPassword())) //TODO: Password rules go here
            throw new BadRequestException("No password specified");

        String hashedPassword = BCrypt.hashpw(request.getPassword(), BCrypt.gensalt());
        new LoginDB().createLogin(request.getPersonId(), hashedPassword, request.getRole());
    }

    @PUT @Path("/person/{id}") @Consumes(APPLICATION_JSON)
    public void updateCredentials(@PathParam("id") int personId,
                                  CreatePasswordRequest request) {

        verifyUserAccess("login.update");

        if(request.getPersonId() <= 0 || request.getPersonId() != personId)
            throw new BadRequestException("No valid person specified");

        LoginDB db = new LoginDB();

        if(!isEmpty(request.getPassword())) {
            //TODO: Password rules go here
            String hashedPassword = BCrypt.hashpw(request.getPassword(), BCrypt.gensalt());
            db.updatePassword(personId, hashedPassword);
        }

        if(!isEmpty(request.getRole())) {
            db.updateRole(personId, request.getRole());
        }
    }

    @DELETE @Path("/person/{id}") @Produces(APPLICATION_JSON)
    public Map<String, Boolean> revokePassword(@Context SecurityContext securityContext,
                                              @PathParam("id") int personId) {

        verifyUserAccess("login.delete");

        if(personId <= 0)
            throw new BadRequestException("No valid person specified");

        boolean success = new LoginDB().deleteLogin(personId);

        final HashMap<String, Boolean> resp = new HashMap<>();
        resp.put("success", success);
        return resp;
    }

    @GET @Path("/person/{id}") @Produces(APPLICATION_JSON)
    public PublicCredentials getRole(@Context SecurityContext securityContext,
                                     @PathParam("id") int personId) {

        verifyUserAccess("login.read");

        if(!securityContext.isUserInRole("system") && !securityContext.isUserInRole("admin"))
            throw new ForbiddenException("Please speak with your admin to complete this action");

        if(personId <= 0)
            throw new BadRequestException("No valid person specified");

        Credentials creds = new LoginDB().getCredentials(personId);
        if(creds == null)
            throw new NotFoundException("No credentials available");

        return creds.toPublicCredentials();
    }


    // ----- Private -----
    private String generateJWT(Credentials creds) {
        try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
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
