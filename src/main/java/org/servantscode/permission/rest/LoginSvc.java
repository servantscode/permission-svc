package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.JWTGenerator;
import org.servantscode.permission.LoginRequest;
import org.servantscode.permission.Role;
import org.servantscode.permission.db.CheckinDB;
import org.servantscode.permission.db.LoginDB;
import org.servantscode.permission.db.RoleDB;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.permission.PasswordProcessor.verifyPassword;

@Path("/login")
public class LoginSvc extends SCServiceBase {
    private static final Logger LOG = LogManager.getLogger(LoginSvc.class);

    private LoginDB db;
    private CheckinDB checkinDb;

    public LoginSvc() {
        db = new LoginDB();
        checkinDb = new CheckinDB();
    }

    @POST
    @Consumes(APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String login(@Context HttpServletResponse resp,
                        LoginRequest request) {

        Credentials dbCreds = db.getCredentials(request.getEmail());
        if (dbCreds != null && verifyPassword(request.getPassword(), dbCreds.getHashedPassword())) {
            if(dbCreds.isRoleRequiresCheckin() && !checkinDb.isCheckedIn(dbCreds.getId()))
                throw new NotAuthorizedException("Role requires checkin for access.");

            String creds = JWTGenerator.generateJWT(dbCreds);
            LOG.info(dbCreds.getEmail() + " logged in.");
            ThreadContext.put("user", dbCreds.getEmail());
            return creds;
        }

        throw new NotAuthorizedException("Invalid login credentials.");
    }
}

