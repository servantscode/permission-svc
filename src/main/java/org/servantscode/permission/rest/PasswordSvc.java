package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.PasswordRequest;
import org.servantscode.permission.db.LoginDB;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.ws.rs.Consumes;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

@Path("/password")
public class PasswordSvc extends SCServiceBase {
    private static final Logger LOG = LogManager.getLogger(PasswordSvc.class);

    private LoginDB db;

    public PasswordSvc() {
        this.db = new LoginDB();
    }

    @POST @Consumes(MediaType.APPLICATION_JSON)
    public void resetPassword(@Context SecurityContext context,
                              PasswordRequest request) {
        int personId = getUserId(context);

        LOG.info("Resetting password for user: " + personId);

        Credentials dbCreds = db.getCredentials(personId);
        if (dbCreds != null && BCrypt.checkpw(request.getOldPassword(), dbCreds.getHashedPassword())) {
            db.updatePassword(personId, BCrypt.hashpw(request.getNewPassword(), BCrypt.gensalt()));
        } else {
            throw new NotAuthorizedException("Illegal password change request");
        }
    }
}
