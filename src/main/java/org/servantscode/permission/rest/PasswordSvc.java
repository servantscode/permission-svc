package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.PasswordRequest;
import org.servantscode.permission.db.LoginDB;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

import static org.servantscode.commons.StringUtils.isSet;

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

        int personId;
        if(isSet(request.getPasswordToken())) {
            personId = db.getPersonIdForPasswordToken(request.getPasswordToken());

            if(personId == -1)
                throw new NotFoundException();
        } else {
            personId = getUserId(context);
            Credentials dbCreds = db.getCredentials(personId);

            if (dbCreds == null || !BCrypt.checkpw(request.getOldPassword(), dbCreds.getHashedPassword()))
                throw new NotAuthorizedException("Illegal password change request");
        }

        db.updatePassword(personId, BCrypt.hashpw(request.getNewPassword(), BCrypt.gensalt()));
        LOG.info("Password updated by user.");
    }
}
