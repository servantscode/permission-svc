package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.db.SessionDB;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.commons.security.SystemJWTGenerator;
import org.servantscode.permission.*;
import org.servantscode.permission.db.LoginDB;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.UUID;

import static org.servantscode.commons.StringUtils.isSet;
import static org.servantscode.permission.PasswordProcessor.encryptPassword;
import static org.servantscode.permission.PasswordProcessor.verifyPassword;

@Path("/password")
public class PasswordSvc extends SCServiceBase {
    private static final Logger LOG = LogManager.getLogger(PasswordSvc.class);

    private LoginDB db;
    private SessionDB sessionDB;

    public PasswordSvc() {
        this.db = new LoginDB();
        this.sessionDB = new SessionDB();
    }

    @POST @Path("/reset") @Consumes(MediaType.APPLICATION_JSON)
    public void requestPasswordReset(ResetPasswordRequest request) {

        Credentials dbCreds = db.getCredentials(request.getEmail());
        if(dbCreds == null)
            return;

        dbCreds.setResetPassword(true);
        dbCreds.setResetToken(UUID.randomUUID().toString());

        db.updateCredentials(dbCreds);
        sessionDB.deleteAllSessions(dbCreds.getId());
        EmailNotificationClient emailClient = new EmailNotificationClient(SystemJWTGenerator.generateToken());
        emailClient.sendPasswordResetEmail(dbCreds.getEmail(), dbCreds.getResetToken());
        LOG.info("Password reset requested for: " + request.getEmail());
    }

    @POST @Consumes(MediaType.APPLICATION_JSON)
    public void resetPassword(PasswordRequest request) {

        int personId;
        if(isSet(request.getPasswordToken())) {
            personId = db.getPersonIdForPasswordToken(request.getPasswordToken());

            if(personId == -1)
                throw new NotFoundException();
        } else {
            personId = getUserId();
            if(personId == -1)
                throw new NotFoundException();

            Credentials dbCreds = db.getCredentials(personId);

            if (dbCreds == null || !verifyPassword(request.getOldPassword(), dbCreds.getHashedPassword()))
                throw new NotAuthorizedException("Illegal password change request");
        }

        db.updatePassword(personId, encryptPassword(request.getNewPassword()));
        sessionDB.deleteAllSessions(personId);
        LOG.info("Password updated by user.");
    }
}
