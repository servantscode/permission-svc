package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.rest.PaginatedResponse;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.EmailNotificationClient;
import org.servantscode.permission.JWTGenerator;
import org.servantscode.permission.PublicCredentials;
import org.servantscode.permission.db.LoginDB;
import org.servantscode.permission.db.RoleDB;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.commons.StringUtils.isEmpty;
import static org.servantscode.commons.StringUtils.isSet;
import static org.servantscode.permission.PasswordProcessor.encryptPassword;

@Path("/credentials")
public class CredentialSvc extends SCServiceBase {
    private static final Logger LOG = LogManager.getLogger(CredentialSvc.class);

    LoginDB db;

    public CredentialSvc() {
        db = new LoginDB();
    }


    @GET @Produces(APPLICATION_JSON)
    public PaginatedResponse<PublicCredentials> usersWithAccess(@QueryParam("start") @DefaultValue("0") int start,
                                                                @QueryParam("count") @DefaultValue("10") int count,
                                                                @QueryParam("sort_field") @DefaultValue("name") String sortField,
                                                                @QueryParam("partial_name") @DefaultValue("") String search,
                                                                @Context SecurityContext securityContext) {

        verifyUserAccess("admin.login.list");

        //Only system users can see system.
        boolean includeSystem = securityContext.isUserInRole("system");

        try {
            int totalCredentials = db.getAccessCount(search, includeSystem);

            List<Credentials> results = db.getCredentials(start, count, sortField, search, includeSystem);
            List<PublicCredentials> publicResults = results.stream().map(Credentials::toPublicCredentials).collect(Collectors.toList());
            return new PaginatedResponse<>(start, publicResults.size(), totalCredentials, publicResults);
        } catch (Throwable t) {
            LOG.error("Retrieving rooms failed:", t);
            throw t;
        }
    }

    @GET @Path("/role/{role}") @Produces(APPLICATION_JSON)
    public PaginatedResponse<PublicCredentials> usersWithRole(@PathParam("role") String role,
                                                              @QueryParam("start") @DefaultValue("0") int start,
                                                              @QueryParam("count") @DefaultValue("10") int count,
                                                              @QueryParam("sort_field") @DefaultValue("name") String sortField,
                                                              @QueryParam("partial_name") @DefaultValue("") String search,
                                                              @Context SecurityContext securityContext) {

        verifyUserAccess("admin.login.list");

        //Only system users can see system.
        if(!securityContext.isUserInRole("system") && role.equals("system"))
            throw new BadRequestException();


        try {
            int totalCredentials = db.getRoleCount(role, search);

            List<Credentials> results = db.getCredentialsForRole(role, start, count, sortField, search);
            List<PublicCredentials> publicResults = results.stream().map(Credentials::toPublicCredentials).collect(Collectors.toList());
            return new PaginatedResponse<>(start, publicResults.size(), totalCredentials, publicResults);
        } catch (Throwable t) {
            LOG.error("Retrieving rooms failed:", t);
            throw t;
        }
    }

    @GET @Path("/{id}") @Produces(APPLICATION_JSON)
    public PublicCredentials getCredentials(@Context SecurityContext securityContext,
                                            @PathParam("id") int personId) {

        verifyUserAccess("admin.login.read");

        if(personId <= 0)
            throw new BadRequestException("No valid person specified");

        Credentials creds = db.getCredentials(personId);

        //Only system users can see system.
        if(!securityContext.isUserInRole("system") && creds.getRole().equals("system"))
            throw new NotFoundException("No credentials available");

        if(creds == null)
            throw new NotFoundException("No credentials available");

        return creds.toPublicCredentials();
    }
    
    @POST @Consumes(APPLICATION_JSON)
    public PublicCredentials createCredentials(@Context SecurityContext securityContext,
                                               CredentialRequest request ) {

        verifyUserAccess("admin.login.create");

        //Only system users can see system.
        if(!securityContext.isUserInRole("system") && request.getRole().equals("system"))
            throw new BadRequestException();

        if(request.getId() <= 0)
            throw new BadRequestException("No valid person specified");
        if(isEmpty(request.getRole()) || !new RoleDB().verifyRole(request.getRole()))
            throw new BadRequestException("No valid role specified");
        if(isEmpty(request.getPassword()) && !request.isSendEmail()) //TODO: Password rules go here
            throw new BadRequestException("No password specified");

        Credentials creds = new Credentials();
        creds.setId(request.getId());
        creds.setRole(request.getRole());
        creds.setHashedPassword(encryptPassword(request.getPassword()));
        creds.setResetPassword(request.isResetPassword());
        if(request.isResetPassword())
            creds.setResetToken(UUID.randomUUID().toString());

        if(db.createLogin(creds)) {
            Credentials dbCreds = db.getCredentials(creds.getId());
            if(request.isSendEmail()) {
                dbCreds.setResetToken(creds.getResetToken());
                sendEmail(dbCreds);
            }

            return dbCreds.toPublicCredentials();
        } else {
            throw new WebApplicationException("Could not create credentials");
        }
    }

    @PUT @Consumes(APPLICATION_JSON)
    public PublicCredentials updateCredentials(@Context SecurityContext securityContext,
                                               CredentialRequest request) {

        verifyUserAccess("admin.login.update");

        //Only system users can see system.
        if(!securityContext.isUserInRole("system") && request.getRole().equals("system"))
            throw new BadRequestException();

        if(request.getId() <= 0)
            throw new BadRequestException("No valid person specified");

        boolean updated = false;
        if(isSet(request.getPassword())) {
            //TODO: Password rules go here
            String hashedPassword = encryptPassword(request.getPassword());
            updated = db.updatePassword(request.getId(), hashedPassword);
        }

        Credentials creds = db.getCredentials(request.getId());
        if(isSet(request.getRole()) || request.isResetPassword()) {
            if(creds == null)
                throw new BadRequestException("Could not update credentials");

            if(isSet(request.getRole()))
                creds.setRole(request.getRole());

            if(request.isResetPassword()) {
                creds.setResetPassword(request.isResetPassword());
                creds.setResetToken(UUID.randomUUID().toString());
            }

            updated |= db.updateCredentials(creds);
        }

        if(!updated) throw new BadRequestException("Could not update credentials");

        if(request.isSendEmail())
            sendEmail(creds);

        return getCredentials(securityContext, request.getId());
    }

    @DELETE @Path("/{id}")
    public void revokePassword(@Context SecurityContext securityContext,
                                               @PathParam("id") int personId) {

        verifyUserAccess("admin.login.delete");

        Credentials creds = db.getCredentials(personId);

        //Only system users can see system.
        if(!securityContext.isUserInRole("system") && creds.getRole().equals("system"))
            throw new BadRequestException();

        if(personId <= 0)
            throw new BadRequestException("No valid person specified");

        if(!db.deleteLogin(personId))
            throw new NotFoundException();
    }

    // ----- Private -----
    private void sendEmail(Credentials creds) {
        if(isEmpty(creds.getEmail()) || isEmpty(creds.getResetToken()))
            throw new IllegalArgumentException();

        EmailNotificationClient emailClient = new EmailNotificationClient(JWTGenerator.systemToken());
        emailClient.sendPasswordResetEmail(creds.getEmail(), creds.getResetToken());
        LOG.info("Password email generated for: " + creds.getEmail());
    }
}
