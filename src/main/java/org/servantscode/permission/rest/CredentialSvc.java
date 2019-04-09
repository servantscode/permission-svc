package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.rest.PaginatedResponse;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Credentials;
import org.servantscode.permission.PublicCredentials;
import org.servantscode.permission.db.LoginDB;
import org.servantscode.permission.db.RoleDB;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.stream.Collectors;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.commons.StringUtils.isEmpty;

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
        if(isEmpty(request.getPassword())) //TODO: Password rules go here
            throw new BadRequestException("No password specified");

        Credentials creds = new Credentials();
        creds.setId(request.getId());
        creds.setRole(request.getRole());
        creds.setHashedPassword(BCrypt.hashpw(request.getPassword(), BCrypt.gensalt()));
        creds.setResetPassword(request.isResetPassword());

        if(db.createLogin(creds))
            return getCredentials(securityContext, creds.getId());
        else
            throw new WebApplicationException("Could not create credentials");
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
        if(!isEmpty(request.getPassword())) {
            //TODO: Password rules go here
            String hashedPassword = BCrypt.hashpw(request.getPassword(), BCrypt.gensalt());
            updated = db.updatePassword(request.getId(), hashedPassword);
        }

        if(!isEmpty(request.getRole()) || request.isResetPassword()) {
            Credentials creds = new Credentials();
            creds.setId(request.getId());
            creds.setRole(request.getRole());
            creds.setResetPassword(request.isResetPassword());

            updated |= db.updateCredentials(creds);
        }

        if(!updated) throw new BadRequestException("Could not update credentials");

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
}
