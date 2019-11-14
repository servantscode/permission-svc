package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.omg.CosNaming.NamingContextPackage.NotFound;
import org.servantscode.commons.db.SessionDB;
import org.servantscode.commons.rest.PaginatedResponse;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Checkin;
import org.servantscode.permission.Role;
import org.servantscode.permission.db.CheckinDB;
import org.servantscode.permission.db.RoleDB;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Path("/checkin")
public class CheckinSvc extends SCServiceBase {
    private static Logger LOG = LogManager.getLogger(CheckinSvc.class);

    private CheckinDB db;
    private RoleDB roleDb;
    private SessionDB sessionDb;

    public CheckinSvc() {
        db = new CheckinDB();
        roleDb = new RoleDB();
        sessionDb = new SessionDB();
    }

    @GET @Produces(MediaType.APPLICATION_JSON)
    public PaginatedResponse<Checkin> getCheckins(@QueryParam("start") @DefaultValue("0") int start,
                                            @QueryParam("count") @DefaultValue("10") int count,
                                            @QueryParam("sort_field") @DefaultValue("personName") String sortField,
                                            @QueryParam("search") @DefaultValue("") String search) {

        verifyUserAccess("admin.checkin.list");
        try {
            int totalCheckins = db.getCount(search);
            List<Checkin> results = db.getCheckins(search, sortField, start, count);

            return new PaginatedResponse<>(start, results.size(), totalCheckins, results);
        } catch (Throwable t) {
            LOG.error("Retrieving checkins failed:", t);
            throw t;
        }
    }

    @GET @Path("/active") @Produces(MediaType.APPLICATION_JSON)
    public PaginatedResponse<Checkin> getActiveCheckins(@QueryParam("start") @DefaultValue("0") int start,
                                                  @QueryParam("count") @DefaultValue("10") int count,
                                                  @QueryParam("sort_field") @DefaultValue("personName") String sortField,
                                                  @QueryParam("search") @DefaultValue("") String search) {

        verifyUserAccess("admin.checkin.list");
        try {
            int totalCheckins = db.getActiveCount(search);
            List<Checkin> results = db.getActiveCheckins(search, sortField, start, count);

            return new PaginatedResponse<>(start, results.size(), totalCheckins, results);
        } catch (Throwable t) {
            LOG.error("Retrieving checkins failed:", t);
            throw t;
        }
    }

    @GET @Path("/{id}") @Produces(MediaType.APPLICATION_JSON)
    public Checkin getCheckin(@PathParam("id") int id) {
        verifyUserAccess("admin.checkin.read");
        try {
            return db.getCheckin(id);
        } catch (Throwable t) {
            LOG.error("Retrieving checkin failed:", t);
            throw t;
        }
    }

    @POST @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Checkin createCheckin(Checkin checkin) {
        verifyUserAccess("admin.checkin.create");

        if(checkin.getPersonId() <= 0 ||
            checkin.getExpiration() == null || checkin.getExpiration().isBefore(ZonedDateTime.now()))
            throw new BadRequestException();

        Role r = roleDb.getUserRole(checkin.getPersonId());
        if(r == null || !r.isRequiresCheckin())
            throw new BadRequestException("No checkin required/accepted.");

        checkin.setCheckedinAt(ZonedDateTime.now());
        checkin.setCheckedinById(getUserId());

        return db.create(checkin);
    }

    @PUT @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Checkin updateCheckin(Checkin checkin) {
        verifyUserAccess("admin.checkin.update");

        Checkin existingCheckin = db.getCheckin(checkin.getId());

        if(checkin.getId() <= 0 || checkin.getPersonId() <= 0 || existingCheckin == null ||
                checkin.getExpiration() == null || checkin.getExpiration().isBefore(ZonedDateTime.now()))
            throw new BadRequestException();

        checkin.setCheckedinAt(ZonedDateTime.now());
        checkin.setCheckedinById(getUserId());

        if(checkin.getExpiration().isBefore(existingCheckin.getExpiration()))
            sessionDb.deleteAllSessions(existingCheckin.getPersonId());

        return db.update(checkin);
    }

    @DELETE @Path("/{id}")
    public void deleteCheckin(@PathParam("id") long id) {
        verifyUserAccess("admin.checkin.delete");

        if(id <= 0)
            throw new BadRequestException();

        Checkin existingCheckin = db.getCheckin(id);

        if(existingCheckin == null || !db.deleteCheckin(id))
            throw new NotFoundException();

        sessionDb.deleteAllSessions(existingCheckin.getPersonId());
        LOG.debug("Checkin revoked: " + id);
    }
}
