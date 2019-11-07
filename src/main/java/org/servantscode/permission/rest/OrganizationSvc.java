package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.Organization;
import org.servantscode.commons.db.OrganizationDB;
import org.servantscode.commons.rest.PaginatedResponse;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.commons.security.OrganizationContext;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.util.List;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.commons.StringUtils.isEmpty;

@Path("/organization")
public class OrganizationSvc extends SCServiceBase {
    private static Logger LOG = LogManager.getLogger(OrganizationSvc.class);

    private OrganizationDB db;

    public OrganizationSvc() {
        db = new OrganizationDB();
    }

    @GET @Produces(MediaType.APPLICATION_JSON)
    public PaginatedResponse<Organization> getOrganizations(@QueryParam("start") @DefaultValue("0") int start,
                                            @QueryParam("count") @DefaultValue("10") int count,
                                            @QueryParam("sort_field") @DefaultValue("name") String sortField,
                                            @QueryParam("search") @DefaultValue("") String search,
                                            @Context SecurityContext securityContext) {

        verifyUserAccess("system.organization.list");
        try {
            int totalOrgs = db.getCount(search);
            List<Organization> results = db.getOrganizations(search, sortField, start, count);

            return new PaginatedResponse<>(start, results.size(), totalOrgs, results);
        } catch (Throwable t) {
            LOG.error("Retrieving organizations failed:", t);
            throw t;
        }
    }

    @GET @Path("/{id}") @Produces(MediaType.APPLICATION_JSON)
    public Organization getOrganization(@PathParam("id") int id) {
        verifyUserAccess("system.organization.read");
        try {
            return db.getOrganization(id);
        } catch (Throwable t) {
            LOG.error("Retrieving organization failed:", t);
            throw t;
        }
    }

    @GET @Path("/active") @Produces(MediaType.APPLICATION_JSON)
    public Organization getActiveOrganization() {
        try {
            return OrganizationContext.getOrganization();
        } catch (Throwable t) {
            LOG.error("Retrieving active organization failed:", t);
            throw t;
        }
    }

    @POST @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Organization createOrganization(Organization org) {
        verifyUserAccess("system.organization.create");

        if(isEmpty(org.getName()) || isEmpty(org.getHostName()))
            throw new BadRequestException("No name specified");

        return db.create(org);
    }

    @PUT @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Organization updateOrganization(Organization org) {
        verifyUserAccess("system.organization.update");

        if(org.getId() <= 0)
            throw new BadRequestException("No organization specified");
        if(isEmpty(org.getName()) || isEmpty(org.getHostName()))
            throw new BadRequestException("No name specified");

        return db.update(org);
    }

    @PUT @Path("/{id}/photo") @Consumes(MediaType.TEXT_PLAIN)
    public void attachPhoto(@PathParam("id") int id,
                            String guid) {
        verifyUserAccess("admin.organization.update");

        LOG.debug("Attaching photo: " + guid);
        try {
            db.attchPhoto(id, guid);
        } catch (Throwable t) {
            LOG.error("Attaching photo to organization failed.", t);
            throw t;
        }
    }
    @DELETE @Path("/{orgId}")
    public void deleteOrganization(@PathParam("orgId") int orgId) {
        verifyUserAccess("system.organization.delete");

        if(orgId <= 0)
            throw new BadRequestException("No organization specified");

        Organization org = db.getOrganization(orgId);

        if(org == null)
            throw new NotFoundException();

        db.delete(org);
        LOG.debug("Organiation deleted: " + org.getName());
    }
}
