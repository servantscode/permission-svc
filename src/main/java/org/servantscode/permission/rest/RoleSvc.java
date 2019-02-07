package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.rest.PaginatedResponse;
import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Role;
import org.servantscode.permission.db.RoleDB;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.util.List;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.commons.StringUtils.isEmpty;

@Path("/role")
public class RoleSvc extends SCServiceBase {
    private static Logger LOG = LogManager.getLogger(RoleSvc.class);

    private RoleDB db;

    public RoleSvc() {
        db = new RoleDB();
    }

    @GET @Path("/autocomplete") @Produces(APPLICATION_JSON)
    public List<String> getRolesNames(@QueryParam("count") @DefaultValue("100") int count,
                                      @QueryParam("partial_name") @DefaultValue("") String nameSearch,
                                      @Context SecurityContext securityContext) {

        verifyUserAccess("role.list");

       List<String> roles = db.getRoleNames(nameSearch, count);

       //Only system users can see system.
        if(!securityContext.isUserInRole("system"))
            roles.removeIf(role -> role.equals("system"));

        return roles;
    }

    @GET @Produces(MediaType.APPLICATION_JSON)
    public PaginatedResponse<Role> getRoles(@QueryParam("start") @DefaultValue("0") int start,
                                            @QueryParam("count") @DefaultValue("10") int count,
                                            @QueryParam("sort_field") @DefaultValue("name") String sortField,
                                            @QueryParam("partial_name") @DefaultValue("") String nameSearch,
                                            @Context SecurityContext securityContext) {

        verifyUserAccess("room.list");
        try {
            int totalPeople = db.getCount(nameSearch);

            List<Role> results = db.getRoles(nameSearch, sortField, start, count);

            //Only system users can see system.
            if(!securityContext.isUserInRole("system"))
                results.removeIf(role -> role.getName().equals("system"));

            return new PaginatedResponse<>(start, results.size(), totalPeople, results);
        } catch (Throwable t) {
            LOG.error("Retrieving rooms failed:", t);
            throw t;
        }
    }

    @GET @Path("/{id}") @Produces(MediaType.APPLICATION_JSON)
    public Role getRole(@PathParam("id") int id,
                        @Context SecurityContext securityContext) {
        verifyUserAccess("rule.read");
        try {

            Role role = db.getRole(id);

            //Only system users can see system.
            if(!securityContext.isUserInRole("system") && role.getName().equals("system"))
                throw new NotFoundException();

            return role;
        } catch (Throwable t) {
            LOG.error("Retrieving rule failed:", t);
            throw t;
        }
    }

    @POST @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Role createRole(Role role) {
        verifyUserAccess("role.create");

        //Only system users can see system.
        if(role.getName().equals("system"))
            throw new BadRequestException();

        if(isEmpty(role.getName()))
            throw new BadRequestException("No name specified");

        return db.create(role);
    }

    @PUT @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Role updateRole(Role role) {
        verifyUserAccess("role.update");

        //System role cannot be deleted
        if(role.getName().equals("system") || role.getId() == 1)
            throw new BadRequestException();

        if(role.getId() <= 0)
            throw new BadRequestException("No role specified");
        if(isEmpty(role.getName()))
            throw new BadRequestException("No name specified");

        return db.update(role);
    }

    @DELETE @Path("/{roleId}")
    public boolean deleteRole(@QueryParam("roleId") int roleId) {
        verifyUserAccess("role.delete");

        //System role cannot be deleted
        if(roleId == 1)
            throw new BadRequestException();

        if(roleId <= 0)
            throw new BadRequestException("No role specified");

        return db.deleteRole(roleId);
    }
}
