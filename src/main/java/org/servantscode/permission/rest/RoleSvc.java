package org.servantscode.permission.rest;

import org.servantscode.commons.rest.SCServiceBase;
import org.servantscode.permission.Role;
import org.servantscode.permission.db.RoleDB;

import javax.ws.rs.*;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.stream.Collectors;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.commons.StringUtils.isEmpty;

@Path("/role")
public class RoleSvc extends SCServiceBase {

    private RoleDB db;

    public RoleSvc() {
        db = new RoleDB();
    }

    @GET @Produces(APPLICATION_JSON)
    public List<String> getRoles() {
        verifyUserAccess("role.list");

        return db.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());
    }

    @POST @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Role createRole(Role role) {
        verifyUserAccess("role.create");

        if(!isEmpty(role.getName()))
            throw new BadRequestException("No name specified");

        return db.create(role);
    }

    @PUT @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Role updateRole(Role role) {
        verifyUserAccess("role.update");

        if(role.getId() <= 0)
            throw new BadRequestException("No role specified");
        if(!isEmpty(role.getName()))
            throw new BadRequestException("No name specified");

        return db.update(role);
    }

    @DELETE @Path("/{roleId}")
    public boolean deleteRole(@QueryParam("roleId") int roleId) {
        verifyUserAccess("role.delete");

        if(roleId <= 0)
            throw new BadRequestException("No role specified");

        return db.deleteRole(roleId);
    }
}
