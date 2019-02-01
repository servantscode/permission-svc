package org.servantscode.permission.rest;

import org.servantscode.permission.Role;
import org.servantscode.permission.db.LoginDB;
import org.servantscode.permission.db.RoleDB;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.servantscode.commons.StringUtils.isEmpty;

@Path("/role")
public class RoleSvc {

    private RoleDB db;

    public RoleSvc() {
        db = new RoleDB();
    }

    @GET @Produces(APPLICATION_JSON)
    public List<String> getRoles(@Context SecurityContext securityContext) {
        if(!securityContext.isUserInRole("system") && !securityContext.isUserInRole("admin"))
            throw new ForbiddenException("Please speak with your admin to complete this action");

        return db.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());
    }

    @POST @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Role createRole(@Context SecurityContext securityContext, Role role) {

        if(!securityContext.isUserInRole("system") && !securityContext.isUserInRole("admin"))
            throw new ForbiddenException("Please speak with your admin to complete this action");

        if(!isEmpty(role.getName()))
            throw new BadRequestException("No name specified");

        return db.create(role);
    }

    @PUT @Consumes(APPLICATION_JSON) @Produces(APPLICATION_JSON)
    public Role updateRole(@Context SecurityContext securityContext, Role role) {

        if(!securityContext.isUserInRole("system") && !securityContext.isUserInRole("admin"))
            throw new ForbiddenException("Please speak with your admin to complete this action");

        if(role.getId() <= 0)
            throw new BadRequestException("No role specified");
        if(!isEmpty(role.getName()))
            throw new BadRequestException("No name specified");

        return db.update(role);
    }

    @DELETE @Path("/{roleId}")
    public boolean deleteRole(@Context SecurityContext securityContext, @QueryParam("roleId") int roleId) {

        if(!securityContext.isUserInRole("system") && !securityContext.isUserInRole("admin"))
            throw new ForbiddenException("Please speak with your admin to complete this action");

        if(roleId <= 0)
            throw new BadRequestException("No role specified");

        return db.deleteRole(roleId);
    }
}
