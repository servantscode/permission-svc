package org.servantscode.permission.db;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.AutoCompleteComparator;
import org.servantscode.commons.db.DBAccess;
import org.servantscode.commons.db.EasyDB;
import org.servantscode.commons.search.InsertBuilder;
import org.servantscode.commons.search.QueryBuilder;
import org.servantscode.commons.search.SearchParser;
import org.servantscode.commons.search.UpdateBuilder;
import org.servantscode.commons.security.OrganizationContext;
import org.servantscode.commons.security.SCSecurityContext;
import org.servantscode.permission.Role;

import java.sql.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static java.lang.String.format;
import static org.servantscode.commons.StringUtils.isEmpty;
import static org.servantscode.commons.security.SCSecurityContext.SYSTEM;

public class RoleDB extends EasyDB<Role> {
    private static Logger LOG = LogManager.getLogger(RoleDB.class);

    private PermissionDB permDB;

    public RoleDB() {
        super(Role.class, "name");
        permDB = new PermissionDB();
    }

    public int getCount(String search, boolean includeSystem) {
        return getCount(count().from("roles").search(searchParser.parse(search)).inOrg(includeSystem));
    }

    public List<Role> getRoles(String search, String sortField, int start, int count, boolean includeSystem) {
        return get(selectAll().from("roles").search(searchParser.parse(search)).inOrg(includeSystem)
                .page(sortField, start, count));
    }

    public Role getRole(int id) {
        return getOne(selectAll().from("roles").withId(id).inOrg(true));
    }

    public boolean verifyRole(String role) {
        return existsAny(count().from("roles").with("name", role).inOrg(role.equals(SYSTEM)));
    }

    public Role create(Role role) {
        InsertBuilder cmd = insertInto("roles")
                .value("name", role.getName())
                .value("requires_checkin", role.isRequiresCheckin())
                .value("org_id", OrganizationContext.orgId());

        role.setId(createAndReturnKey(cmd));
        permDB.updatePermissionsForRole(role.getId(), role.getPermissions());
        return role;
    }

    public Role update(Role role) {
        UpdateBuilder cmd = update("roles")
                .value("name", role.getName())
                .value("requires_checkin", role.isRequiresCheckin())
                .withId(role.getId()).inOrg();

        if(!update(cmd))
            throw new RuntimeException("Could not update role: " + role.getName());

        permDB.updatePermissionsForRole(role.getId(), role.getPermissions());
        return role;
    }

    //No need to delete permissions. FK delete cascades
    public boolean deleteRole(int roleId) {
        return delete(deleteFrom("roles").withId(roleId).inOrg());
    }

    // ----- Private -----
    @Override
    protected Role processRow(ResultSet rs) throws SQLException {
        Role r = new Role(rs.getInt("id"), rs.getString("name"));
        r.setRequiresCheckin(rs.getBoolean("requires_checkin"));
        r.setPermissions(permDB.getPermissionsForRoleId(r.getId()));
        return r;
    }
}
