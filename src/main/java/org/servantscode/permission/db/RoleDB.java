package org.servantscode.permission.db;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.AutoCompleteComparator;
import org.servantscode.commons.db.DBAccess;
import org.servantscode.commons.search.QueryBuilder;
import org.servantscode.commons.search.SearchParser;
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

public class RoleDB extends DBAccess {
    private static Logger LOG = LogManager.getLogger(RoleDB.class);

    private PermissionDB permDB;
    private SearchParser<Role> searchParser;

    public RoleDB() {
        permDB = new PermissionDB();
        searchParser = new SearchParser<>(Role.class, "name");
    }

    public int getCount(String search, boolean includeSystem) {
//        String sql = format("Select count(1) from roles%s", optionalWhereClause(search, includeSystem));
        QueryBuilder query = count().from("roles").search(searchParser.parse(search)).inOrg(includeSystem);

        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn);
             ResultSet rs = stmt.executeQuery()) {

            return rs.next()? rs.getInt(1): 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve role count '" + search + "'", e);
        }
    }

    public List<Role> getRoles(String search, String sortField, int start, int count, boolean includeSystem) {
        QueryBuilder query = selectAll().from("roles").search(searchParser.parse(search)).inOrg(includeSystem)
                .sort(sortField).limit(count).offset(start);
//        String sql = format("SELECT * FROM roles%s ORDER BY %s LIMIT ? OFFSET ?", optionalWhereClause(search, includeSystem), sortField);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn)){

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve roles.", e);
        }
    }

    public Role getRole(int id) {
        QueryBuilder query = selectAll().from("roles").withId(id).inOrg(true);
//        String sql = "SELECT * FROM roles WHERE id=?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn)) {

            return firstOrNull(processResults(stmt));
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve rule: " + id, e);
        }
    }

    public boolean verifyRole(String role) {
        QueryBuilder query = selectAll().from("roles").where("name=?", role).inOrg(role.equals(SYSTEM));
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn)){

            return !processResults(stmt).isEmpty();
        } catch (SQLException e) {
            throw new RuntimeException("Could not verify role: " + role, e);
        }
    }

    public Role create(Role role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO roles(name, org_id) values (?,?)", Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, role.getName());
            stmt.setInt(2, OrganizationContext.orgId());

            if(stmt.executeUpdate() == 0)
                throw new RuntimeException("Could not create role: " + role.getName());

            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs.next())
                    role.setId(rs.getInt(1));
            }

            permDB.createPermissionsForRole(role.getId(), role.getPermissions());
            return role;
        } catch (SQLException e) {
            throw new RuntimeException("Could not create role: " + role.getName(), e);
        }
    }

    public Role update(Role role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("UPDATE roles SET name=? WHERE id=? AND org_id=?")
        ){
            stmt.setString(1, role.getName());
            stmt.setInt(2, role.getId());
            stmt.setInt(3, OrganizationContext.orgId());

            if(stmt.executeUpdate() == 0) {
                throw new RuntimeException("Could not update role: " + role.getName());
            }

            permDB.updatePermissionsForRole(role.getId(), role.getPermissions());
            return role;
        } catch (SQLException e) {
            throw new RuntimeException("Could not update role: " + role.getId(), e);
        }
    }

    //No need to delete permissions. FK delete cascades
    public boolean deleteRole(int roleId) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("DELETE FROM roles WHERE id=? AND org_id=?")
        ){
            stmt.setInt(1, roleId);
            stmt.setInt(2, OrganizationContext.orgId());

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not delete role: " + roleId, e);
        }
    }

    // ----- Private -----
    private List<Role> processResults(PreparedStatement stmt) throws SQLException {
        List<Role> results = new LinkedList<>();
        try (ResultSet rs = stmt.executeQuery()){
            while(rs.next()) {
                Role r = new Role(rs.getInt("id"), rs.getString("name"));
                r.setPermissions(permDB.getPermissionsForRoleId(r.getId()));
                results.add(r);
            }
        }
        return results;
    }
}
