package org.servantscode.permission.db;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.AutoCompleteComparator;
import org.servantscode.commons.db.DBAccess;
import org.servantscode.permission.Role;

import java.sql.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static java.lang.String.format;
import static org.servantscode.commons.StringUtils.isEmpty;

public class RoleDB extends DBAccess {
    private static Logger LOG = LogManager.getLogger(RoleDB.class);

    private PermissionDB permDB;

    public RoleDB() {
        permDB = new PermissionDB();
    }

    public int getCount(String search, boolean includeSystem) {
        String sql = format("Select count(1) from roles%s", optionalWhereClause(search, includeSystem));
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            if (rs.next())
                return rs.getInt(1);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve role count '" + search + "'", e);
        }
        return 0;
    }

    public List<String> getRoleNames(String search, int count, boolean includeSystem) {
        String sql = format("SELECT name FROM roles%s", optionalWhereClause(search, includeSystem));
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            List<String> names = new ArrayList<>();

            while (rs.next())
                names.add(rs.getString(1));

            long start = System.currentTimeMillis();
            names.sort(new AutoCompleteComparator(search));
            LOG.debug(String.format("Sorted %d names in %d ms.", names.size(), System.currentTimeMillis()-start));

            return (count < names.size()) ? names.subList(0, count): names;
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve role names containing '" + search + "'", e);
        }
    }

    public List<Role> getRoles(String search, String sortField, int start, int count, boolean includeSystem) {
        String sql = format("SELECT * FROM roles%s ORDER BY %s LIMIT ? OFFSET ?", optionalWhereClause(search, includeSystem), sortField);
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql);
        ){
            stmt.setInt(1, count);
            stmt.setInt(2, start);

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve roles.", e);
        }
    }

    public Role getRole(int id) {
        String sql = "SELECT * FROM roles WHERE id=?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql);
        ) {

            stmt.setInt(1, id);

            List<Role> rules = processResults(stmt);
            if(rules.isEmpty())
                return null;

            return rules.get(0);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve rule: " + id, e);
        }

    }

    public boolean verifyRole(String role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT * FROM roles WHERE name=?");
        ){
            stmt.setString(1, role);

            return !processResults(stmt).isEmpty();
        } catch (SQLException e) {
            throw new RuntimeException("Could not verify role: " + role, e);
        }
    }

    public Role create(Role role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO roles(name) values (?)", Statement.RETURN_GENERATED_KEYS)
        ){
            stmt.setString(1, role.getName());


            if(stmt.executeUpdate() == 0) {
                throw new RuntimeException("Could not create role: " + role.getName());
            }

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
             PreparedStatement stmt = conn.prepareStatement("UPDATE roles SET name=? WHERE id=?")
        ){
            stmt.setString(1, role.getName());
            stmt.setInt(2, role.getId());

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
             PreparedStatement stmt = conn.prepareStatement("DELETE FROM roles WHERE id=?")
        ){
            stmt.setInt(1, roleId);

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

    private String optionalWhereClause(String search, boolean includeSystem) {
        String clause = !isEmpty(search) ? format(" WHERE name ILIKE '%%%s%%'", search.replace("'", "''")) : "";
        if(!includeSystem)
            clause = (isEmpty(clause)? " WHERE": clause + " AND") + " name <> 'system'";
        return clause;
    }
}
