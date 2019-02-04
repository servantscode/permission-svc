package org.servantscode.permission.db;

import org.servantscode.commons.db.DBAccess;
import org.servantscode.permission.Role;

import java.sql.*;
import java.util.LinkedList;
import java.util.List;

public class RoleDB extends DBAccess {

    private PermissionDB permDB;

    public RoleDB() {
        permDB = new PermissionDB();
    }

    public List<Role> getRoles() {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT * FROM roles");
        ){

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve roles.", e);
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

            return role;
        } catch (SQLException e) {
            throw new RuntimeException("Could not update role: " + role.getId(), e);
        }
    }

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
}
