package org.servantscode.permission.db;

import org.servantscode.commons.db.DBAccess;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;

public class PermissionDB extends DBAccess {
    public String[] getPermissionsForRole(String role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT permission FROM permissions " +
                     "WHERE role_id=(SELECT id FROM roles WHERE name=?)"))
        {
            stmt.setString(1, role);
            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not get permissions for role: " + role, e);
        }
    }

    public String[] getPermissionsForRoleId(int roleId) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT permission FROM permissions WHERE role_id=?")) {
            stmt.setInt(1, roleId);
            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not get permissions for role: " + roleId, e);
        }
    }

    // ----- Private -----
    private String[] processResults(PreparedStatement stmt) throws SQLException {
        try (ResultSet rs = stmt.executeQuery()) {
            LinkedList<String> perms = new LinkedList<>();
            while (rs.next())
                perms.add(rs.getString(1));

            return perms.toArray(new String[perms.size()]);
        }
    }
}
