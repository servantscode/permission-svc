package org.servantscode.permission.db;

import org.servantscode.commons.db.DBAccess;
import org.servantscode.commons.search.QueryBuilder;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;

public class PermissionDB extends DBAccess {
    public String[] getPermissionsForRoleId(int roleId) {
        QueryBuilder query = select("permission").from("permissions").where("role_id=?", roleId);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn)) {

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not get permissions for role: " + roleId, e);
        }
    }

    public void createPermissionsForRole(int roleId, String[] permissions) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO permissions(role_id, permission) VALUES (?, ?)")) {
            stmt.setInt(1, roleId);

            for(String perm: permissions) {
                stmt.setString(2, perm);
                stmt.addBatch();
            }

            stmt.executeBatch();
        } catch (SQLException e) {
            throw new RuntimeException("Could not create permissions for role: " + roleId, e);
        }
    }

    public void updatePermissionsForRole(int roleId, String[] permissions) {
        deletePermissionsForRole(roleId);
        createPermissionsForRole(roleId, permissions);
    }

    public void deletePermissionsForRole(int roleId) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("DELETE FROM permissions WHERE role_id=?")) {
            stmt.setInt(1, roleId);

            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Could not create permissions for role: " + roleId, e);
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
