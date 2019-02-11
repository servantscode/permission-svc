package org.servantscode.permission.db;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.db.DBAccess;
import org.servantscode.permission.Credentials;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;

import static java.lang.String.format;
import static org.servantscode.commons.StringUtils.isEmpty;

public class LoginDB extends DBAccess {
    private static Logger LOG = LogManager.getLogger(LoginDB.class);

    private PermissionDB permDB;

    public LoginDB() {
        permDB = new PermissionDB();
    }


    public int getRoleCount(String role, String search) {
        String sql = format("SELECT count(1) FROM logins l, people p, roles r " +
                            "WHERE p.id = l.person_id AND l.role_id = r.id AND r.name=?%s",
                            optionalWhereClause(search));
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, role);
            try(ResultSet rs = stmt.executeQuery()) {
                if (rs.next())
                    return rs.getInt(1);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve role count '" + search + "'", e);
        }
        return 0;

    }

    public Credentials getCredentials(String email) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT l.*, p.name AS name, r.name AS role, p.email " +
                                                                 "FROM logins l, people p, roles r " +
                                                                 "WHERE p.id = l.person_id AND l.role_id = r.id AND p.email=?");
        ){
            stmt.setString(1, email);

            List<Credentials> creds = processResults(stmt);
            if(creds.isEmpty())
                return null;

            if(creds.size() > 1)
                throw new RuntimeException("Duplicative email logins found!");

            return creds.get(0);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve login information for: " + email, e);
        }
    }

    public Credentials getCredentials(int personId) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT l.*, p.name AS name, r.name AS role, p.email " +
                     "FROM logins l, people p, roles r " +
                     "WHERE p.id = l.person_id AND l.role_id=r.id AND l.person_id=?");
        ){
            stmt.setInt(1, personId);

            List<Credentials> creds = processResults(stmt);
            if(creds.isEmpty())
                return null;

            if(creds.size() > 1)
                throw new RuntimeException("Duplicative email logins found!");

            return creds.get(0);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve login information for person: " + personId, e);
        }
    }

    public List<Credentials> getCredentialsForRole(String role, int start, int count, String sortField, String search) {
        String sql = format("SELECT l.*, p.name AS name, r.name AS role, p.email " +
                            "FROM logins l, people p, roles r " +
                            "WHERE p.id = l.person_id AND l.role_id=r.id AND r.name=?%s " +
                            "ORDER BY %s LIMIT ? OFFSET ?",
                            optionalWhereClause(search), sortField);

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql);
        ){
            stmt.setString(1, role);
            stmt.setInt(2, count);
            stmt.setInt(3, start);

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve user with role: " + role, e);
        }
    }

    public boolean createLogin(int personId, String hashedPassword, String role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO logins(person_id, hashed_password, role_Id) VALUES (?, ?, (SELECT id FROM roles WHERE name=?))");
        ){

            stmt.setInt(1, personId);
            stmt.setString(2, hashedPassword);
            stmt.setString(3, role);

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not create login for: Person(" + personId + ")", e);
        }
    }

    public boolean updateRole(int personId, String role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("UPDATE logins SET role=(SELECT id FROM roles WHERE name=?) WHERE person_id =?");
        ){

            stmt.setString(1, role);
            stmt.setInt(2, personId);

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not update role for Person(" + personId + ")", e);
        }
    }

    public boolean updatePassword(int personId, String hashedPassword) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("UPDATE logins SET hashed_password=? WHERE person_id =?");
        ){

            stmt.setString(1, hashedPassword);
            stmt.setInt(2, personId);

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not update role for Person(" + personId + ")", e);
        }
    }

    public boolean deleteLogin(int personId) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("DELETE FROM logins WHERE person_id = ?");
        ){
            stmt.setInt(1, personId);

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not delete login for Person(" + personId + ")", e);
        }
    }
    // ----- Private -----
    private List<Credentials> processResults(PreparedStatement stmt) throws SQLException {
        try (ResultSet rs = stmt.executeQuery()){
            List<Credentials> results = new LinkedList<>();

            while(rs.next()) {
                Credentials creds = new Credentials();
                creds.setName(rs.getString("name"));
                creds.setPersonId(rs.getInt("person_id"));
                creds.setEmail(rs.getString("email"));
                creds.setHashedPassword(rs.getString("hashed_password"));
                creds.setRole(rs.getString("role"));
                creds.setRoleId(rs.getInt("role_id"));
                creds.setPermissions(permDB.getPermissionsForRoleId(creds.getRoleId()));
                results.add(creds);
            }

            return results;
        }
    }

    private String optionalWhereClause(String search) {
        return !isEmpty(search) ? format(" AND p.name ILIKE '%%%s%%'", search.replace("'", "''")) : "";
    }
}
