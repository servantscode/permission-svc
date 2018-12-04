package org.servantscode.permission.db;

import org.servantscode.commons.db.DBAccess;
import org.servantscode.permission.Credentials;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class LoginDB extends DBAccess {

    public Credentials getCredentials(String email) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT l.*, p.name AS person_name, p.email " +
                     "FROM logins l, people p " +
                     "WHERE p.id = l.person_id AND p.email=?");
        ){
            stmt.setString(1, email);

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve login information for: " + email, e);
        }
    }

    public Credentials getCredentials(int personId) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT l.*, p.name AS person_name, p.email " +
                     "FROM logins l, people p " +
                     "WHERE p.id = l.person_id AND l.person_id=?");
        ){
            stmt.setInt(1, personId);

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve login information for person: " + personId, e);
        }
    }

    public boolean createLogin(int personId, String hashedPassword, String role) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO logins(person_id, hashed_password, role) VALUES (?, ?, ?)");
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
             PreparedStatement stmt = conn.prepareStatement("UPDATE logins SET role=? WHERE person_id =?");
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
    private Credentials processResults(PreparedStatement stmt) throws SQLException {
        try (ResultSet rs = stmt.executeQuery()){
            if(!rs.next())
                return null;

            Credentials creds = new Credentials();
            creds.setUsername(rs.getString("person_name"));
            creds.setPersonId(rs.getInt("person_id"));
            creds.setEmail(rs.getString("email"));
            creds.setHashedPassword(rs.getString("hashed_password"));
            creds.setRole(rs.getString("role"));

            if(rs.next())
                throw new RuntimeException("Duplicative email logins found!");
            return creds;
        }
    }
}
