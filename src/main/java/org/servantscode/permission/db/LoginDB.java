package org.servantscode.permission.db;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.db.DBAccess;
import org.servantscode.commons.search.QueryBuilder;
import org.servantscode.commons.search.SearchParser;
import org.servantscode.commons.security.OrganizationContext;
import org.servantscode.permission.Credentials;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import static java.lang.String.format;
import static org.servantscode.commons.StringUtils.isEmpty;
import static org.servantscode.commons.security.SCSecurityContext.SYSTEM;

public class LoginDB extends DBAccess {
    private static Logger LOG = LogManager.getLogger(LoginDB.class);

    private static final String[] RESET_PASSWORD = new String[] {"password.reset"};

    private PermissionDB permDB;
    private SearchParser<Credentials> searchParser;

    private static HashMap<String, String> FIELD_MAP;
    static {
        FIELD_MAP = new HashMap<>(8);
        FIELD_MAP.put("name", "p.name");
        FIELD_MAP.put("role", "r.name");
    }

    public LoginDB() {
        permDB = new PermissionDB();
        searchParser = new SearchParser<>(Credentials.class, "name", FIELD_MAP);
    }

    public int getAccessCount(String search, boolean includeSystem) {
        QueryBuilder query = count().from("logins l", "people p", "roles r")
                .where("p.id=l.person_id").where("l.role_id=r.id")
                .search(searchParser.parse(search))
                .inOrg("p.org_id", includeSystem).inOrg("r.org_id", includeSystem);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn);
             ResultSet rs = stmt.executeQuery()) {

            return rs.next()? rs.getInt(1): 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve role count '" + search + "'", e);
        }
    }

    public int getRoleCount(String role, String search) {
        boolean includeSystem = !role.equals(SYSTEM);

        QueryBuilder query = count().from("logins l", "people p", "roles r")
                .where("p.id=l.person_id").where("l.role_id=r.id").where("r.name=?", role)
                .search(searchParser.parse(search))
                .inOrg("p.org_id", includeSystem).inOrg("r.org_id", includeSystem);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn);
             ResultSet rs = stmt.executeQuery()) {

            return rs.next()? rs.getInt(1): 0;
    } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve role count '" + search + "'", e);
        }
    }

    private QueryBuilder baseQuery(boolean includeSystem) {
        return select("l.*", "p.name AS name", "r.name AS role", "p.email")
            .from("logins l", "people p", "roles r")
            .where("p.id = l.person_id").where("l.role_id = r.id")
            .inOrg("p.org_id", includeSystem).inOrg("r.org_id", includeSystem);
    }

    public List<Credentials> getCredentials(int start, int count, String sortField, String search, boolean includeSystem) {
        QueryBuilder query = baseQuery(includeSystem).search(searchParser.parse(search))
            .sort(sortField).limit(count).offset(start);

        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn)) {

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve user credentials.", e);
        }
    }


    public Credentials getCredentials(String email) {
        QueryBuilder query = baseQuery(true).where("p.email=?", email);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn) ){

            List<Credentials> creds = processResults(stmt);
            if(creds.size() > 1)
                throw new RuntimeException("Duplicative email logins found!");

            return firstOrNull(creds);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve login information for: " + email, e);
        }
    }

    public Credentials getCredentials(int personId) {
        QueryBuilder query = baseQuery(true).where("l.person_id=?", personId);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn) ){

            List<Credentials> creds = processResults(stmt);
            if(creds.size() > 1)
                throw new RuntimeException("Duplicative email logins found!");

            return firstOrNull(creds);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve login information for person: " + personId, e);
        }
    }

    public List<Credentials> getCredentialsForRole(String role, int start, int count, String sortField, String search) {
        QueryBuilder query = baseQuery(role.equals(SYSTEM))
                .search(searchParser.parse(search)).where("r.name=?", role)
                .sort(sortField).limit(count).offset(start);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn) ){

            return processResults(stmt);
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve users with role: " + role, e);
        }
    }

    public int getPersonIdForPasswordToken(String passwordToken) {
        QueryBuilder query = select("person_id").from("logins")
                .where("reset_token=?", passwordToken);
        try (Connection conn = getConnection();
             PreparedStatement stmt = query.prepareStatement(conn);
             ResultSet rs = stmt.executeQuery()) {

            int personId = rs.next()? rs.getInt("person_id"): -1;
            if(rs.next())
                throw new RuntimeException("Duplicative password tokens found!");

            return personId;
        } catch (SQLException e) {
            throw new RuntimeException("Could not retrieve login information for password tokens : " + passwordToken, e);
        }
    }

    public boolean createLogin(Credentials creds) {
        String sql = "INSERT INTO logins(person_id, hashed_password, role_id, reset_password, reset_token) " +
                "VALUES (?, ?, (SELECT id FROM roles WHERE name=? AND (org_id=? OR org_id IS NULL)), ?, ?)";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)){

            stmt.setInt(1, creds.getId());
            stmt.setString(2, creds.getHashedPassword());
            stmt.setString(3, creds.getRole());
            stmt.setInt(4, OrganizationContext.orgId());
            stmt.setBoolean(5, creds.isResetPassword());
            stmt.setString(6, creds.getResetToken());

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not create login for: Person(" + creds.getId() + ")", e);
        }
    }

    public boolean updateCredentials(Credentials creds) {
        String sql ="UPDATE logins " +
                "SET role_id=(SELECT id FROM roles WHERE name=? AND (org_id=? OR org_id IS NULL)), " +
                "reset_password=?, reset_token=? " +
                "WHERE person_id=?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)){

            stmt.setString(1, creds.getRole());
            stmt.setInt(2, OrganizationContext.orgId());
            stmt.setBoolean(3, creds.isResetPassword());
            stmt.setString(4, creds.getResetToken());
            stmt.setInt(5, creds.getId());

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RuntimeException("Could not update role for Person(" + creds.getId() + ")", e);
        }
    }

    public boolean updatePassword(int personId, String hashedPassword) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement("UPDATE logins SET hashed_password=?, reset_password=false, reset_token=NULL WHERE person_id=?");
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
                creds.setId(rs.getInt("person_id"));
                creds.setEmail(rs.getString("email"));
                creds.setHashedPassword(rs.getString("hashed_password"));
                creds.setRole(rs.getString("role"));
                creds.setRoleId(rs.getInt("role_id"));
                boolean passwordResetRequired = rs.getBoolean("reset_password");
                creds.setResetPassword(passwordResetRequired);
                if(passwordResetRequired) {
                    creds.setPermissions(RESET_PASSWORD);
                }else {
                    creds.setPermissions(permDB.getPermissionsForRoleId(creds.getRoleId()));
                }
                results.add(creds);
            }

            return results;
        }
    }
}
