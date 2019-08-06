package org.servantscode.permission.db;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.db.AbstractDBUpgrade;

import java.sql.SQLException;

public class DBUpgrade extends AbstractDBUpgrade {
    private static final Logger LOG = LogManager.getLogger(DBUpgrade.class);

    @Override
    public void doUpgrade() throws SQLException {
        LOG.info("Verifying database structures.");

        if(!tableExists("organizations")) {
            LOG.info("-- Creating organizations table");
            runSql("CREATE TABLE organizations (id SERIAL PRIMARY KEY, " +
                                               "name TEXT, " +
                                               "host_name TEXT, " +
                                               "photo_guid TEXT)");
            runSql("INSERT INTO organizations (name, host_name) VALUES ('Servant''s Code Default', 'localhost')");
        }

        if(!tableExists("roles")) {
            LOG.info("-- Creating roles table");
            runSql("CREATE TABLE roles (id SERIAL PRIMARY KEY, " +
                                       "name TEXT, " +
                                       "org_id INTEGER references organizations(id) ON DELETE CASCADE)");
            runSql("INSERT INTO roles(name) values ('system')");
        }

        if(!tableExists("permissions")) {
            LOG.info("-- Creating permissions table");
            runSql("CREATE TABLE permissions (role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE, " +
                                             "permission TEXT)");
            runSql("INSERT INTO permissions(role_id, permission) values (1, '*')");
        }

        if(!tableExists("logins")) {
            LOG.info("-- Creating logins table");
            runSql("CREATE TABLE logins (person_id INTEGER PRIMARY KEY REFERENCES people(id) ON DELETE CASCADE, " +
                                        "hashed_password TEXT, " +
                                        "role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE, " +
                                        "reset_password BOOLEAN DEFAULT false, " +
                                        "reset_token TEXT)");
        }

        if(!tableExists("sessions")) {
            LOG.info("-- Creating sessions table");
            runSql("CREATE TABLE sessions (person_id INTEGER REFERENCES people(id) ON DELETE CASCADE, " +
                                          "org_id INTEGER REFERENCES organizations(id), " +
                                          "token TEXT, " +
                                          "expiration TIMESTAMP WITH TIME ZONE, " +
                                          "ip TEXT)");
        }
    }
}
