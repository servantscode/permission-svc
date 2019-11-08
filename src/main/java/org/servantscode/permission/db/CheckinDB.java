package org.servantscode.permission.db;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.db.DBAccess;
import org.servantscode.commons.db.EasyDB;
import org.servantscode.commons.search.InsertBuilder;
import org.servantscode.commons.search.QueryBuilder;
import org.servantscode.commons.search.SearchParser;
import org.servantscode.commons.search.UpdateBuilder;
import org.servantscode.commons.security.OrganizationContext;
import org.servantscode.permission.Checkin;
import org.servantscode.permission.Checkin;

import java.sql.*;
import java.util.LinkedList;
import java.util.List;

import static org.servantscode.commons.security.SCSecurityContext.SYSTEM;

public class CheckinDB extends EasyDB<Checkin> {
    private static Logger LOG = LogManager.getLogger(CheckinDB.class);


    public CheckinDB() {
        super(Checkin.class, "personName");
    }

    private QueryBuilder select(QueryBuilder selection) {
        return selection.from("checkins c")
                .leftJoin("people vol ON vol.id=c.person_id")
                .leftJoin("people admin ON admin.id=c.checkedin_by");
    }

    private QueryBuilder fields() {
        return select("c.*", "vol.name AS person_name", "admin.name AS checkedin_by_name");
    }

    public int getCount(String search) {
        return getCount(select(count()).search(searchParser.parse(search)).inOrg("c.org_id"));
    }

    public List<Checkin> getCheckins(String search, String sortField, int start, int count) {
        return get(select(fields()).search(searchParser.parse(search)).inOrg("c.org_id")
                .page(sortField, start, count));
    }

    public Checkin getCheckin(long id) {
        return getOne(select(fields()).with("c.id", id).inOrg("c.org_id"));
    }

    public boolean isCheckedIn(int personId) {
        return existsAny(select(count()).with("person_id", personId).where("expiration > now()").inOrg("c.org_id"));
    }

    public Checkin create(Checkin checkin) {
        InsertBuilder cmd = insertInto("checkins")
                .value("person_id", checkin.getPersonId())
                .value("expiration", checkin.getExpiration())
                .value("checkedin_at", checkin.getCheckedinAt())
                .value("checkedin_by", checkin.getCheckedinById())
                .value("org_id", OrganizationContext.orgId());

        checkin.setId(createAndReturnLongKey(cmd));
        return getCheckin(checkin.getId());
    }

    public Checkin update(Checkin checkin) {
        UpdateBuilder cmd = update("checkins")
                .value("expiration", checkin.getExpiration())
                .value("checkedin_at", checkin.getCheckedinAt())
                .value("checkedin_by", checkin.getCheckedinById())
                .with("id", checkin.getId()).inOrg();

        if(!update(cmd))
            throw new RuntimeException("Could not update checkin for: " + checkin.getPersonId());

        return checkin;
    }

    public boolean deleteCheckin(long checkinId) {
        return delete(deleteFrom("checkins").withId(checkinId).inOrg());
    }

    // ----- Private -----
    @Override
    protected Checkin processRow(ResultSet rs) throws SQLException {
        Checkin c = new Checkin();
        c.setPersonId(rs.getInt("person_id"));
        c.setPersonName(rs.getString("person_name"));
        c.setExpiration(convert(rs.getTimestamp("expiration")));
        c.setCheckedinAt(convert(rs.getTimestamp("checkedin_at")));
        c.setCheckedinById(rs.getInt("checkedin_by"));
        c.setCheckedinByName(rs.getString("checkedin_by_name"));
        return c;
    }
}
