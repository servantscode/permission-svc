package org.servantscode.permission;

import java.time.ZonedDateTime;

public class Checkin {
    private long id;
    private int personId;
    private String personName;
    private ZonedDateTime expiration;
    private ZonedDateTime checkedinAt;
    private int checkedinById;
    private String checkedinByName;

    // ----- Accessors -----
    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public int getPersonId() { return personId; }
    public void setPersonId(int personId) { this.personId = personId; }

    public String getPersonName() { return personName; }
    public void setPersonName(String personName) { this.personName = personName; }

    public ZonedDateTime getExpiration() { return expiration; }
    public void setExpiration(ZonedDateTime expiration) { this.expiration = expiration; }

    public ZonedDateTime getCheckedinAt() { return checkedinAt; }
    public void setCheckedinAt(ZonedDateTime checkedinAt) { this.checkedinAt = checkedinAt; }

    public int getCheckedinById() { return checkedinById; }
    public void setCheckedinById(int checkedinById) { this.checkedinById = checkedinById; }

    public String getCheckedinByName() { return checkedinByName; }
    public void setCheckedinByName(String checkedinByName) { this.checkedinByName = checkedinByName; }
}
