package org.servantscode.permission;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class Credentials {
    private String username;
    private int userId;
    private String email;
    private String systemRole;

    @JsonIgnore //Just in case
    private String hashedPassword;

    // ----- Accessors -----
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getSystemRole() { return systemRole; }
    public void setSystemRole(String systemRole) { this.systemRole = systemRole; }

    public String getHashedPassword() { return hashedPassword; }
    public void setHashedPassword(String hashedPassword) { this.hashedPassword = hashedPassword; }
}
