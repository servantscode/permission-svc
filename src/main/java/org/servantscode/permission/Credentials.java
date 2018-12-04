package org.servantscode.permission;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class Credentials {
    private String username;
    private int personId;
    private String email;
    private String role;

    @JsonIgnore //Just in case
    private String hashedPassword;

    public PublicCredentials toPublicCredentials() {
        return new PublicCredentials(email, role);
    }
    // ----- Accessors -----
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public int getPersonId() { return personId; }
    public void setPersonId(int personId) { this.personId = personId; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public String getHashedPassword() { return hashedPassword; }
    public void setHashedPassword(String hashedPassword) { this.hashedPassword = hashedPassword; }
}
