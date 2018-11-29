package org.servantscode.permission.rest;

public class CreatePasswordRequest {
    private String email;
    private int personId;
    private String password;
    private String role;

    public CreatePasswordRequest() { }

    // ----- Accessors -----
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public int getPersonId() { return personId; }
    public void setPersonId(int personId) { this.personId = personId; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}
