package org.servantscode.permission;

public class PublicCredentials {
    private String email;
    private String role;

    public PublicCredentials(String email, String role) {
        this.email = email;
        this.role = role;
    }

    // ----- Accessors -----
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}
