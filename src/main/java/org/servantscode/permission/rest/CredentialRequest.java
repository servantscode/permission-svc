package org.servantscode.permission.rest;

public class CredentialRequest {
    private int id;
    private String email;
    private String password;
    private String role;
    private boolean resetPassword;

    public CredentialRequest() { }

    // ----- Accessors -----
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public boolean isResetPassword() { return resetPassword; }
    public void setResetPassword(boolean resetPassword) { this.resetPassword = resetPassword; }
}
