package org.servantscode.permission;

public class PublicCredentials {
    private String name;
    private int id;
    private String email;
    private String role;
    private boolean resetPassword;

    public PublicCredentials(String name, int id, String email, String role, boolean resetPassword) {
        this.name = name;
        this.id = id;
        this.email = email;
        this.role = role;
        this.resetPassword = resetPassword;
    }

    // ----- Accessors -----
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public boolean isResetPassword() { return resetPassword; }
    public void setResetPassword(boolean resetPassword) { this.resetPassword = resetPassword; }
}
