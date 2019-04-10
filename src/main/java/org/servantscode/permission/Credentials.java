package org.servantscode.permission;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class Credentials {
    private int id;
    private String name;
    private String email;
    private String role;
    private boolean resetPassword;

    @JsonIgnore
    private String resetToken;

    @JsonIgnore
    private int roleId;

    @JsonIgnore //Don't let this out!
    private String hashedPassword;

    @JsonIgnore
    private String[] permissions;

    public PublicCredentials toPublicCredentials() { return new PublicCredentials(name, id, email, role, resetPassword); }

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

    public String getResetToken() { return resetToken; }
    public void setResetToken(String resetToken) { this.resetToken = resetToken; }

    public int getRoleId() { return roleId; }
    public void setRoleId(int roleId) { this.roleId = roleId; }

    public String getHashedPassword() { return hashedPassword; }
    public void setHashedPassword(String hashedPassword) { this.hashedPassword = hashedPassword; }

    public String[] getPermissions() { return permissions; }
    public void setPermissions(String[] permissions) { this.permissions = permissions; }
}
