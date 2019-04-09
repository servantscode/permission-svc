package org.servantscode.permission;

public class PasswordRequest {
    private String newPassword;
    private String oldPassword;
    private String passwordToken;

    // ----- Accessors -----
    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }

    public String getOldPassword() { return oldPassword; }
    public void setOldPassword(String oldPassword) { this.oldPassword = oldPassword; }

    public String getPasswordToken() { return passwordToken; }
    public void setPasswordToken(String passwordToken) { this.passwordToken = passwordToken; }
}
