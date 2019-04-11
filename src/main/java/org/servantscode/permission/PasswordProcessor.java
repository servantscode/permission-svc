package org.servantscode.permission;

import org.springframework.security.crypto.bcrypt.BCrypt;

import static org.servantscode.commons.StringUtils.isEmpty;

public class PasswordProcessor {
    public static String encryptPassword(String password) {
        if(isEmpty(password))
            return "";
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyPassword(String oldPassword, String hashedPassword) {
        return BCrypt.checkpw(oldPassword, hashedPassword);
    }
}
