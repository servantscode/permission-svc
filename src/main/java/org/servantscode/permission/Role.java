package org.servantscode.permission;

public class Role {

    private int id;
    private String name;
    private boolean requiresCheckin;

    private String[] permissions;

    public Role() {}

    public Role(int id, String name) {
        this.id = id;
        this.name = name;
    }

    // ----- Accessors -----
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public boolean isRequiresCheckin() { return requiresCheckin; }
    public void setRequiresCheckin(boolean requiresCheckin) { this.requiresCheckin = requiresCheckin; }

    public String[] getPermissions() { return permissions; }
    public void setPermissions(String[] permissions) { this.permissions = permissions; }
}
