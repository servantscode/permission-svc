package org.servantscode.permission.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

@Path("/permission")
public class PermissionSvc {
    private static Logger LOG = LogManager.getLogger(PermissionSvc.class);

    @GET @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> getAvailablePermissions() {
        InputStream fileStream = this.getClass().getClassLoader().getResourceAsStream("permissions.txt");
        BufferedReader reader = new BufferedReader(new InputStreamReader(fileStream));
        try {
            return mapPermissions(reader);
        } catch (IOException e) {
            LOG.error("Could not process permission list.", e);
            throw new WebApplicationException();
        }
    }

    // ----- Private -----
    private Map<String, Object> mapPermissions(BufferedReader input) throws IOException {
        Map<String, Object> permissionList = new HashMap<>();
        String permission;
        while((permission = input.readLine()) != null)
            addPermissionString(permissionList, permission.split("\\."), 0);
        return permissionList;
    }

    private void addPermissionString(Map<String, Object> list, String[] permission, int index) {
        if(index == permission.length -1) {
            list.put(permission[index], false);
        } else {
            Map<String, Object> nextList = (Map<String, Object>) list.get(permission[index]);
            if(nextList == null) {
                nextList = new HashMap<>();
                list.put(permission[index], nextList);
            }
            addPermissionString(nextList, permission, index+1);
        }
    }
}
