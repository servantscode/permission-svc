package org.servantscode.permission;

import org.glassfish.jersey.client.ClientConfig;

import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static java.util.Arrays.asList;

public class EmailNotificationClient {

    final private Client client;
    final private WebTarget webTarget;
    final private String token;

    private static final String APPLICATION_URL = "http://localhost:4200";

    private static final String SERVICE_URL = "http://email-svc:8080/rest/email";

    public EmailNotificationClient(String token) {
        client = ClientBuilder.newClient(new ClientConfig().register(this.getClass()));
        webTarget = client.target(SERVICE_URL);
        this.token = token;
    }

    public void sendPasswordResetEmail(String to, String resetToken) {
        sendEmail("greg@servantscode.org", to, "Password reset requested",
                "You password reset fairy is here. Click the link below to reset your password: <br/>" +
                        APPLICATION_URL + "/account/reset/" + resetToken);
    }

    public void sendEmail(String from, String to, String subject, String message ) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("from", from);
        payload.put("to", asList(to));
        payload.put("subject", subject);
        payload.put("message", message);
        post(payload);
    }

    public Response post(Map<String, Object> data) {
        translateDates(data);
        return buildInvocation()
                .post(Entity.entity(data, MediaType.APPLICATION_JSON));
    }

    // ----- Private -----

    private void translateDates(Map<String, Object> data) {
        data.entrySet().forEach( (entry) -> {
            Object obj = entry.getValue();
            if(obj instanceof ZonedDateTime) {
                entry.setValue(((ZonedDateTime)obj).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
            } else if(obj instanceof List) {
                List list = (List)obj;
                if(!list.isEmpty() && list.get(0) instanceof Map)
                    list.forEach((item) -> translateDates((Map<String, Object>)item));
            } else if(obj instanceof Map) {
                translateDates((Map<String, Object>)obj);
            }
        });
    }

    private Invocation.Builder buildInvocation(Map<String, Object>... optionalParams) {
        WebTarget target = webTarget;

        if(optionalParams.length > 0) {
            Map<String, Object> params = optionalParams[0];
            for(Map.Entry<String, Object> entry: params.entrySet())
                target = target.property(entry.getKey(), entry.getValue());
        }

        return target
                .request(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + token);
    }
}
