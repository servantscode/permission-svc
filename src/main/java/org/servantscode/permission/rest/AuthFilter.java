package org.servantscode.permission.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.servantscode.commons.StringUtils;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.security.Principal;
import java.util.List;

import static org.servantscode.commons.StringUtils.isEmpty;

@Provider
public class AuthFilter implements ContainerRequestFilter {
    private static final Logger LOGGER = LogManager.getLogger(AuthFilter.class);

    private static final Algorithm algorithm = Algorithm.HMAC256("secret");
    private static final JWTVerifier VERIFIER = JWT.require(algorithm)
            .acceptLeeway(1)   //1 sec leeway for date checks to account for clock slop
            .withIssuer("Servant's Code")
            .build();

    @Override
    public void filter(ContainerRequestContext requestContext) {
        // No token required for login.
        // TODO: Is there a better way to do this with routing?
        LOGGER.debug("Authentication in process for: " + requestContext.getUriInfo().getPath());
        if(requestContext.getUriInfo().getPath().equalsIgnoreCase("login") &&
                requestContext.getMethod().equalsIgnoreCase("POST"))
            return;

        List<String> authHeaders = requestContext.getHeaders().get("Authorization");
        if(authHeaders == null || authHeaders.size() != 1)
            throw new NotAuthorizedException("Not Authorized");

        String authHeader = authHeaders.get(0);
        if(isEmpty(authHeader))
            throw new NotAuthorizedException("Not Authorized");

        String[] headerBits = authHeader.split("\\s");
        if(headerBits.length != 2 || !headerBits[0].equalsIgnoreCase("Bearer"))
            throw new NotAuthorizedException("Not Authorized");

        try {
            DecodedJWT jwt = VERIFIER.verify(headerBits[1]);
            requestContext.setSecurityContext(createContext(requestContext.getUriInfo(), jwt));
        } catch (JWTVerificationException e) {
            LOGGER.warn("Invalid jwt token presented.", e);
            throw new NotAuthorizedException("Not Authorized");
        }
    }

    // ----- Private -----
    private SecurityContext createContext(final UriInfo uriInfo, final DecodedJWT jwt) {
        return new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return jwt::getSubject;
            }

            @Override
            public boolean isUserInRole(String role) {
                Claim claim = jwt.getClaim("role");
                if(claim == null)
                    return false;

                return claim.asString().equalsIgnoreCase(role);
            }

            @Override
            public boolean isSecure() {
                return uriInfo.getAbsolutePath().toString().startsWith("https");
            }

            @Override
            public String getAuthenticationScheme() {
                return "JWT";
            }
        };
    }
}