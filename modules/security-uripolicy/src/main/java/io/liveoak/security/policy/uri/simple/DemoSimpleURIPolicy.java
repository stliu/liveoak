/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.policy.uri.simple;

import io.liveoak.security.policy.uri.RolesContainer;
import io.liveoak.spi.RequestType;

/**
 * Demo policy with pre-configured rules for testing purposes
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DemoSimpleURIPolicy extends SimpleURIPolicy {

    public void initialize() {
        // Everything is allowed, unless specially configured
        addRolePolicy("*", "*", "*", "*", ALLOW_ALL_ROLES_CONTAINER);

        // Collection protected1 is available for READ for role "users"
        addRolePolicy("authTest", "protected1", "*", RequestType.READ.name(),
                new RolesContainer().addAllowedRole("user"));

        // Collection protected1 is available for other actions than READ for role "admins" (READ specified by previous rule)
        addRolePolicy("authTest", "protected1", "*", "*",
                new RolesContainer().addAllowedRole("admin"));

        // Resource "12345" in collection "protected1" is available for "users" and "powerUsers" for all requestTypes (readMember+write)
        addRolePolicy("authTest", "protected1", "12345", "*",
                new RolesContainer().addAllowedRole("user").addAllowedRole("powerUser"));

        // Collection protected2 is available for CREATE for realm role "users"
        addRolePolicy("authTest", "protected2", "*", RequestType.CREATE.name(),
                new RolesContainer().addAllowedRole("user"));
    }
}
