/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */

package io.liveoak.security.integration;

import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.container.auth.SimpleLogger;
import io.liveoak.security.impl.PolicyBasedAuthzService;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.resource.async.Resource;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzCheckResource implements Resource {

    private static final SimpleLogger log = new SimpleLogger(AuthzCheckResource.class);

    private final String id;
    private final AuthzServiceRootResource parent;

    public AuthzCheckResource(String id, AuthzServiceRootResource parent) {
        this.id = id;
        this.parent = parent;
    }

    @Override
    public Resource parent() {
        return parent;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public void readProperties(RequestContext ctx, PropertySink sink) throws Exception {
        PolicyBasedAuthzService authzService = parent.getAuthzService();

        try {
            RequestContext reqCtxToAuthorize = ctx.requestAttributes() != null ? ctx.requestAttributes().getAttribute(AuthzConstants.ATTR_REQUEST_CONTEXT, RequestContext.class) : null;
            boolean result = authzService.isAuthorized(reqCtxToAuthorize);
            sink.accept(AuthzConstants.ATTR_AUTHZ_RESULT, result);
        } catch (Throwable t) {
            log.error("Failed to authorize request", t);
            sink.accept(AuthzConstants.ATTR_AUTHZ_RESULT, false);
        }

        sink.close();
    }
}
