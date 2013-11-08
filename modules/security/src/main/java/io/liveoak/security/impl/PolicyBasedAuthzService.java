/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.security.impl;

import io.liveoak.container.DefaultRequestAttributes;
import io.liveoak.spi.container.DirectConnector;
import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.container.auth.SimpleLogger;
import io.liveoak.security.spi.AuthzDecision;
import io.liveoak.security.spi.AuthzPolicyEntry;
import io.liveoak.spi.RequestAttributes;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourcePath;
import io.liveoak.spi.state.ResourceState;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PolicyBasedAuthzService {

    private static final SimpleLogger log = new SimpleLogger(PolicyBasedAuthzService.class);

    private AtomicReference<List<AuthzPolicyEntry>> policies = new AtomicReference<>();
    private DirectConnector directConnector;

    public PolicyBasedAuthzService(DirectConnector directConnector) {
        this.directConnector = directConnector;
    }

    // TODO Once DirectConnector is fixed remove synchronized
    public synchronized boolean isAuthorized(RequestContext reqContext) {
        if (reqContext == null) {
            return false;
        }

        ResourcePath resPath = reqContext.resourcePath();
        AuthzDecision decision = AuthzDecision.IGNORE;

        List<AuthzPolicyEntry> policies = this.policies.get();
        if (policies == null) {
            return true;
        }

        if (policies != null) {
            for (AuthzPolicyEntry policyEntry : policies) {

                // Check if policy is mapped to actual resourcePath
                if (policyEntry.isResourceMapped(resPath)) {
                    String policyEndpoint = policyEntry.getPolicyResourceEndpoint();

                    if (log.isTraceEnabled()) {
                        log.trace("Going to trigger policyName " + policyEntry.getPolicyName() + " for request: " + reqContext);
                    }

                    // TODO: This should be triggered concurrently with usage of future objects
                    AuthzDecision result = invokePolicyEndpoint(reqContext, policyEndpoint);
                    decision = decision.mergeDecision(result);

                    if (log.isTraceEnabled()) {
                        log.trace("Result of authorization policy check: " + decision);
                    }

                    if (decision == AuthzDecision.REJECT) {
                        break;
                    }
                }
            }
        }

        return decision == AuthzDecision.ACCEPT;
    }

    protected AuthzDecision invokePolicyEndpoint(RequestContext reqContext, String policyEndpoint) {
        // Put current request as attribute of the authzRequest
        RequestAttributes attribs = new DefaultRequestAttributes();
        attribs.setAttribute(AuthzConstants.ATTR_REQUEST_CONTEXT, reqContext);
        RequestContext authzRequest = new RequestContext.Builder().requestAttributes(attribs).build();

        try {
            ResourceState resourceState = this.directConnector.read(authzRequest, policyEndpoint);
            Object result = resourceState.getProperty(AuthzConstants.ATTR_AUTHZ_POLICY_RESULT);
            return Enum.valueOf(AuthzDecision.class, (String) result);
        } catch (InterruptedException ie) {
            log.error("Interrupted", ie);
            Thread.currentThread().interrupt();
            return AuthzDecision.REJECT;
        } catch (Exception e) {
            log.error("Couldn't invoke policyEndpoint " + policyEndpoint + " due to exception", e);
            return AuthzDecision.REJECT;
        }
    }

    public List<AuthzPolicyEntry> getPolicies() {
        List<AuthzPolicyEntry> policies = this.policies.get();
        return policies != null ? Collections.unmodifiableList(policies) : null;
    }

    public void setPolicies(List<AuthzPolicyEntry> policies) {
        this.policies.set(policies);
    }

}
