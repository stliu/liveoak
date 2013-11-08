package io.liveoak.security.integration;

import io.liveoak.container.DefaultContainer;
import io.liveoak.container.auth.AuthzConstants;
import io.liveoak.container.auth.SimpleLogger;
import io.liveoak.security.impl.PolicyBasedAuthzService;
import io.liveoak.security.spi.AuthzPolicyEntry;
import io.liveoak.security.spi.AuthzServiceConfig;
import io.liveoak.spi.InitializationException;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.ResourceContext;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.resource.async.Resource;
import io.liveoak.spi.resource.async.ResourceSink;
import io.liveoak.spi.resource.async.Responder;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Root resource to be registered in DefaultContainer
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzServiceRootResource implements RootResource {

    private static final SimpleLogger log = new SimpleLogger(AuthzServiceRootResource.class);

    private String id;
    private PolicyBasedAuthzService authzService;
    private AuthzServiceConfigResource configResource = new AuthzServiceConfigResource(this);

    private final Map<String, Resource> childResources = new HashMap<>();
    private AuthzServiceConfig config;

    public AuthzServiceRootResource(String id) {
        this.id = id;
    }

    @Override
    public void initialize(ResourceContext context) throws InitializationException {
        authzService = new PolicyBasedAuthzService(context.directConnector());
        registerChildrenResources();
        authzService.setPolicies(config != null ? config.getPolicies() : null);
    }

    public PolicyBasedAuthzService getAuthzService() {
        return authzService;
    }

    private void registerChildrenResources() {
        this.childResources.put(AuthzConstants.AUTHZ_CHECK_RESOURCE_ID, new AuthzCheckResource(AuthzConstants.AUTHZ_CHECK_RESOURCE_ID, this));
    }

    @Override
    public void destroy() {
        // Nothing here for now
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public void readMember(RequestContext ctx, String id, Responder responder) {
        try {
            if (!this.childResources.containsKey(id)) {
                responder.noSuchResource(id);
                return;
            }

            responder.resourceRead(this.childResources.get(id));

        } catch (Throwable t) {
            responder.internalError(t.getMessage());
        }
    }

    @Override
    public void readMembers(RequestContext ctx, ResourceSink sink) {
        this.childResources.values().forEach((e) -> {
            sink.accept(e);
        });

        sink.close();
    }

    @Override
    public void readProperties(RequestContext ctx, PropertySink sink) throws Exception {
        // TODO: should be improved and probably handled with child resource
        Collection<AuthzPolicyEntry> policies = this.authzService.getPolicies();
        if (policies != null) {
            sink.accept("policies", policies.toString());
        }
        sink.close();
    }

    @Override
    public Resource configuration() {
        return configResource;
    }

    public void setConfig(AuthzServiceConfig config) {
        this.config = config;
        if (authzService != null) {
            authzService.setPolicies(config != null ? config.getPolicies() : null);
        }
    }

    public AuthzServiceConfig getConfig() {
        return config;
    }
}
