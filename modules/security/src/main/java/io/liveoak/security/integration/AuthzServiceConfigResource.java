package io.liveoak.security.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.liveoak.security.spi.AuthzServiceConfig;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.ConfigResource;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.resource.async.Resource;
import io.liveoak.spi.resource.async.Responder;
import io.liveoak.spi.state.ResourceState;

import java.io.File;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AuthzServiceConfigResource implements ConfigResource {

    private AuthzServiceRootResource authzService;

    private String configFile;

    private AuthzServiceConfig config;

    public AuthzServiceConfigResource(AuthzServiceRootResource authzService) {
        this.authzService = authzService;
    }

    @Override
    public Resource parent() {
        return authzService;
    }

    @Override
    public void readProperties(RequestContext ctx, PropertySink sink) throws Exception {
        if (configFile != null) {
            sink.accept("authz-config", configFile);
        }
        sink.close();
    }

    @Override
    public void updateProperties(RequestContext ctx, ResourceState state, Responder responder) throws Exception {
        try {
            configFile = (String) state.getProperty("authz-config");
            if (configFile == null) {
                this.config = null;
            } else {
                File file = new File(configFile);
                if (file.isFile()) {
                    ObjectMapper om = new ObjectMapper();
                    config = om.readValue(file, AuthzServiceConfig.class);
                } else {
                    // TODO LOG
                    System.out.println(config + " not found");
                    this.config = null;
                }
            }

            authzService.setConfig(config);

            responder.resourceUpdated(this);
        } catch (Throwable t) {
            t.printStackTrace();
            responder.internalError(t);
        }
    }

}
