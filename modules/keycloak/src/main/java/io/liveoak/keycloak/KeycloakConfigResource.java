package io.liveoak.keycloak;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.ConfigResource;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.resource.async.Resource;
import io.liveoak.spi.resource.async.Responder;
import io.liveoak.spi.state.ResourceState;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ApplicationRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.ApplicationManager;
import org.keycloak.services.managers.RealmManager;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class KeycloakConfigResource implements ConfigResource {

    public static final String REALM = "realm";
    public static final String APP_CONFIG = "app-config";

    private KeycloakRootResource keycloak;

    private String appConfig;

    public KeycloakConfigResource(KeycloakRootResource keycloak) {
        this.keycloak = keycloak;
    }

    @Override
    public Resource parent() {
        return keycloak;
    }

    @Override
    public void readProperties(RequestContext ctx, PropertySink sink) throws Exception {
        sink.accept(REALM, keycloak.getRealm());
        if (appConfig != null) {
            sink.accept(APP_CONFIG, appConfig);
        }
        sink.close();
    }

    @Override
    public void updateProperties(RequestContext ctx, ResourceState state, Responder responder) throws Exception {
        try {
            String realm = (String) state.getProperty(REALM);
            if (realm != null && !realm.equals(keycloak.getRealm())) {
                keycloak.setRealm(realm);
            }

            String appConfig = (String) state.getProperty(APP_CONFIG);
            if (appConfig != null && !appConfig.equals(this.appConfig)) {
                File file = new File(appConfig);
                if (file.isFile()) {
                    ApplicationRepresentation appRep = loadJson(file, ApplicationRepresentation.class);
                    keycloak.setApp(appRep);
                } else {
                    // TODO LOG
                    System.out.println(appConfig + " not found");
                }
                this.appConfig = appConfig;
            }

            responder.resourceUpdated(this);
        } catch (Throwable t) {
            t.printStackTrace();
            responder.internalError(t);
        }
    }

    private static <T> T loadJson(File file, Class<T> type) {
        try {
            JsonFactory factory = new JsonFactory();
            factory.enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES);
            factory.enable(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
            ObjectMapper mapper = new ObjectMapper(factory);
            return mapper.readValue(file, type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }

}
