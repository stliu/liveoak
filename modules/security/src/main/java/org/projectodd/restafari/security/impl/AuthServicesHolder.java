package org.projectodd.restafari.security.impl;

import java.util.HashSet;
import java.util.Set;

import org.projectodd.restafari.security.spi.ApplicationIdResolver;
import org.projectodd.restafari.security.spi.ApplicationMetadata;
import org.projectodd.restafari.security.spi.AuthPersister;
import org.projectodd.restafari.security.spi.AuthorizationPolicy;
import org.projectodd.restafari.security.spi.AuthorizationPolicyEntry;
import org.projectodd.restafari.security.spi.AuthorizationService;
import org.projectodd.restafari.security.spi.TokenManager;
import org.projectodd.restafari.spi.ResourcePath;


/**
 * Container for various services related to authentication/authorization
 * TODO: Probably remove later...
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthServicesHolder {

    // TODO: replace with real logging
    private final SimpleLogger log = new SimpleLogger(AuthServicesHolder.class);

    private static AuthServicesHolder INSTANCE = new AuthServicesHolder();

    private final AuthorizationService authorizationService;
    private final AuthPersister authPersister;
    private final TokenManager tokenManager;

    // TODO: Probably remove
    private ApplicationIdResolver applicationIdResolver;

    // TODO: Also remove... loading of policies should be done in mbaas way
    private final Set<ClassLoader> policyLoaders = new HashSet<>();

    private AuthServicesHolder() {
        this.authorizationService = new PolicyBasedAuthorizationService();
        this.authPersister = new InMemoryAuthPersister();
        this.tokenManager = new DefaultTokenManager();
        this.applicationIdResolver = (resourceReq) -> AuthConstants.DEFAULT_APP_ID;

        // Register default loaders
        policyLoaders.add(AuthServicesHolder.class.getClassLoader());
        policyLoaders.add(Thread.currentThread().getContextClassLoader());

        // Register default metadata and URIPolicy for default application
        registerDefaultAppConfig();
    };

    public static AuthServicesHolder getInstance() {
        return INSTANCE;
    }

    public AuthorizationService getAuthorizationService() {
        return authorizationService;
    }

    public AuthPersister getAuthPersister() {
        return authPersister;
    }

    public TokenManager getTokenManager() {
        return tokenManager;
    }

    public ApplicationIdResolver getApplicationIdResolver() {
        return applicationIdResolver;
    }

    public void setApplicationIdResolver(ApplicationIdResolver applicationIdResolver) {
        this.applicationIdResolver = applicationIdResolver;
    }

    private void registerDefaultAppConfig() {
        ApplicationMetadata appMetadata = new ApplicationMetadata(AuthConstants.DEFAULT_APP_ID, AuthConstants.DEFAULT_REALM_NAME,
                AuthConstants.DEFAULT_APPLICATION_NAME, AuthConstants.DEFAULT_PUBLIC_KEY);
        authPersister.registerApplicationMetadata(appMetadata);
    }

    public void registerClassloader(ClassLoader policyClassloader) {
        this.policyLoaders.add(policyClassloader);
    }

    public void registerDefaultPolicies() {
        // Register simple demo policy as default one
        AuthorizationPolicy simplePolicy = loadPolicy("org.projectodd.restafari.security.policy.uri.simple.DemoSimpleURIPolicy");
        simplePolicy.init();
        AuthorizationPolicyEntry simplePolicyEntry = new AuthorizationPolicyEntry("someId", simplePolicy);
        simplePolicyEntry.addIncludedResourcePrefix(new ResourcePath());
        // Don't test URI under /droolsTest/foo/bar/* with simple policy
        simplePolicyEntry.addExcludedResourcePrefix(new ResourcePath("/droolsTest/foo/bar"));

        // Register drools based URIPolicy for context /droolsTest
        AuthorizationPolicy droolsPolicy = loadPolicy("org.projectodd.restafari.security.policy.uri.complex.DemoURIPolicy");
        droolsPolicy.init();
        AuthorizationPolicyEntry droolsPolicyEntry = new AuthorizationPolicyEntry("someId2", droolsPolicy);
        droolsPolicyEntry.addIncludedResourcePrefix(new ResourcePath("droolsTest"));

        authPersister.registerPolicy(AuthConstants.DEFAULT_APP_ID, simplePolicyEntry);
        authPersister.registerPolicy(AuthConstants.DEFAULT_APP_ID, droolsPolicyEntry);
    }

    private AuthorizationPolicy loadPolicy(String policyClassname) {
        Class<?> clazz = null;
        for (ClassLoader cl : this.policyLoaders) {
            clazz = loadPolicyClass(policyClassname, cl);
            if (clazz != null) {
                break;
            }
        }

        if (clazz == null) {
            log.error("Unable to load policy class " + policyClassname);
            throw new IllegalStateException("Unable to load policy class: " + policyClassname + " with classloaders: " + policyLoaders);
        }

        try {
            return (AuthorizationPolicy) clazz.newInstance();
        } catch (Exception e) {
            log.error("Unable to instantiate instance of policy class " + clazz);
            throw new IllegalStateException("Unable to instantiate instance of policy class " + clazz);
        }
    }

    private static Class<?> loadPolicyClass(String policyClassname, ClassLoader cl) {
         try {
            return cl.loadClass(policyClassname);
         } catch (ClassNotFoundException cnfe) {
            return null;
         }
    }
}
