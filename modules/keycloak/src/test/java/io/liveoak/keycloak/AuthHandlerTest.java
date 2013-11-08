/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.keycloak;

import io.liveoak.container.DefaultContainer;
import io.liveoak.container.LiveOakFactory;
import io.liveoak.container.LiveOakSystem;
import io.liveoak.container.codec.DefaultResourceState;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.SecurityContext;
import io.liveoak.spi.state.ResourceState;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.representations.SkeletonKeyToken;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

public class AuthHandlerTest {

    private static DefaultContainer container;
    private static CloseableHttpClient httpClient;
    private static LiveOakSystem system;
    private static TokenUtil tokenUtil;
    private MockRootResource mock;
    private static KeycloakRootResource keycloak;

    @BeforeClass
    public static void before() throws Exception {
        container = new DefaultContainer();

        ResourceState config = new DefaultResourceState();
        config.putProperty(KeycloakConfigResource.REALM, "default");

        keycloak = new KeycloakRootResource("auth");
        container.registerResource(keycloak);

        tokenUtil = new TokenUtil(keycloak);

        system = LiveOakFactory.create();

        httpClient = HttpClientBuilder.create().build();
    }

    @AfterClass
    public static void after() throws Exception {
        try {
            httpClient.close();
        } finally {
            system.stop();
            System.err.flush();
        }
    }

    @Before
    public void beforeTest() throws Exception {
        mock = new MockRootResource("auth-test");
        container.registerResource(mock);
    }


    @Test(timeout = 10000)
    public void testNoAuth() throws Exception {
        HttpRequestBase httpMethod = createHttpMethod("GET", "http://localhost:8080/auth-test");
        sendRequestAndCheckStatus(httpMethod, HttpStatus.SC_OK);

        RequestContext context = mock.pollRequest(2, TimeUnit.SECONDS);
        Assert.assertFalse(context.securityContext().isAuthenticated());
    }

    @Test(timeout = 10000)
    public void testAuth() throws Exception {
        SkeletonKeyToken token = tokenUtil.createToken();

        HttpRequestBase httpMethod = createHttpMethod("GET", "http://localhost:8080/auth-test");
        httpMethod.addHeader(new BasicHeader("Authorization", "bearer " + tokenUtil.toString(token)));
        sendRequestAndCheckStatus(httpMethod, HttpStatus.SC_OK);

        SecurityContext context = mock.pollRequest(10, TimeUnit.SECONDS).securityContext();
        Assert.assertTrue(context.isAuthenticated());
        Assert.assertEquals("default", context.getRealm());
        Assert.assertEquals("user-id", context.getSubject());
        Assert.assertEquals(3, context.getRoles().size());
        Assert.assertEquals(token.getIssuedAt(), context.lastVerified());
    }

    @Test(timeout = 10000)
    public void testAuthExpired() throws Exception {
        SkeletonKeyToken token = tokenUtil.createToken();
        token.expiration((System.currentTimeMillis() / 1000) - 10);

        HttpRequestBase httpMethod = createHttpMethod("GET", "http://localhost:8080/auth-test");
        httpMethod.addHeader(new BasicHeader("Authorization", "bearer " + tokenUtil.toString(token)));
        sendRequestAndCheckStatus(httpMethod, HttpStatus.SC_UNAUTHORIZED);
    }

    @Test(timeout = 10000)
    public void testInvalidAuth() throws Exception {
        HttpRequestBase httpMethod = createHttpMethod("GET", "http://localhost:8080/auth-test");
        httpMethod.addHeader(new BasicHeader("Authorization", "bearer invalid-token"));
        sendRequestAndCheckStatus(httpMethod, HttpStatus.SC_UNAUTHORIZED);
    }

    private HttpRequestBase createHttpMethod(String method, String uri) {
        HttpRequestBase httpMethod;
        switch (method) {
            case "GET":
                httpMethod = new HttpGet(uri);
                break;
            case "POST":
                httpMethod = new HttpPost(uri);
                break;
            case "PUT":
                httpMethod = new HttpPut(uri);
                break;
            case "DELETE":
                httpMethod = new HttpDelete(uri);
                break;
            default:
                throw new IllegalArgumentException("Unsupported method: " + method);
        }
        httpMethod.addHeader(new BasicHeader("Accept", "application/json"));
        httpMethod.addHeader(new BasicHeader("Content-Type", "application/json"));
        return httpMethod;
    }

    private void sendRequestAndCheckStatus(HttpRequestBase req, int expectedStatusCode) throws IOException {
        CloseableHttpResponse resp = httpClient.execute(req);
        assertEquals(expectedStatusCode, resp.getStatusLine().getStatusCode());
        resp.close();
    }
}
