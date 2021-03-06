/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.testtools;

import io.liveoak.container.LiveOakFactory;
import io.liveoak.container.LiveOakSystem;
import io.liveoak.common.codec.DefaultResourceState;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.state.ResourceState;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.After;
import org.junit.Before;


/**
 * @author Bob McWhirter
 */
public abstract class AbstractHTTPResourceTestCase extends AbstractTestCase {

    private LiveOakSystem system;
    protected CloseableHttpClient httpClient;

    public abstract RootResource createRootResource();

    public ResourceState createConfig() {
        return new DefaultResourceState();
    }

    @Before
    public void setUpClient() throws Exception {
        RequestConfig cconfig = RequestConfig.custom().setSocketTimeout(500000).build();
        this.httpClient = HttpClients.custom().setDefaultRequestConfig(cconfig).build();
    }

    @After
    public void tearDownClient() throws Exception {
        this.httpClient.close();
    }

    @Before
    public void setUpServer() throws Exception {
        this.system = LiveOakFactory.create();
        this.system.directDeployer().deploy(createRootResource(), createConfig());
    }

    @After
    public void tearDownServer() throws Exception {
        this.system.stop();
    }
}
