/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.testtools;

import io.liveoak.container.DefaultContainer;
import io.liveoak.container.LiveOakFactory;
import io.liveoak.container.LiveOakSystem;
import io.liveoak.spi.Container;
import io.liveoak.spi.container.DirectConnector;
import io.liveoak.container.codec.DefaultResourceState;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.state.ResourceState;
import org.junit.After;
import org.junit.Before;
import org.vertx.java.core.Vertx;


/**
 * @author Bob McWhirter
 */
public abstract class AbstractResourceTestCase extends AbstractTestCase {

    protected LiveOakSystem system;

    protected DirectConnector connector;
    protected RootResource resource;
    protected Vertx vertx;


    public abstract RootResource createRootResource();

    public ResourceState createConfig() {
        return new DefaultResourceState();
    }

    @Before
    public void setUpSystem() throws Exception {
        this.system = LiveOakFactory.create();
        this.resource = createRootResource();
        this.system.directDeployer().deploy(this.resource, createConfig());
        this.connector = this.system.directConnector();
        this.vertx = this.system.vertx();
    }

    @After
    public void tearDownSystem() throws Exception {
        this.system.stop();
    }

}
