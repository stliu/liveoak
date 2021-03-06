/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.git;

import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.RootResource;
import io.liveoak.spi.state.ResourceState;
import io.liveoak.testtools.AbstractResourceTestCase;
import org.junit.Test;

import java.io.File;

import static org.fest.assertions.Assertions.assertThat;

/**
 * @author <a href="http://community.jboss.org/people/kenfinni">Ken Finnigan</a>
 */
public class GitResourceTest extends AbstractResourceTestCase {

    @Override
    public RootResource createRootResource() {
        return new GitRepoResource("git");
    }

    @Override
    public ResourceState createConfig() {
        File repoDir = new File(this.projectRoot, "/target/repo");
        if (!repoDir.exists()) {
            repoDir.mkdirs();
        }

        ResourceState config = super.createConfig();
        config.putProperty("repoPath", repoDir.getAbsolutePath());
        config.putProperty("createIfMissing", Boolean.TRUE );
        return config;
    }

    @Test
    public void testRoot() throws Exception {
        ResourceState result = client.read(new RequestContext.Builder().build(), "/git");

        assertThat(result).isNotNull();
    }
}
