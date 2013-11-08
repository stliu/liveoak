/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.container.auth;

import io.liveoak.container.DefaultRequestAttributes;
import io.liveoak.container.DefaultResourceErrorResponse;
import io.liveoak.spi.container.DirectConnector;
import io.liveoak.spi.ResourceErrorResponse;
import io.liveoak.spi.ResourceRequest;
import io.liveoak.spi.ResourceResponse;
import io.liveoak.spi.RequestAttributes;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.async.PropertySink;
import io.liveoak.spi.state.ResourceState;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Handler for checking authorization of current request. It's independent of protocol.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthzHandler extends SimpleChannelInboundHandler<ResourceRequest> {

    // TODO: replace with real logging
    private static final SimpleLogger log = new SimpleLogger(AuthzHandler.class);

    private final DirectConnector connector;

    public AuthzHandler(DirectConnector connector) {
        this.connector = connector;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ResourceRequest req) throws Exception {
        try {
            // Put current request as attribute of the request, which will be sent to AuthzService
            RequestAttributes attribs = new DefaultRequestAttributes();
            attribs.setAttribute(AuthzConstants.ATTR_REQUEST_CONTEXT, req.requestContext());
            RequestContext authzRequest = new RequestContext.Builder().requestAttributes(attribs).build();

            this.connector.read(authzRequest, "/authz/authzCheck", new Consumer<ResourceResponse>() {

                boolean authorized;

                @Override
                public void accept(ResourceResponse resourceResponse) {
                    try {
                        resourceResponse.resource().readProperties(authzRequest, new PropertySink() {
                            @Override
                            public void accept(String name, Object value) {
                                if (name.equals(AuthzConstants.ATTR_AUTHZ_RESULT)) {
                                    authorized = (boolean) value;
                                }
                            }

                            @Override
                            public void close() throws Exception {
                            }
                        });

                        if (authorized) {
                            ctx.fireChannelRead(req);
                        } else {
                            boolean authenticated = req.requestContext().securityContext().isAuthenticated();
                            ResourceErrorResponse.ErrorType errorType = authenticated ? ResourceErrorResponse.ErrorType.FORBIDDEN : ResourceErrorResponse.ErrorType.NOT_AUTHORIZED;
                            ctx.writeAndFlush(new DefaultResourceErrorResponse(req, errorType));
                        }
                    } catch (Throwable t) {
                        t.printStackTrace();
                        ctx.writeAndFlush(new DefaultResourceErrorResponse(req, ResourceErrorResponse.ErrorType.INTERNAL_ERROR));
                    }
                }
            });
        } catch (Throwable e) {
            ctx.writeAndFlush(new DefaultResourceErrorResponse(req, ResourceErrorResponse.ErrorType.INTERNAL_ERROR));
        }
    }

}
