/*
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Eclipse Public License version 1.0, available at http://www.eclipse.org/legal/epl-v10.html
 */
package io.liveoak.container.auth;

import io.liveoak.container.DefaultResourceErrorResponse;
import io.liveoak.container.DefaultSecurityContext;
import io.liveoak.spi.container.DirectConnector;
import io.liveoak.spi.ResourceErrorResponse;
import io.liveoak.spi.ResourceRequest;
import io.liveoak.spi.ResourceResponse;
import io.liveoak.spi.RequestContext;
import io.liveoak.spi.resource.async.PropertySink;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpHeaders;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AuthHandler extends SimpleChannelInboundHandler<ResourceRequest> {

    // TODO: replace with real logging
    private static final SimpleLogger log = new SimpleLogger(AuthHandler.class);

    public static final String AUTH_TYPE = "bearer";

    private DirectConnector connector;

    public AuthHandler(DirectConnector connector) {
        this.connector = connector;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ResourceRequest req) throws Exception {
        final RequestContext requestContext = req.requestContext();
        final DefaultSecurityContext securityContext = (DefaultSecurityContext) requestContext.securityContext();
        final String token = getBearerToken(requestContext);
        if (token != null) {
            initSecurityContext(ctx, req, securityContext, token);
        } else {
            ctx.fireChannelRead(req);
        }
    }

    private void initSecurityContext(final ChannelHandlerContext ctx, final ResourceRequest req, final DefaultSecurityContext securityContext, String token) {
        final RequestContext tokenRequestContext = new RequestContext.Builder().build();
        try {
            connector.read(tokenRequestContext, "/auth/token-info/" + token, new Consumer<ResourceResponse>() {
                @Override
                public void accept(ResourceResponse resourceResponse) {
                    try {
                        resourceResponse.resource().readProperties(tokenRequestContext, new PropertySink() {
                            @Override
                            public void accept(String name, Object value) {
                                switch (name) {
                                    case "realm":
                                        securityContext.setRealm((String) value);
                                        break;
                                    case "subject":
                                        securityContext.setSubject((String) value);
                                        break;
                                    case "issued-at":
                                        securityContext.setLastVerified(((Date) value).getTime());
                                        break;
                                    case "roles":
                                        Set<String> roles = new HashSet<>();
                                        roles.addAll((Collection<? extends String>) value);
                                        securityContext.setRoles(roles);
                                        break;
                                }
                            }

                            @Override
                            public void close() throws Exception {
                            }
                        });

                        ctx.fireChannelRead(req);
                    } catch (Throwable t) {
                        ctx.writeAndFlush(new DefaultResourceErrorResponse(req, ResourceErrorResponse.ErrorType.NOT_AUTHORIZED));
                    }
                }
            });
        } catch (Throwable t) {
            t.printStackTrace();
            ctx.writeAndFlush(new DefaultResourceErrorResponse(req, ResourceErrorResponse.ErrorType.INTERNAL_ERROR));
        }
    }

    private String getBearerToken(RequestContext requestContext) {
        String auth = requestContext.requestAttributes().getAttribute(HttpHeaders.Names.AUTHORIZATION, String.class);
        if (auth != null) {
            String[] a = auth.split(" ");
            if (a.length == 2 && a[0].equals(AUTH_TYPE)) {
                return a[1];
            }
        }
        return null;
    }

}
