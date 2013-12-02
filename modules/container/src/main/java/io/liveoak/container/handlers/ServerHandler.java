package io.liveoak.container.handlers;

import io.liveoak.container.DefaultContainer;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;

/**
 * @author Bob McWhirter
 */
public class ServerHandler implements HttpHandler {

    public ServerHandler(DefaultContainer container) {
        this.container = container;
        this.decodingHandler =
                new WebSocketDetectingHandler(
                        new ResourceRequestDecodingHandler(
                                new AuthorizationHandler(
                                        new ResourceRequestHandler(
                                                new SubscriptionWatcherHandler(
                                                        new ResourceResponseHandler(this.container.getCodecManager()),
                                                        this.container.getSubscriptionManager()),
                                                this.container)),
                                container.getCodecManager()));
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        this.decodingHandler.handleRequest(exchange);
    }

    private DefaultContainer container;
    private HttpHandler decodingHandler;
}
