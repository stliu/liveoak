package io.liveoak.container.handlers;

import io.liveoak.container.ResourceResponse;
import io.liveoak.container.ResourceResponseSink;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;

/**
 * @author Bob McWhirter
 */
public class UndertowResourceResponseSink implements ResourceResponseSink{

    public UndertowResourceResponseSink(HttpHandler next, HttpServerExchange exchange) {
        this.next = next;
        this.exchange = exchange;
    }

    @Override
    public void accept(ResourceResponse response) {
        exchange.putAttachment( ResourceResponse.ATTACHMENT_KEY, response );
        try {
            //this.next.handleRequest( this.exchange );
            this.exchange.dispatch( this.next );
        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    public String toString() {
        return "[Sink: exchange=" + this.exchange + "; responseStarted=" + this.exchange.isResponseStarted() + "]";
    }

    private HttpHandler next;
    private HttpServerExchange exchange;
}
