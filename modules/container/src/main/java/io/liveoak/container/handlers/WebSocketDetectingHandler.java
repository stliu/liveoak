package io.liveoak.container.handlers;

import io.liveoak.stomp.common.DebugHandler;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.websocketx.WebSocket13FrameDecoder;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.HttpUpgradeListener;
import io.undertow.util.AttachmentKey;
import io.undertow.util.HeaderValues;
import io.undertow.util.Headers;
import io.undertow.websockets.WebSocketConnectionCallback;
import io.undertow.websockets.WebSocketProtocolHandshakeHandler;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.spi.WebSocketHttpExchange;
import org.jboss.netty.xnio.transport.WrappingXnioSocketChannel;
import org.xnio.StreamConnection;

/**
 * @author Bob McWhirter
 */
public class WebSocketDetectingHandler implements HttpHandler, HttpUpgradeListener {

    private static final AttachmentKey<StreamConnection> CHANNEL_KEY = AttachmentKey.create( StreamConnection.class );

    public WebSocketDetectingHandler(HttpHandler next) {
        this.handshakeHandler = new WebSocketProtocolHandshakeHandler(this);
        this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        exchange.dispatch();
        HeaderValues upgradeHeaders = exchange.getRequestHeaders().get(Headers.UPGRADE);
        if (upgradeHeaders != null) {
            String upgradeValue = upgradeHeaders.getFirst();
            if (upgradeValue.equalsIgnoreCase("websocket")) {
                this.handshakeHandler.handleRequest(exchange);
                return;
            }
        }

        this.next.handleRequest(exchange);
    }

    @Override
    public void handleUpgrade(StreamConnection streamConnection, HttpServerExchange exchange) {
        System.err.println( "apparently upgraded" );

        WrappingXnioSocketChannel nettyChannel = new WrappingXnioSocketChannel( streamConnection );
        ChannelPipeline pipeline = nettyChannel.pipeline();
        pipeline.addLast( new DebugHandler( "Debug" ) );

    }

    /*
    @Override
    public void onConnect(WebSocketHttpExchange exchange, WebSocketChannel channel) {
        System.err.println("version: " + channel.getVersion());
        WrappingXnioSocketChannel nettyChannel = new WrappingXnioSocketChannel( xnioChannel );
        ChannelPipeline pipeline = nettyChannel.pipeline();
        pipeline.addLast( new WebSocket13FrameDecoder( true, false, 32767) );
        pipeline.addLast( new DebugHandler( "Debug" ) );

        //pipeline.addLast(new WebSocketStompFrameDecoder());
        //pipeline.addLast( new DebugHandler( "STOMP-B" ) );
        /*
        pipeline.addLast(new StompFrameDecoder());
        pipeline.addLast(new StompFrameEncoder());
        // handle frames
        pipeline.addLast(new ConnectHandler(serverContext));
        pipeline.addLast(new DisconnectHandler(serverContext));
        pipeline.addLast(new SubscribeHandler(serverContext));
        pipeline.addLast(new UnsubscribeHandler(serverContext));
        // convert some frames to messages
        pipeline.addLast(new ReceiptHandler());
        pipeline.addLast(new StompMessageDecoder());
        pipeline.addLast(new StompMessageEncoder(true));
        // handle messages
        pipeline.addLast(new SendHandler(serverContext));
        // catch errors, return an ERROR message.
        pipeline.addLast(new ErrorHandler());
        */
    //}

    private WebSocketProtocolHandshakeHandler handshakeHandler;
    private HttpHandler next;
}


