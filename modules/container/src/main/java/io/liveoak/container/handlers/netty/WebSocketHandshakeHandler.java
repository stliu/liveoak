package io.liveoak.container.handlers.netty;


import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.websocketx.WebSocketServerHandshaker;
import io.netty.handler.codec.http.websocketx.WebSocketServerHandshakerFactory;

/**
 * @author Bob McWhirter
 */
public class WebSocketHandshakeHandler extends SimpleChannelInboundHandler<Object> {

    public WebSocketHandshakeHandler() {
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
        FullHttpRequest req = (FullHttpRequest) msg;
        String upgrade = req.headers().get(HttpHeaders.Names.UPGRADE);
        if (HttpHeaders.Values.WEBSOCKET.equalsIgnoreCase(upgrade)) {
            WebSocketServerHandshakerFactory wsFactory = new WebSocketServerHandshakerFactory(req.getUri(), null, false);
            WebSocketServerHandshaker handshaker = wsFactory.newHandshaker(req);
            if (handshaker == null) {
                WebSocketServerHandshakerFactory.sendUnsupportedWebSocketVersionResponse(ctx.channel());
            } else {
                ChannelFuture future = handshaker.handshake(ctx.channel(), req);
                future.addListener(f -> {
                    //this.configurator.switchToWebSockets(ctx.pipeline());
                    System.err.println( "OKAY!" );
                });
            }
        }
    }

}
