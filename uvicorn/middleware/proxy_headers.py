"""
This middleware can be used when a known proxy is fronting the application,
and is trusted to be properly setting the `X-Forwarded-Proto` and
`X-Forwarded-For` headers with the connecting client information.

Modifies the `client` and `scheme` information so that they reference
the connecting client, rather that the connecting proxy.

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#Proxies
"""

from __future__ import annotations

from typing import Union, cast

from uvicorn._types import ASGI3Application, ASGIReceiveCallable, ASGISendCallable, HTTPScope, Scope, WebSocketScope


class ProxyHeadersMiddleware:
    def __init__(
        self,
        app: ASGI3Application,
        trusted_hosts: list[str] | str = "127.0.0.1",
    ) -> None:
        self.app = app
        if isinstance(trusted_hosts, str):
            self.trusted_hosts = {item.strip() for item in trusted_hosts.split(",")}
        else:
            self.trusted_hosts = set(trusted_hosts)
        self.always_trust = "*" in self.trusted_hosts

    def get_trusted_client_host(self, x_forwarded_for_hosts: list[str]) -> str | None:
        if self.always_trust:
            return x_forwarded_for_hosts[0]

        for host in reversed(x_forwarded_for_hosts):
            if host not in self.trusted_hosts:
                return host

        return None  # pragma: full coverage

    def parse_forwarded(self, forwarded: str) -> dict:
        forwarded_dict = {}
        # We are only interested in the initial request
        for pair in forwarded.split(",")[0].split(';'):
            key, value = pair.split("=")
            forwarded_dict[key.strip()] = value.strip()
        return forwarded_dict

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] in ("http", "websocket"):
            scope = cast(Union["HTTPScope", "WebSocketScope"], scope)
            client_addr: tuple[str, int] | None = scope.get("client")
            client_host = client_addr[0] if client_addr else None

            if self.always_trust or client_host in self.trusted_hosts:
                headers = dict(scope["headers"])

                forwarded_dict = {}
                if b"forwarded" in headers:
                    forwarded = headers[b"forwarded"].decode("latin1").strip()
                    forwarded_dict = self.parse_forwarded(forwarded)

                if "proto" in forwarded_dict or b"x-forwarded-proto" in headers:
                    # Determine if the incoming request was http or https based on
                    # the X-Forwarded-Proto header.
                    proto = forwarded_dict.get("proto", None)
                    if proto is None:
                        proto = headers[b"x-forwarded-proto"].decode("latin1").strip()
                    if scope["type"] == "websocket":
                        scope["scheme"] = proto.replace("http", "ws")
                    else:
                        scope["scheme"] = proto

                if b"x-forwarded-for" in headers:
                    # Determine the client address from the last trusted IP in the
                    # X-Forwarded-For header. We've lost the connecting client's port
                    # information by now, so only include the host.
                    x_forwarded_for = headers[b"x-forwarded-for"].decode("latin1")
                    x_forwarded_for_hosts = [item.strip() for item in x_forwarded_for.split(",")]
                    host = self.get_trusted_client_host(x_forwarded_for_hosts)
                    port = 0
                    scope["client"] = (host, port)  # type: ignore[arg-type]

                if "host" in forwarded_dict:
                    headers[b"host"] = forwarded_dict["host"].encode("latin1")

                scope['headers'] = [(k, v) for k, v in headers.items()]

        return await self.app(scope, receive, send)
