/**
 * @author Eltik. Credit to CORS proxy by Rob Wu.
 * @description Proxies M3U8 and TS files with custom headers.
 * @license MIT
 */

import dotenv from "dotenv";
dotenv.config();

import httpProxy from "http-proxy";
import https from "node:https";
import http, { Server } from "node:http";
import net from "node:net";
import url from "node:url";
import { getProxyForUrl } from "proxy-from-env";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import colors from "colors";
import axios from "axios";

function withCORS(headers: http.OutgoingHttpHeaders, request: http.IncomingMessage): http.OutgoingHttpHeaders {
    headers["access-control-allow-origin"] = "*";
    const corsMaxAge = (request as any).corsAnywhereRequestState?.corsMaxAge;
    if (request.method === "OPTIONS" && corsMaxAge) {
        headers["access-control-max-age"] = corsMaxAge;
    }
    if (request.headers["access-control-request-method"]) {
        headers["access-control-allow-methods"] = request.headers["access-control-request-method"];
        delete request.headers["access-control-request-method"];
    }
    if (request.headers["access-control-request-headers"]) {
        headers["access-control-allow-headers"] = request.headers["access-control-request-headers"];
        delete request.headers["access-control-request-headers"];
    }
    headers["access-control-expose-headers"] = Object.keys(headers).join(",");
    return headers;
}

function proxyRequest(req: http.IncomingMessage, res: http.ServerResponse, proxy: httpProxy) {
    const location = (req as any).corsAnywhereRequestState.location;
    req.url = location.path;

    const proxyOptions: httpProxy.ServerOptions = {
        changeOrigin: false,
        prependPath: false,
        target: location,
        headers: {
            host: location.host,
        },
        buffer: {
            pipe: function (proxyReq) {
                const proxyReqOn = proxyReq.on;
                proxyReq.on = function (eventName, listener) {
                    if (eventName !== "response") {
                        return proxyReqOn.call(this, eventName, listener);
                    }
                    return proxyReqOn.call(this, "response", function (proxyRes) {
                        if (onProxyResponse(proxy, proxyReq, proxyRes, req, res)) {
                            try {
                                listener(proxyRes);
                            } catch (err) {
                                proxyReq.emit("error", err);
                            }
                        }
                    });
                };
                return req.pipe(proxyReq);
            },
        },
    };

    const proxyThroughUrl = (req as any).corsAnywhereRequestState.getProxyForUrl(location.href);
    if (proxyThroughUrl) {
        proxyOptions.target = proxyThroughUrl;
        (proxyOptions as any).toProxy = true;
        req.url = location.href;
    }

    try {
        proxy.web(req, res, proxyOptions);
    } catch (err) {
        console.error("Proxy error:", err);
        res.writeHead(500, withCORS({}, req));
        res.end("Internal server error during proxying");
    }
}

function onProxyResponse(proxy: httpProxy, proxyReq: http.ClientRequest, proxyRes: http.IncomingMessage, req: http.IncomingMessage, res: http.ServerResponse): boolean {
    const requestState = (req as any).corsAnywhereRequestState;
    const statusCode = proxyRes.statusCode;

    if (!requestState.redirectCount_) {
        res.setHeader("x-request-url", requestState.location.href);
    }

    if (statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308) {
        let locationHeader = proxyRes.headers.location;
        let parsedLocation;
        if (locationHeader) {
            locationHeader = url.resolve(requestState.location.href, locationHeader);
            parsedLocation = parseURL(locationHeader);
        }
        if (parsedLocation) {
            if (statusCode === 301 || statusCode === 302 || statusCode === 303) {
                requestState.redirectCount_ = (requestState.redirectCount_ || 0) + 1;
                if (requestState.redirectCount_ <= requestState.maxRedirects) {
                    res.setHeader("X-CORS-Redirect-" + requestState.redirectCount_, `${statusCode} ${locationHeader}`);
                    req.method = "GET";
                    req.headers["content-length"] = "0";
                    delete req.headers["content-type"];
                    requestState.location = parsedLocation;

                    req.removeAllListeners();
                    proxyReq.removeAllListeners("error");
                    proxyReq.once("error", () => {});
                    proxyReq.abort();

                    proxyRequest(req, res, proxy);
                    return false;
                }
            }
            proxyRes.headers.location = requestState.proxyBaseUrl + "/" + locationHeader;
        }
    }

    delete proxyRes.headers["set-cookie"];
    delete proxyRes.headers["set-cookie2"];
    proxyRes.headers["x-final-url"] = requestState.location.href;
    withCORS(proxyRes.headers, req);
    return true;
}

function parseURL(req_url: string): url.Url | null {
    const match = req_url.match(/^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i);
    if (!match) return null;
    if (!match[1] && /^https?:/i.test(req_url)) return null;

    const parsed = url.parse(!match[1] ? ((match[4] === "443" ? "https:" : "http:") + req_url) : req_url);
    if (!parsed.hostname) return null;
    return parsed;
}

interface CorsAnywhereOptions {
    handleInitialRequest?: (req: http.IncomingMessage, res: http.ServerResponse, location: url.Url | null) => boolean;
    getProxyForUrl: (url: string) => string;
    maxRedirects: number;
    originBlacklist: string[];
    originWhitelist: string[];
    checkRateLimit?: (origin: string) => string | undefined;
    redirectSameOrigin: boolean;
    requireHeader: string[] | null;
    removeHeaders: string[];
    setHeaders: Record<string, string>;
    corsMaxAge: number;
}

function getHandler(options: Partial<CorsAnywhereOptions>, proxy: httpProxy): (req: http.IncomingMessage, res: http.ServerResponse) => void {
    const corsAnywhere: CorsAnywhereOptions = {
        handleInitialRequest: null,
        getProxyForUrl: getProxyForUrl,
        maxRedirects: 5,
        originBlacklist: [],
        originWhitelist: [],
        checkRateLimit: null,
        redirectSameOrigin: false,
        requireHeader: null,
        removeHeaders: [],
        setHeaders: {},
        corsMaxAge: 0,
    };

    Object.assign(corsAnywhere, options);

    if (corsAnywhere.requireHeader) {
        corsAnywhere.requireHeader = typeof corsAnywhere.requireHeader === "string"
            ? [corsAnywhere.requireHeader.toLowerCase()]
            : corsAnywhere.requireHeader.length === 0
            ? null
            : corsAnywhere.requireHeader.map(h => h.toLowerCase());
    }

    const hasRequiredHeaders = (headers: http.IncomingHttpHeaders): boolean =>
        !corsAnywhere.requireHeader || corsAnywhere.requireHeader.some(h => h in headers);

    return function (req: http.IncomingMessage, res: http.ServerResponse): void {
        (req as any).corsAnywhereRequestState = {
            getProxyForUrl: corsAnywhere.getProxyForUrl,
            maxRedirects: corsAnywhere.maxRedirects,
            corsMaxAge: corsAnywhere.corsMaxAge,
        };

        const cors_headers = withCORS({}, req);
        if (req.method === "OPTIONS") {
            res.writeHead(200, cors_headers);
            res.end();
            return;
        }

        const location = parseURL(req.url?.slice(1) || "");
        if (corsAnywhere.handleInitialRequest?.(req, res, location)) return;

        if (!location) {
            if (/^\/https?:\/[^/]/i.test(req.url || "")) {
                res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
                res.end("The URL is invalid: two slashes are needed after the http(s):.");
                return;
            }
            res.end(readFileSync(join(__dirname, "../index.html")));
            return;
        }

        if (location.host === "iscorsneeded") {
            res.writeHead(200, { "Content-Type": "text/plain" });
            res.end("no");
            return;
        }

        if ((Number(location.port) || 0) > 65535) {
            res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
            res.end("Port number too large: " + location.port);
            return;
        }

        function isValidHostName(hostname: string): boolean {
            const regexp = /\.(?:[a-zA-Z0-9\-]+)$/i; // Simplified for brevity; include full TLD list if needed
            return !!(regexp.test(hostname) || net.isIPv4(hostname) || net.isIPv6(hostname));
        }

        if (!/^\/https?:/.test(req.url || "") && !isValidHostName(location.hostname)) {
            const uri = new URL(req.url || web_server_url, "http://localhost:3000");
            if (uri.pathname === "/m3u8-proxy") {
                let headers: Record<string, string> = {};
                try {
                    headers = JSON.parse(uri.searchParams.get("headers") || "{}");
                } catch (e: any) {
                    res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
                    res.end("Invalid headers: " + e.message);
                    return;
                }
                const url = uri.searchParams.get("url");
                if (!url) {
                    res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
                    res.end("Missing URL parameter");
                    return;
                }
                return proxyM3U8(url, headers, res);
            } else if (uri.pathname === "/ts-proxy") {
                let headers: Record<string, string> = {};
                try {
                    headers = JSON.parse(uri.searchParams.get("headers") || "{}");
                } catch (e: any) {
                    res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
                    res.end("Invalid headers: " + e.message);
                    return;
                }
                const url = uri.searchParams.get("url");
                if (!url) {
                    res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
                    res.end("Missing URL parameter");
                    return;
                }
                return proxyTs(url, headers, req, res);
            } else if (uri.pathname === "/") {
                res.end(readFileSync(join(__dirname, "../index.html")));
            } else {
                res.writeHead(404, withCORS({ "Content-Type": "text/plain" }, req));
                res.end("Invalid host: " + location.hostname);
            }
            return;
        }

        if (!hasRequiredHeaders(req.headers)) {
            res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
            res.end("Missing required request header. Must specify one of: " + corsAnywhere.requireHeader);
            return;
        }

        const origin = req.headers.origin || "";
        if (corsAnywhere.originBlacklist.includes(origin)) {
            res.writeHead(403, withCORS({ "Content-Type": "text/plain" }, req));
            res.end(`The origin "${origin}" was blacklisted by the operator of this proxy.`);
            return;
        }

        if (corsAnywhere.originWhitelist.length && !corsAnywhere.originWhitelist.includes(origin)) {
            res.writeHead(403, withCORS({ "Content-Type": "text/plain" }, req));
            res.end(`The origin "${origin}" was not whitelisted by the operator of this proxy.`);
            return;
        }

        const rateLimitMessage = corsAnywhere.checkRateLimit?.(origin);
        if (rateLimitMessage) {
            res.writeHead(429, withCORS({ "Content-Type": "text/plain" }, req));
            res.end(`The origin "${origin}" has sent too many requests.\n${rateLimitMessage}`);
            return;
        }

        if (corsAnywhere.redirectSameOrigin && origin && location.href.startsWith(origin + "/")) {
            res.writeHead(301, withCORS({ vary: "origin", "cache-control": "private", location: location.href }, req));
            res.end();
            return;
        }

        const isRequestedOverHttps = req.connection.encrypted || /^\s*https/.test(req.headers["x-forwarded-proto"] || "");
        const proxyBaseUrl = (isRequestedOverHttps ? "https://" : "http://") + req.headers.host;

        corsAnywhere.removeHeaders.forEach(header => delete req.headers[header]);
        Object.assign(req.headers, corsAnywhere.setHeaders);

        (req as any).corsAnywhereRequestState.location = location;
        (req as any).corsAnywhereRequestState.proxyBaseUrl = proxyBaseUrl;

        proxyRequest(req, res, proxy);
    };
}

function createServer(options: Partial<CorsAnywhereOptions> & { httpsOptions?: https.ServerOptions } = {}): Server {
    const httpProxyOptions: httpProxy.ServerOptions = {
        xfwd: true,
        secure: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0",
    };
    Object.assign(httpProxyOptions, options.httpProxyOptions);

    const proxyServer = httpProxy.createServer(httpProxyOptions);
    const requestHandler = getHandler(options, proxyServer);
    const server = options.httpsOptions
        ? https.createServer(options.httpsOptions, requestHandler)
        : http.createServer(requestHandler);

    proxyServer.on("error", (err, req, res) => {
        if (res.headersSent) {
            if (!res.writableEnded) res.end();
            return;
        }
        res.getHeaderNames().forEach(name => res.removeHeader(name));
        res.writeHead(404, withCORS({ "Content-Type": "text/plain" }, req));
        res.end("Not found because of proxy error: " + err);
    });

    return server;
}

const host = process.env.HOST || "0.0.0.0";
const port = process.env.PORT || 8080;
const web_server_url = process.env.PUBLIC_URL || `http://${host}:${port}`;

export default function server(): void {
    const originBlacklist = parseEnvList(process.env.CORSANYWHERE_BLACKLIST);
    const originWhitelist = parseEnvList(process.env.CORSANYWHERE_WHITELIST);
    function parseEnvList(env?: string): string[] {
        return env ? env.split(",") : [];
    }

    createServer({
        originBlacklist,
        originWhitelist,
        requireHeader: [],
        checkRateLimit: createRateLimitChecker(process.env.CORSANYWHERE_RATELIMIT),
        removeHeaders: [
            "cookie",
            "cookie2",
            "x-request-start",
            "x-request-id",
            "via",
            "connect-time",
            "total-route-time",
        ],
        redirectSameOrigin: true,
        httpProxyOptions: {
            xfwd: false,
        },
    }).listen(port, host, () => {
        console.log(colors.green("Server running on ") + colors.blue(`${web_server_url}`));
    });
}

function createRateLimitChecker(CORSANYWHERE_RATELIMIT?: string): (origin: string) => string | undefined {
    const rateLimitConfig = /^(\d+) (\d+)(?:\s*$|\s+(.+)$)/.exec(CORSANYWHERE_RATELIMIT || "");
    if (!rateLimitConfig) return () => undefined;

    const maxRequestsPerPeriod = parseInt(rateLimitConfig[1]);
    const periodInMinutes = parseInt(rateLimitConfig[2]);
    let unlimitedPattern: RegExp | undefined;
    if (rateLimitConfig[3]) {
        const unlimitedPatternParts = rateLimitConfig[3]
            .trim()
            .split(/\s+/)
            .map((host, i) => {
                if (host.startsWith("/") && host.endsWith("/")) {
                    try {
                        return host.slice(1, -1);
                    } catch {
                        throw new Error(`Invalid regex at index ${i} in CORSANYWHERE_RATELIMIT`);
                    }
                }
                return host.replace(/[$()*+.?[\\\]^{|}]/g, "\\$&");
            });
        unlimitedPattern = new RegExp("^(?:" + unlimitedPatternParts.join("|") + ")$", "i");
    }

    let accessedHosts: Record<string, number> = {};
    setInterval(() => (accessedHosts = {}), periodInMinutes * 60000);

    const rateLimitMessage = `The number of requests is limited to ${maxRequestsPerPeriod} per ${periodInMinutes === 1 ? "minute" : periodInMinutes + " minutes"}. Please self-host CORS Anywhere if you need more quota. See https://github.com/Rob--W/cors-anywhere#demo-server`;

    return function checkRateLimit(origin: string): string | undefined {
        const host = origin.replace(/^[\w\-]+:\/\//i, "");
        if (unlimitedPattern?.test(host)) return undefined;
        accessedHosts[host] = (accessedHosts[host] || 0) + 1;
        if (accessedHosts[host] > maxRequestsPerPeriod) return rateLimitMessage;
        return undefined;
    };
}

export async function proxyM3U8(url: string, headers: Record<string, string>, res: http.ServerResponse): Promise<void> {
    if (!url.match(/^https?:\/\//)) {
        res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, {} as any));
        res.end("Invalid URL: Must include http:// or https://");
        return;
    }

    const req = await axios.get(url, {
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36",
            ...headers,
        },
        validateStatus: () => true,
    }).catch(err => {
        res.writeHead(500, withCORS({ "Content-Type": "text/plain" }, {} as any));
        res.end(`Failed to fetch M3U8: ${err.message}`);
        return null;
    });

    if (!req) return;

    if (req.status >= 400) {
        res.writeHead(req.status, withCORS({ "Content-Type": "text/plain" }, {} as any));
        res.end(`Failed to fetch M3U8: ${req.statusText}`);
        return;
    }

    const m3u8 = req.data;
    const newLines: string[] = [];
    const lines = m3u8.split("\n");
    const isMaster = m3u8.includes("RESOLUTION=");

    for (const line of lines) {
        if (line.startsWith("#")) {
            if (line.startsWith("#EXT-X-KEY:")) {
                const regex = /https?:\/\/[^"\s]+/g;
                const keyUrl = regex.exec(line)?.[0];
                if (keyUrl) {
                    const proxyUrl = `${web_server_url}/ts-proxy?url=${encodeURIComponent(keyUrl)}&headers=${encodeURIComponent(JSON.stringify(headers))}`;
                    newLines.push(line.replace(regex, proxyUrl));
                } else {
                    newLines.push(line);
                }
            } else {
                newLines.push(line);
            }
        } else if (line.trim()) {
            try {
                const uri = new URL(line, url);
                const endpoint = isMaster ? "/m3u8-proxy" : "/ts-proxy";
                newLines.push(`${web_server_url}${endpoint}?url=${encodeURIComponent(uri.href)}&headers=${encodeURIComponent(JSON.stringify(headers))}`);
            } catch {
                newLines.push(line); // Fallback to original line if URL parsing fails
            }
        } else {
            newLines.push(line);
        }
    }

    res.setHeader("Content-Type", "application/vnd.apple.mpegurl");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Access-Control-Allow-Methods", "*");
    res.end(newLines.join("\n"));
}

export async function proxyTs(url: string, headers: Record<string, string>, req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!url.match(/^https?:\/\//)) {
        res.writeHead(400, withCORS({ "Content-Type": "text/plain" }, req));
        res.end("Invalid URL: Must include http:// or https://");
        return;
    }

    const uri = new URL(url);
    const options: http.RequestOptions | https.RequestOptions = {
        hostname: uri.hostname,
        port: uri.port || (url.startsWith("https://") ? 443 : 80),
        path: uri.pathname + uri.search,
        method: req.method,
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36",
            ...headers,
        },
    };

    try {
        const proxy = (url.startsWith("https://") ? https : http).request(options, r => {
            r.headers["content-type"] = "video/mp2t";
            withCORS(r.headers, req);
            res.writeHead(r.statusCode || 200, r.headers);
            r.pipe(res, { end: true });
        });

        proxy.on("error", err => {
            res.writeHead(500, withCORS({ "Content-Type": "text/plain" }, req));
            res.end(`Failed to proxy TS file: ${err.message}`);
        });

        req.pipe(proxy, { end: true });
    } catch (e: any) {
        res.writeHead(500, withCORS({ "Content-Type": "text/plain" }, req));
        res.end(`Failed to proxy TS file: ${e.message}`);
    }
}
