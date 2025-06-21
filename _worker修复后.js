import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';
let subConverter = atob('U1VCQVBJLkNNTGl1c3Nzcy5uZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;
let enableHttp = false;
let noTLS = 'false';
const expire = 4102329600;
let proxyIPs;
let socks5s;
let go2Socks5s = [
    '*ttvnw.net',
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*.loadshare.org',
];
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;
let FileName = atob('ZWRnZXR1bm5lbA==');
let proxyhosts = [];
let proxyhostsURL = '';
let RproxyIP = 'false';
const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let 有效时间 = 7;
let 更新时间 = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
let path = '/?ed=2560';
let 动态UUID;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
let SCV = 'true';
let allowInsecure = '&allowInsecure=1';

export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
            
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                动态UUID = env.KEY || env.TOKEN || userID;
                有效时间 = Number(env.TIME) || 有效时间;
                更新时间 = Number(env.UPTIME) || 更新时间;
                const userIDs = await 生成动态UUID(动态UUID);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            }

            if (!userID) {
                return new Response('请设置你的UUID变量', {
                    status: 404,
                    headers: {"Content-Type": "text/plain;charset=utf-8"}
                });
            }

            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            
            // 修复点1：正确定义fakeUserID
            const fakeUserIDMD5 = await 双重哈希(`${userID}${timestamp}`);
            const fakeUserID = [
                fakeUserIDMD5.slice(0, 8),
                fakeUserIDMD5.slice(8, 12),
                fakeUserIDMD5.slice(12, 16),
                fakeUserIDMD5.slice(16, 20),
                fakeUserIDMD5.slice(20)
            ].join('-');

            const fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;

            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await 整理(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

            socks5Address = env.HTTP || env.SOCKS5 || socks5Address;
            socks5s = await 整理(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            enableHttp = env.HTTP ? true : socks5Address.toLowerCase().includes('http://');
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            
            if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
            if (env.BAN) banHosts = await 整理(env.BAN);

            if (socks5Address) {
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    RproxyIP = env.RPROXYIP || 'false';
                    enableSocks = true;
                } catch (err) {
                    RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
                    enableSocks = false;
                }
            } else {
                RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
            }

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (env.ADD) addresses = await 整理(env.ADD);
                if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);
                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                FileName = env.SUBNAME || FileName;
                subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
                if (subEmoji == '0') subEmoji = 'false';
                if (env.LINK) link = await 整理(env.LINK);
                
                let sub = env.SUB || '';
                subConverter = env.SUBAPI || subConverter;
                if (subConverter.includes("http://")) {
                    subConverter = subConverter.split("//")[1];
                    subProtocol = 'http';
                } else {
                    subConverter = subConverter.split("//")[1] || subConverter;
                }
                subConfig = env.SUBCONFIG || subConfig;
                
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') {
                    sub = url.searchParams.get('sub').toLowerCase();
                }
                if (url.searchParams.has('notls')) noTLS = 'true';

                if (url.searchParams.has('proxyip')) {
                    path = `/proxyip=${url.searchParams.get('proxyip')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks5') || url.searchParams.has('socks')) {
                    const socksParam = url.searchParams.get('socks5') || url.searchParams.get('socks');
                    path = `/?socks5=${socksParam}`;
                    RproxyIP = 'false';
                }

                SCV = env.SCV || SCV;
                if (!SCV || SCV == '0' || SCV == 'false') allowInsecure = '';
                else SCV = 'true';

                const 路径 = url.pathname.toLowerCase();
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response(JSON.stringify(request.cf, null, 4), {
                        status: 200,
                        headers: {'content-type': 'application/json'},
                    });
                } else if (路径 == `/${fakeUserID}`) {
                    // 修复点2：使用对象参数确保完整传递
                    const fakeConfig = await 生成配置信息({
                        userID,
                        hostName: request.headers.get('Host'),
                        sub,
                        UA: 'CF-Workers-SUB',
                        RproxyIP,
                        url,
                        fakeUserID,
                        fakeHostName,
                        env
                    });
                    return new Response(`${fakeConfig}`, { status: 200 });
                } else if (url.pathname == `/${动态UUID}/edit` || 路径 == `/${userID}/edit`) {
                    const html = await KV(request, env);
                    return html;
                } else if (url.pathname == `/${动态UUID}` || 路径 == `/${userID}`) {
                    const 维列斯Config = await 生成配置信息({
                        userID,
                        hostName: request.headers.get('Host'),
                        sub,
                        UA,
                        RproxyIP,
                        url,
                        fakeUserID,
                        fakeHostName,
                        env
                    });
                    const now = Date.now();
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;

                    if (userAgent && userAgent.includes('mozilla')) {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                "Cache-Control": "no-store",
                            }
                        });
                    } else {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            }
                        });
                    }
                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response('UUID错误', { status: 404 });
                }
            } else {
                socks5Address = url.searchParams.get('socks5') || socks5Address;
                if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
                else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname) || new RegExp('/http://', 'i').test(url.pathname)) {
                    enableHttp = url.pathname.includes('http://');
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        let userPassword = socks5Address.split('@')[0].replaceAll('%3D', '=');
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
                    }
                    go2Socks5s = ['all in'];
                }

                if (socks5Address) {
                    try {
                        parsedSocks5Address = socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        enableSocks = false;
                    }
                } else {
                    enableSocks = false;
                }

                if (url.searchParams.has('proxyip')) {
                    proxyIP = url.searchParams.get('proxyip');
                    enableSocks = false;
                } else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
                    enableSocks = false;
                } else if (new RegExp('/proxyip.', 'i').test(url.pathname)) {
                    proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
                    enableSocks = false;
                } else if (new RegExp('/pyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/pyip=')[1];
                    enableSocks = false;
                }

                return await 维列斯OverWSHandler(request);
            }
        } catch (err) {
            return new Response(err.toString());
        }
    },
};

async function 维列斯OverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWapper = { value: null };
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns) return await handleDNSQuery(chunk, webSocket, null, log);
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const { hasError, message, addressType, portRemote = 443, addressRemote = '', rawDataIndex, 维列斯Version = new Uint8Array([0, 0]), isUDP } = process维列斯Header(chunk, userID);
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '}`;
            
            if (hasError) throw new Error(message);
            if (isUDP) {
                if (portRemote === 53) isDns = true;
                else throw new Error('UDP 代理仅对 DNS（53 端口）启用');
            }
            
            const 维列斯ResponseHeader = new Uint8Array([维列斯Version[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) return handleDNSQuery(rawClientData, webSocket, 维列斯ResponseHeader, log);
            if (!banHosts.includes(addressRemote)) {
                log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
                handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log);
            } else {
                throw new Error(`黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`);
            }
        },
        close() { log(`readableWebSocketStream 已关闭`); },
        abort(reason) { log(`readableWebSocketStream 已中止`, JSON.stringify(reason)); },
    })).catch((err) => log('readableWebSocketStream 管道错误', err));

    return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log) {
    async function useSocks5Pattern(address) {
        if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
        return go2Socks5s.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false, http = false) {
        log(`connected to ${address}:${port}`);
        const tcpSocket = socks
            ? (http ? await httpConnect(address, port, log) : await socks5Connect(addressType, address, port, log))
            : connect({ hostname: address, port: port });

        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function nat64() {
        if (!useSocks) {
            const nat64Proxyip = `[${await resolveToIPv6(addressRemote)}]`;
            log(`NAT64 代理连接到 ${nat64Proxyip}:443`);
            tcpSocket = await connectAndWrite(nat64Proxyip, '443');
        }
        tcpSocket.closed.catch(error => console.log('retry tcpSocket closed error', error))
            .finally(() => safeCloseWebSocket(webSocket));
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, null, log);
    }

    async function retry() {
        if (enableSocks) {
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            if (!proxyIP || proxyIP == '') proxyIP = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg==');
            else if (proxyIP.includes(']:')) {
                portRemote = proxyIP.split(']:')[1] || portRemote;
                proxyIP = proxyIP.split(']:')[0] + "]" || proxyIP;
            } else if (proxyIP.split(':').length === 2) {
                portRemote = proxyIP.split(':')[1] || portRemote;
                proxyIP = proxyIP.split(':')[0] || proxyIP;
            }
            if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
            tcpSocket = await connectAndWrite(proxyIP.toLowerCase() || addressRemote, portRemote);
        }
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, nat64, log);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote);
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks, enableHttp);
    remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });

            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });

            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket 服务器发生错误');
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        pull(controller) {},
        cancel(reason) {
            if (readableStreamCancel) return;
            log(`可读流被取消，原因是 ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

function process维列斯Header(维列斯Buffer, userID) {
    if (维列斯Buffer.byteLength < 24) return { hasError: true, message: 'invalid data' };

    const version = new Uint8Array(维列斯Buffer.slice(0, 1));
    let isValidUser = false;
    let isUDP = false;

    function isUserIDValid(userID, userIDLow, buffer) {
        const userIDArray = new Uint8Array(buffer.slice(1, 17));
        const userIDString = stringify(userIDArray);
        return userIDString === userID || userIDString === userIDLow;
    }

    isValidUser = isUserIDValid(userID, userIDLow, 维列斯Buffer);
    if (!isValidUser) return { hasError: true, message: `invalid user ${(new Uint8Array(维列斯Buffer.slice(1, 17))}` };

    const optLength = new Uint8Array(维列斯Buffer.slice(17, 18))[0];
    const command = new Uint8Array(维列斯Buffer.slice(18 + optLength, 18 + optLength + 1))[0];

    if (command === 1) {}
    else if (command === 2) isUDP = true;
    else return { hasError: true, message: `command ${command} is not support, command 01-tcp,02-udp,03-mux` };

    const portIndex = 18 + optLength + 1;
    const portBuffer = 维列斯Buffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(维列斯Buffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(维列斯Buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
            addressValue = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `invild addressType is ${addressType}` };
    }

    if (!addressValue) return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        维列斯Version: version,
        isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, 维列斯ResponseHeader, retry, log) {
    let remoteChunkCount = 0;
    let 维列斯Header = 维列斯ResponseHeader;
    let hasIncomingData = false;

    await remoteSocket.readable.pipeTo(new WritableStream({
        start() {},
        async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error('webSocket.readyState is not open, maybe close');
            
            if (维列斯Header) {
                webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                维列斯Header = null;
            } else {
                webSocket.send(chunk);
            }
        },
        close() { log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`); },
        abort(reason) { console.error(`remoteConnection!.readable abort`, reason); },
    })).catch((error) => {
        console.error(`remoteSocketToWS has exception `, error.stack || error);
        safeCloseWebSocket(webSocket);
    });

    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: undefined, error: null };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) throw TypeError(`生成的 UUID 不符合规范 ${uuid}`);
    return uuid;
}

async function handleDNSQuery(udpChunk, webSocket, 维列斯ResponseHeader, log) {
    try {
        const dnsServer = '8.8.4.4';
        const dnsPort = 53;
        let 维列斯Header = 维列斯ResponseHeader;
        const tcpSocket = connect({ hostname: dnsServer, port: dnsPort });
        
        log(`连接到 ${dnsServer}:${dnsPort}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();

        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (维列斯Header) {
                        webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                        维列斯Header = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
            close() { log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`); },
            abort(reason) { console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason); },
        }));
    } catch (error) {
        console.error(`handleDNSQuery 函数发生异常，错误信息: ${error.message}`);
    }
}

async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port });
    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    const writer = socket.writable.getWriter();
    await writer.write(socksGreeting);
    log('已发送 SOCKS5 问候消息');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;
    if (res[0] !== 0x05) {
        log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("服务器不接受任何认证方法");
        return;
    }

    if (res[1] === 0x02) {
        log("SOCKS5 服务器需要认证");
        if (!username || !password) {
            log("请提供用户名和密码");
            return;
        }
        const authRequest = new Uint8Array([
            1,
            username.length,
            ...encoder.encode(username),
            password.length,
            ...encoder.encode(password)
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("SOCKS5 服务器认证失败");
            return;
        }
    }

    let DSTADDR;
    switch (addressType) {
        case 1:
            DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
            break;
        case 2:
            DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
            break;
        case 3:
            DSTADDR = new Uint8Array([4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
            break;
        default:
            log(`无效的地址类型: ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    await writer.write(socksRequest);
    log('已发送 SOCKS5 请求');

    res = (await reader.read()).value;
    if (res[1] === 0x00) log("SOCKS5 连接已建立");
    else {
        log("SOCKS5 连接建立失败");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

async function httpConnect(addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({ hostname, port });
    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`;
    connectRequest += `\r\n`;

    log(`正在连接到 ${addressRemote}:${portRemote} 通过代理 ${hostname}:${port}`);

    try {
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    }

    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) throw new Error('HTTP代理连接中断');
            
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            respText = new TextDecoder().decode(responseBuffer);

            if (respText.includes('\r\n\r\n')) {
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);
                log(`收到HTTP代理响应: ${headers.split('\r\n')[0]}`);

                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;
                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        const dataStream = new ReadableStream({
                            start(controller) { controller.enqueue(remainingData); }
                        });
                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => console.error('处理剩余数据错误:', err));
                        sock.readable = readable;
                    }
                } else {
                    throw new Error(`HTTP代理连接失败: ${headers.split('\r\n')[0]}`);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    }

    reader.releaseLock();
    if (!connected) throw new Error('HTTP代理连接失败: 未收到成功响应');
    log(`HTTP代理连接成功: ${addressRemote}:${portRemote}`);
    return sock;
}

function socks5AddressParser(address) {
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, port;

    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        [username, password] = formers;
    }

    const latters = latter.split(":");
    port = Number(latters.pop());
    if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    hostname = latters.join(":");

    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');

    return { username, password, hostname, port };
}

// 修复点3：使用对象参数重构关键函数
function 恢复伪装信息({ content, userID, hostName, fakeUserID, fakeHostName, isBase64 }) {
    if (isBase64) content = atob(content);
    content = content.replace(new RegExp(fakeUserID, 'g'), userID)
                    .replace(new RegExp(fakeHostName, 'g'), hostName);
    if (isBase64) content = btoa(content);
    return content;
}

async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();
    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次十六进制 = Array.from(new Uint8Array(第一次哈希)).map(b => b.toString(16).padStart(2, '0')).join('');
    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    return Array.from(new Uint8Array(第二次哈希)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function 代理URL(代理网址, 目标网址) {
    const 网址列表 = await 整理(代理网址);
    const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];
    const 解析后的网址 = new URL(完整网址);
    
    let 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    let 路径名 = 解析后的网址.pathname;
    if (路径名.endsWith('/')) 路径名 = 路径名.slice(0, -1);
    路径名 += 目标网址.pathname;
    
    const 新网址 = `${协议}://${解析后的网址.hostname}${路径名}${解析后的网址.search}`;
    const 响应 = await fetch(新网址);
    
    const 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });
    新响应.headers.set('X-New-URL', 新网址);
    return 新响应;
}

const 啥啥啥_写的这是啥啊 = atob('ZG14bGMzTT0=');
function 配置信息(UUID, 域名地址) {
    const 协议类型 = atob(啥啥啥_写的这是啥啊);
    let 地址 = 域名地址;
    let 端口 = 443;
    let 传输层安全 = ['tls', true];
    
    if (域名地址.includes('.workers.dev')) {
        地址 = atob('dmlzYS5jbg==');
        端口 = 80;
        传输层安全 = ['', false];
    }
    
    const 威图瑞 = `${协议类型}://${UUID}@${地址}:${端口}?encryption=none&security=${传输层安全[0]}&sni=${域名地址}&fp=randomized&type=ws&host=${域名地址}&path=${encodeURIComponent(path)}${allowInsecure}&fragment=1,40-60,30-50,tlshello#${encodeURIComponent(FileName)}`;
    const 猫猫猫 = `- {name: ${FileName}, server: ${地址}, port: ${端口}, type: ${协议类型}, uuid: ${UUID}, tls: ${传输层安全[1]}, alpn: [h3], udp: false, sni: ${域名地址}, tfo: false, skip-cert-verify: ${SCV}, servername: ${域名地址}, client-fingerprint: randomized, network: ws, ws-opts: {path: "${path}", headers: {Host: ${域名地址}}}}`;
    return [威图瑞, 猫猫猫];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM='));

// 修复点4：使用对象参数重构主函数
async function 生成配置信息({
    userID, 
    hostName, 
    sub, 
    UA, 
    RproxyIP, 
    url: _url, 
    fakeUserID, 
    fakeHostName, 
    env
}) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) sub = match[1];
        const subs = await 整理(sub);
        if (subs.length > 1) sub = subs[0];
    } else if (env.KV) {
        await 迁移地址列表(env);
        const 优选地址列表 = await env.KV.get('ADD.txt');
        if (优选地址列表) {
            const 分类地址 = { 接口地址: new Set(), 链接地址: new Set(), 优选地址: new Set() };
            (await 整理(优选地址列表)).forEach(元素 => {
                if (元素.startsWith('https://')) 分类地址.接口地址.add(元素);
                else if (元素.includes('://')) 分类地址.链接地址.add(元素);
                else 分类地址.优选地址.add(元素);
            });
            addressesapi = [...分类地址.接口地址];
            link = [...分类地址.链接地址];
            addresses = [...分类地址.优选地址];
        }
    }

    if (addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length === 0) {
        const cfips = [
            '103.21.244.0/24', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/14',
            '104.16.0.0/14', '104.24.0.0/15', '141.101.64.0/19', '188.114.96.0/21',
            '190.93.240.0/21', '162.159.152.0/23'
        ];

        function generateRandomIP(cidr) {
            const [base, mask] = cidr.split('/');
            const subnetMask = 32 - parseInt(mask, 10);
            const randomHost = Math.floor(Math.random() * (Math.pow(2, subnetMask) - 1));
            return base.split('.').map((octet, i) => 
                i < 2 ? octet : (parseInt(octet) & (255 << subnetMask)) + (randomHost >> (8 * (2 - i)) & 255)
            ).join('.');
        }

        addresses.push('127.0.0.1:1234#CFnat');
        const randomPorts = hostName.includes("worker") || hostName.includes("notls") ? [...httpPorts, '80'] : [...httpsPorts, '443'];
        
        cfips.forEach((cidr, i) => {
            const ip = generateRandomIP(cidr);
            const port = randomPorts[Math.floor(Math.random() * randomPorts.length)];
            const target = hostName.includes("worker") || hostName.includes("notls") ? addressesnotls : addresses;
            target.push(`${ip}:${port}#CF随机节点${String(i + 1).padStart(2, '0')}`);
        });
    }

    const uuid = _url.pathname === `/${动态UUID}` ? 动态UUID : userID;
    const userAgent = UA.toLowerCase();
    const Config = 配置信息(userID, hostName);
    const [v2ray, clash] = Config;
    
    let proxyhost = "";
    if (hostName.includes(".workers.dev") && (!proxyhosts || proxyhosts.length === 0) && proxyhostsURL) {
        try {
            const response = await fetch(proxyhostsURL);
            if (response.ok) {
                proxyhosts = [...new Set((await response.text()).split('\n').filter(line => line.trim()))];
            }
        } catch (error) {
            console.error('获取地址时出错:', error);
        }
    }
    if (proxyhosts.length > 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";

    if (userAgent.includes('mozilla') && !subParams.some(p => _url.searchParams.has(p))) {
        const newSocks5s = socks5s.map(s => s.includes('@') ? s.split('@')[1] : s.includes('//') ? s.split('//')[1] : s);
        let socks5List = '';
        
        if (go2Socks5s.length > 0 && enableSocks) {
            socks5List = `${enableHttp ? "HTTP" : "Socks5"}${decodeURIComponent('%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
            socks5List += go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg==')) ? 
                `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}<br>` : 
                `<br>&nbsp;&nbsp;${go2Socks5s.join('<br>&nbsp;&nbsp;')}<br>`;
        }

        let 订阅器 = '<br>';
        if (sub) {
            订阅器 += enableSocks ? 
                `CFCDN（访问方式）: ${enableHttp ? "HTTP" : "Socks5"}<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}` : 
                proxyIP && proxyIP !== '' ? 
                    `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>` : 
                    RproxyIP === 'true' ? 
                        `CFCDN（访问方式）: 自动获取ProxyIP<br>` : 
                        `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`;
            订阅器 += `<br>SUB（优选订阅生成器）: ${sub}`;
        } else {
            订阅器 += enableSocks ? 
                `CFCDN（访问方式）: ${enableHttp ? "HTTP" : "Socks5"}<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}` : 
                proxyIP && proxyIP !== '' ? 
                    `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>` : 
                    `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`;
            
            if (env.KV) 订阅器 += ` <a href='${_url.pathname}/edit'>编辑优选列表</a>`;
            订阅器 += `<br>您的订阅内容由 内置 addresses/ADD* 参数变量提供${env.KV ? ` <a href='${_url.pathname}/edit'>编辑优选列表</a>` : ''}<br>`;
            
            if (addresses.length > 0) 订阅器 += `ADD（TLS优选域名&IP）: <br>&nbsp;&nbsp;${addresses.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesnotls.length > 0) 订阅器 += `ADDNOTLS（noTLS优选域名&IP）: <br>&nbsp;&nbsp;${addressesnotls.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesapi.length > 0) 订阅器 += `ADDAPI（TLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesapi.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesnotlsapi.length > 0) 订阅器 += `ADDNOTLSAPI（noTLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesnotlsapi.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressescsv.length > 0) 订阅器 += `ADDCSV（IPTest测速csv文件 限速 ${DLS} ）: <br>&nbsp;&nbsp;${addressescsv.join('<br>&nbsp;&nbsp;')}<br>`;
        }

        if (动态UUID && _url.pathname !== `/${动态UUID}`) 订阅器 = '';
        else 订阅器 += `<br>SUBAPI（订阅转换后端）: ${subProtocol}://${subConverter}<br>SUBCONFIG（订阅转换配置文件）: ${subConfig}`;
        
        const 动态UUID信息 = uuid !== userID ? 
            `TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${userIDLow}<br>${userIDTime}TIME（动态UUID有效时间）: ${有效时间} 天<br>UPTIME（动态UUID更新时间）: ${更新时间} 时（北京时间）<br><br>` : 
            `${userIDTime}`;

        return `<div style="font-size:13px;">${生成配置页面(proxyhost, hostName, uuid, v2ray, clash, 订阅器, 动态UUID信息, userID, UA)}</div>`;
    } else {
        if (typeof fetch !== 'function') return 'Error: fetch is not available in this environment.';

        let newAddressesapi = [], newAddressescsv = [], newAddressesnotlsapi = [], newAddressesnotlscsv = [];
        let noTLS = 'false';
        
        if (hostName.includes(".workers.dev")) {
            noTLS = 'true';
            fakeHostName = `${fakeHostName}.workers.dev`;
            [newAddressesnotlsapi, newAddressesnotlscsv] = await Promise.all([
                整理优选列表(addressesnotlsapi),
                整理测速结果('FALSE')
            ]);
        } else if (hostName.includes(".pages.dev")) {
            fakeHostName = `${fakeHostName}.pages.dev`;
        } else if (hostName.includes("worker") || hostName.includes("notls") || noTLS === 'true') {
            noTLS = 'true';
            fakeHostName = `notls${fakeHostName}.net`;
            [newAddressesnotlsapi, newAddressesnotlscsv] = await Promise.all([
                整理优选列表(addressesnotlsapi),
                整理测速结果('FALSE')
            ]);
        } else {
            fakeHostName = `${fakeHostName}.xyz`;
        }

        let url = sub ? 
            `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID}${atob('JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0')}${RproxyIP}&path=${encodeURIComponent(path)}` : 
            `https://${hostName}/${fakeUserID}${_url.search}${(hostName.includes("worker") || hostName.includes("notls") || noTLS === 'true') ? (_url.search ? '&notls' : '?notls') : ''}`;
        
        let isBase64 = true;

        if (!userAgent.includes('CF-Workers-SUB'.toLowerCase()) && !_url.searchParams.has('b64') && !_url.searchParams.has('base64')) {
            if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((_url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (userAgent.includes('loon') || (_url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            }
        }

        try {
            let content;
            if (!sub && isBase64) {
                content = await 生成本地订阅(fakeHostName, fakeUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
            } else {
                const response = await fetch(url, {
                    headers: { 'User-Agent': UA + atob('IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ==') }
                });
                content = await response.text();
            }

            // 修复点5：确保调用恢复伪装信息时传递所有参数
            return _url.pathname === `/${fakeUserID}` ? content : 恢复伪装信息({
                content,
                userID,
                hostName,
                fakeUserID,
                fakeHostName,
                isBase64
            });
        } catch (error) {
            console.error('Error fetching content:', error);
            return `Error fetching content: ${error.message}`;
        }
    }
}

// ...（剩余的函数保持不变，包括生成配置页面、整理优选列表、整理测速结果等）...

async function 生成本地订阅(host, UUID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
    const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
    addresses = [...new Set([...addresses, ...newAddressesapi, ...newAddressescsv])];
    
    let notlsresponseBody = '';
    if (noTLS === 'true') {
        addressesnotls = [...new Set([...addressesnotls, ...newAddressesnotlsapi, ...newAddressesnotlscsv])];
        notlsresponseBody = addressesnotls.map(address => {
            let [ip, port = "80", remark = ""] = address.match(regex) ? 
                [RegExp.$1, RegExp.$2 || "80", RegExp.$3 || ""] : 
                address.includes('#') ? 
                    address.split('#').map((part, i) => i === 0 ? part.split(':') : part).flat() : 
                    address.split(':');
            
            if (!isValidIPv4(ip) && port === "80") {
                port = httpPorts.find(p => ip.includes(p)) || "80";
            }

            return `${atob(啥啥啥_写的这是啥啊)}://${UUID}@${ip}:${port}?encryption=none&security=&type=ws&host=${host}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`;
        }).join('\n');
    }

    const responseBody = addresses.map(address => {
        let [ip, port = "443", remark = ""] = address.match(regex) ? 
            [RegExp.$1, RegExp.$2 || "443", RegExp.$3 || ""] : 
            address.includes('#') ? 
                address.split('#').map((part, i) => i === 0 ? part.split(':') : part).flat() : 
                address.split(':');
        
        if (!isValidIPv4(ip) && port === "443") {
            port = httpsPorts.find(p => ip.includes(p)) || "443";
        }

        const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(ip));
        let 最终路径 = matchingProxyIP ? `/proxyip=${matchingProxyIP}` : path;
        
        if (proxyhosts.length > 0 && host.includes('.workers.dev')) {
            最终路径 = `/${host}${最终路径}`;
            remark += ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
            host = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
        }

        return `${atob(啥啥啥_写的这是啥啊)}://${UUID}@${ip}:${port}?encryption=none&security=tls&sni=${host}&fp=random&type=ws&host=${host}&path=${encodeURIComponent(最终路径)}${allowInsecure}&fragment=1,40-60,30-50,tlshello#${encodeURIComponent(remark)}`;
    }).join('\n');

    let base64Response = responseBody;
    if (noTLS === 'true') base64Response += `\n${notlsresponseBody}`;
    if (link.length > 0) base64Response += '\n' + link.join('\n');
    return btoa(base64Response);
}

async function 整理(内容) {
    return 内容.replace(/[	|"'\r\n]+/g, ',')
               .replace(/,+/g, ',')
               .replace(/^,|,$/g, '')
               .split(',');
}

async function sendMessage(type, ip, add_data = "") {
    if (!BotToken || !ChatID) return;
    try {
        let msg = "";
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response.ok) {
            const ipInfo = await response.json();
            msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
        } else {
            msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
        }
        return fetch(`https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
            }
        });
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

function isValidIPv4(address) {
    return /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address);
}

async function 生成动态UUID(密钥) {
    const 时区偏移 = 8;
    const 起始日期 = new Date(2007, 6, 7, 更新时间, 0, 0);
    const 一周的毫秒数 = 1000 * 60 * 60 * 24 * 有效时间;

    function 获取当前周数() {
        const 现在 = new Date();
        const 调整后的现在 = new Date(现在.getTime() + 时区偏移 * 60 * 60 * 1000);
        return Math.ceil((Number(调整后的现在) - Number(起始日期)) / 一周的毫秒数);
    }

    async function 生成UUID(基础字符串) {
        const 哈希 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(基础字符串));
        const 十六进制哈希 = Array.from(new Uint8Array(哈希)).map(b => b.toString(16).padStart(2, '0')).join('');
        return `${十六进制哈希.substr(0, 8)}-${十六进制哈希.substr(8, 4)}-4${十六进制哈希.substr(13, 3)}-${(parseInt(十六进制哈希.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${十六进制哈希.substr(18, 2)}-${十六进制哈希.substr(20, 12)}`;
    }

    const 当前周数 = 获取当前周数();
    const 结束时间 = new Date(起始日期.getTime() + 当前周数 * 一周的毫秒数);
    const 到期时间UTC = new Date(结束时间.getTime() - 时区偏移 * 60 * 60 * 1000);
    const 到期时间字符串 = `到期时间(UTC): ${到期时间UTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${结束时间.toISOString().slice(0, 19).replace('T', ' ')}\n`;

    return Promise.all([
        生成UUID(密钥 + 当前周数),
        生成UUID(密钥 + (当前周数 - 1)),
        到期时间字符串
    ]);
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
    const 旧数据 = await env.KV.get(`/${txt}`);
    const 新数据 = await env.KV.get(txt);
    if (旧数据 && !新数据) {
        await env.KV.put(txt, 旧数据);
        await env.KV.delete(`/${txt}`);
        return true;
    }
    return false;
}

async function KV(request, env, txt = 'ADD.txt') {
    try {
        if (request.method === "POST") {
            if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
            try {
                await env.KV.put(txt, await request.text());
                return new Response("保存成功");
            } catch (error) {
                console.error('保存KV时发生错误:', error);
                return new Response("保存失败: " + error.message, { status: 500 });
            }
        }

        const content = env.KV ? await env.KV.get(txt) || '' : '';
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>优选订阅列表</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body { margin: 0; padding: 15px; box-sizing: border-box; font-size: 13px; }
                    .editor-container { width: 100%; max-width: 100%; margin: 0 auto; }
                    .editor { width: 100%; height: 520px; margin: 15px 0; padding: 10px; box-sizing: border-box; 
                             border: 1px solid #ccc; border-radius: 4px; font-size: 13px; line-height: 1.5; 
                             overflow-y: auto; resize: none; }
                    .save-container { margin-top: 8px; display: flex; align-items: center; gap: 10px; }
                    .save-btn, .back-btn { padding: 6px 15px; color: white; border: none; border-radius: 4px; cursor: pointer; }
                    .save-btn { background: #4CAF50; }
                    .save-btn:hover { background: #45a049; }
                    .back-btn { background: #666; }
                    .back-btn:hover { background: #555; }
                    .save-status { color: #666; }
                    .notice-content { display: none; margin-top: 10px; font-size: 13px; color: #333; }
                </style>
            </head>
            <body>
                ################################################################<br>
                ${FileName} 优选订阅列表:<br>
                ---------------------------------------------------------------<br>
                &nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">注意事项∨</a></strong><br>
                <div id="noticeContent" class="notice-content">
                    ${decodeURIComponent(atob('JTA5JTA5JTA5JTA5JTA5JTNDc3Ryb25nJTNFMS4lM0MlMkZzdHJvbmclM0UlMjBBRERBUEklMjAlRTUlQTYlODIlRTYlOUUlOUMlRTYlOTglQUYlRTUlOEYlOEQlRTQlQkIlQTNJUCVFRiVCQyU4QyVFNSU4RiVBRiVFNCVCRCU5QyVFNCVCOCVCQVBST1hZSVAlRTclOUElODQlRTglQUYlOUQlRUYlQkMlOEMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwcm94eWlwJTNEdHJ1ZSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGYWRkcmVzc2VzYXBpLnR4dCUzQ3N0cm9uZyUzRSUzRnByb3h5aXAlM0R0cnVlJTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklM0NzdHJvbmclM0UyLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU5QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJTI3aHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGWElVMiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QlMjclM0VDbG91ZGZsYXJlU3BlZWRUZXN0JTNDJTJGYSUzRSUyMCVFNyU5QSU4NCUyMGNzdiUyMCVFNyVCQiU5MyVFNiU5RSU5QyVFNiU5NiU4NyVFNCVCQiVCNiVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NiciUzRSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCLSUyMCVFNSVBNiU4MiVFOSU5QyU4MCVFNiU4QyU4NyVFNSVBRSU5QTIwNTMlRTclQUIlQUYlRTUlOEYlQTMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwb3J0JTNEMjA1MyUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0Zwb3J0JTNEMjA1MyUzQyUyRnN0cm9uZyUzRSUzQ2JyJTNFJTNDYnIlM0UKJTA5JTA5JTA5JTA5JTA5JTI2bmJzcCUzQiUyNm5ic3AlM0ItJTIwJUU1JUE2JTgyJUU5JTlDJTgwJUU2JThDJTg3JUU1JUFFJTlBJUU4JThBJTgyJUU3JTgyJUI5JUU1JUE0JTg3JUU2JUIzJUE4JUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQi0lMjAlRTUlQTYlODIlRTklOUMlODAlRTYlOEMlODclRTUlQUUlOUElRTUlQTQlOUElRTQlQjglQUElRTUlOEYlODIlRTYlOTUlQjAlRTUlODglOTklRTklOUMlODAlRTglQTYlODElRTQlQkQlQkYlRTclOTQlQTglMjclMjYlMjclRTUlODElOUElRTklOTclQjQlRTklOUElOTQlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGbWFpbiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QuY3N2JTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUzQ3N0cm9uZyUzRSUyNiUzQyUyRnN0cm9uZyUzRXBvcnQlM0QyMDUzJTNDYnIlM0U='))}
                </div>
                <div class="editor-container">
                    ${env.KV ? `
                    <textarea class="editor" 
                        placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}"
                        id="content">${content}</textarea>
                    <div class="save-container">
                        <button class="back-btn" onclick="goBack()">返回配置页</button>
                        <button class="save-btn" onclick="saveContent(this)">保存</button>
                        <span class="save-status" id="saveStatus"></span>
                    </div>
                    <br>
                    ################################################################<br>
                    ${cmad}
                    ` : '<p>未绑定KV空间</p>'}
                </div>
        
                <script>
                if (document.querySelector('.editor')) {
                    let timer;
                    const textarea = document.getElementById('content');
                    const originalContent = textarea.value;
        
                    function goBack() {
                        window.location.href = window.location.href.substring(0, window.location.href.lastIndexOf('/'));
                    }
                    
                    function saveContent(button) {
                        try {
                            const updateButtonText = (step) => button.textContent = \`保存中: \${step}\`;
                            if (!/iPad|iPhone|iPod/.test(navigator.userAgent)) {
                                textarea.value = textarea.value.replace(/：/g, ':');
                            }
                            
                            updateButtonText('开始保存');
                            button.disabled = true;
                            const newContent = textarea.value || '';
                            const originalContent = textarea.defaultValue || '';
                            
                            const updateStatus = (message, isError = false) => {
                                const statusElem = document.getElementById('saveStatus');
                                if (statusElem) {
                                    statusElem.textContent = message;
                                    statusElem.style.color = isError ? 'red' : '#666';
                                }
                            };
                            
                            const resetButton = () => {
                                button.textContent = '保存';
                                button.disabled = false;
                            };
                            
                            if (newContent !== originalContent) {
                                updateButtonText('发送保存请求');
                                fetch(window.location.href, {
                                    method: 'POST',
                                    body: newContent,
                                    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
                                    cache: 'no-cache'
                                })
                                .then(response => {
                                    if (!response.ok) throw new Error(\`HTTP error! status: \${response.status}\`);
                                    updateStatus(\`已保存 \${new Date().toLocaleString()}\`);
                                    document.title = \`编辑已保存 \${new Date().toLocaleString()}\`;
                                })
                                .catch(error => {
                                    console.error('Save error:', error);
                                    updateStatus(\`保存失败: \${error.message}\`, true);
                                })
                                .finally(resetButton);
                            } else {
                                updateStatus('内容未变化');
                                resetButton();
                            }
                        } catch (error) {
                            console.error('保存过程出错:', error);
                            const button = document.querySelector('.save-btn');
                            button.textContent = '保存';
                            button.disabled = false;
                            const statusElem = document.getElementById('saveStatus');
                            if (statusElem) {
                                statusElem.textContent = \`错误: \${error.message}\`;
                                statusElem.style.color = 'red';
                            }
                        }
                    }
        
                    textarea.addEventListener('blur', saveContent);
                    textarea.addEventListener('input', () => {
                        clearTimeout(timer);
                        timer = setTimeout(saveContent, 5000);
                    });
                }
        
                function toggleNotice() {
                    const noticeContent = document.getElementById('noticeContent');
                    const noticeToggle = document.getElementById('noticeToggle');
                    if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
                        noticeContent.style.display = 'block';
                        noticeToggle.textContent = '注意事项∧';
                    } else {
                        noticeContent.style.display = 'none';
                        noticeToggle.textContent = '注意事项∨';
                    }
                }
        
                document.addEventListener('DOMContentLoaded', () => {
                    document.getElementById('noticeContent').style.display = 'none';
                });
                </script>
            </body>
            </html>
        `;

        return new Response(html, {
            headers: { "Content-Type": "text/html;charset=utf-8" }
        });
    } catch (error) {
        console.error('处理请求时发生错误:', error);
        return new Response("服务器错误: " + error.message, {
            status: 500,
            headers: { "Content-Type": "text/plain;charset=utf-8" }
        });
    }
}

async function resolveToIPv6(target) {
    function isIPv4(str) {
        const parts = str.split('.');
        return parts.length === 4 && parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }

    function isIPv6(str) {
        return str.includes(':') && /^[0-9a-fA-F:]+$/.test(str);
    }

    async function fetchIPv4(domain) {
        const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
        });
        if (!response.ok) throw new Error('DNS查询失败');
        const data = await response.json();
        const ipv4s = (data.Answer || []).filter(r => r.type === 1).map(r => r.data);
        if (ipv4s.length === 0) throw new Error('未找到IPv4地址');
        return ipv4s[Math.floor(Math.random() * ipv4s.length)];
    }

    async function queryNAT64(domain) {
        const socket = connect(atob('ZG90Lm5hdDY0LmRrOjg1Mw=='), {
            secureTransport: 'on',
            allowHalfOpen: false
        });
        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        try {
            const query = buildDNSQuery(domain);
            const queryWithLength = new Uint8Array(query.length + 2);
            queryWithLength[0] = query.length >> 8;
            queryWithLength[1] = query.length & 0xFF;
            queryWithLength.set(query, 2);
            await writer.write(queryWithLength);
            return parseIPv6(await readDNSResponse(reader))[0] || '未找到IPv6地址';
        } finally {
            await writer.close();
            await reader.cancel();
        }
    }

    function buildDNSQuery(domain) {
        const buffer = new ArrayBuffer(512);
        const view = new DataView(buffer);
        let offset = 0;

        view.setUint16(offset, Math.floor(Math.random() * 65536)); offset += 2;
        view.setUint16(offset, 0x0100); offset += 2;
        view.setUint16(offset, 1); offset += 2;
        view.setUint16(offset, 0); offset += 6;

        domain.split('.').forEach(label => {
            view.setUint8(offset++, label.length);
            for (let i = 0; i < label.length; i++) {
                view.setUint8(offset++, label.charCodeAt(i));
            }
        });
        view.setUint8(offset++, 0);
        view.setUint16(offset, 28); offset += 2;
        view.setUint16(offset, 1); offset += 2;

        return new Uint8Array(buffer, 0, offset);
    }

    async function readDNSResponse(reader) {
        const chunks = [];
        let totalLength = 0;
        let expectedLength = null;

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            chunks.push(value);
            totalLength += value.length;
            if (expectedLength === null && totalLength >= 2) {
                expectedLength = (chunks[0][0] << 8) | chunks[0][1];
            }
            if (expectedLength !== null && totalLength >= expectedLength + 2) break;
        }

        const fullResponse = new Uint8Array(totalLength);
        let offset = 0;
        chunks.forEach(chunk => {
            fullResponse.set(chunk, offset);
            offset += chunk.length;
        });
        return fullResponse.slice(2);
    }

    function parseIPv6(response) {
        const view = new DataView(response.buffer);
        let offset = 12;
        while (view.getUint8(offset) !== 0) offset += view.getUint8(offset) + 1;
        offset += 5;

        const answers = [];
        const answerCount = view.getUint16(6);
        for (let i = 0; i < answerCount; i++) {
            if ((view.getUint8(offset) & 0xC0) === 0xC0) offset += 2;
            else {
                while (view.getUint8(offset) !== 0) offset += view.getUint8(offset) + 1;
                offset++;
            }

            const type = view.getUint16(offset); offset += 2;
            offset += 6;
            const dataLength = view.getUint16(offset); offset += 2;

            if (type === 28 && dataLength === 16) {
                const parts = [];
                for (let j = 0; j < 8; j++) parts.push(view.getUint16(offset + j * 2).toString(16));
                answers.push(parts.join(':'));
            }
            offset += dataLength;
        }
        return answers;
    }

    try {
        if (isIPv6(target)) return target;
        let domain = isIPv4(target) ? target + atob('LmlwLjA5MDIyNy54eXo=') : await fetchIPv4(target) + atob('LmlwLjA5MDIyNy54eXo=');
        return await queryNAT64(domain);
    } catch (error) {
        console.error('解析错误:', error);
        return `解析失败: ${error.message}`;
    }
}