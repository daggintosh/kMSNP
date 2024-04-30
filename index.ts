import * as tcp from 'net'
import * as tls from 'tls'
import { readFileSync } from 'fs'

const server = tcp.createServer().listen(1863, '0.0.0.0')

enum SenderType {
    Server = " [SERVER]",
    Client = " [Client]",
    None = ""
}

enum SecurityLevel {
    Insecure = "[TCP]",
    Secure = "[TLS]"
}

function Logger(senderType: SenderType, securityLevel: SecurityLevel, message: String): void {
    console.log(`${securityLevel}${senderType} ${message}`);
}

server.on('connection', socket => {
    Logger(SenderType.Client, SecurityLevel.Insecure, "New socket connection")

    socket.on('data', data => {
        var rawstringData = data.toString().split('\r\n')[0]
        Logger(SenderType.Client, SecurityLevel.Insecure, rawstringData)
        var stringData = rawstringData.split(" ")

        var requestType = stringData[0]
        var transaction = stringData[1]
        var returnString = ""
        switch (requestType) {
            case "VER":
                returnString = `VER ${transaction} MSNP14 MSNP13 CVR0`
                break
            case "CVR":
                returnString = `CVR ${transaction} 7.0.2 7.0.2 7.0.2 http://example.com http://example.com`
                break
            case "USR":
                returnString = `USR ${transaction} TWN S TWEENER`
                break
            default:
                returnString = "UNIMPLEMENTED"
                break
        }
        Logger(SenderType.Client, SecurityLevel.Insecure, returnString)
        socket.write(returnString + "\r\n")
    })
})

server.on('listening', () => {
    Logger(SenderType.None, SecurityLevel.Insecure, "TCP server listening on 1863")
})

const secureServer = tls.createServer({
    secureProtocol: "TLSv1_method",
    ciphers: "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:SEED-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5:@SECLEVEL=0",
    cert: readFileSync('cert.pem'),
    key: readFileSync('key.pem'),
    enableTrace: true
}).listen(443, '0.0.0.0')

secureServer.on('tlsClientError', err => {
    console.error(err)
})

secureServer.on('listening', () => {
    Logger(SenderType.None, SecurityLevel.Secure, "TLS server listening on 443")
})