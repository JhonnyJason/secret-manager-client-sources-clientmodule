clientmodule = {}

############################################################
#region modules
noble = require("noble-ed25519")

tbut = require("./thingybyteutils")
secUtl = require("./secretmanagercryptoutils")
secretmanagerinterface = require("./secretmanagerinterface")
network = require("./network")
Object.assign(network, secretmanagerinterface)

#endregion

############################################################
class Client
    constructor: (@secretKeyHex, @publicKeyHex, @serverURL) ->
        @ready = addNodeId(this)

    updateServerURL: (serverURL) ->
        @serverURL = serverURL
        @ready = addNodeId(this)

    getSecretSpace: ->
        await @ready
        secret = await getSecretSpace(this)
        return await decrypt(secret, @secretKeyHex)

    getSecret: (secretId) ->
        await @ready
        secret = await getSecret(secretId, this)
        return await decrypt(secret, @secretKeyHex)

    getSecretFrom: (secretId, fromId) ->
        await @ready
        secretId = fromId+"."+secretId
        secret = await getSecret(secretId, this)
        return await decrypt(secret, @secretKeyHex)


    setSecret: (secretId, secret) ->
        await @ready
        secret = await encrypt(secret, @publicKeyHex)
        return await setSecret(secretId, secret, this)

    deleteSecret: (secretId) ->
        await @ready
        return await deleteSecret(secretId, this)


    acceptSecretsFrom: (fromId) ->
        await @ready
        return await acceptSecretsFrom(fromId, this)

    stopAcceptSecretsFrom: (fromId) ->
        await @ready
        return await stopAcceptSecretsFrom(fromId, this)


    shareSecretTo: (shareToId, secretId, secret) ->
        await @ready
        secret = await encrypt(secret, shareToId)
        return await shareSecretTo(shareToId, secretId, secret, this)

    deleteSharedSecret: (sharedToId, secretId) ->
        await @ready
        return await deleteSharedSecret(sharedToId, secretId, this)

############################################################
#region internalFunctions

############################################################
#region cryptoHelpers
newSecretBytes = noble.utils.randomPrivateKey

############################################################
decrypt = (content, secretKey) ->
    content = await secUtl.asymetricDecrypt(content, secretKey)
    content = secUtl.removeSalt(content)
    try content = JSON.parse(content) 
    catch err then return content # was no stringified Object


    if content.encryptedContent?
        content = await secUtl.asymetricDecrypt(content, secretKey)
        content = secUtl.removeSalt(content)
        try content = JSON.parse(content)
        catch err then return content # was no stringified Object

    return content

############################################################
encrypt = (content, publicKey) ->
    if typeof content == "object" then content = JSON.stringify(content)
    salt = secUtl.createRandomLengthSalt()    
    content = salt + content

    content = await secUtl.asymetricEncrypt(content, publicKey)
    return JSON.stringify(content)

############################################################
createSignature = (payload, route, secretKeyHex) ->
    content = route+JSON.stringify(payload)
    return await secUtl.createSignature(content, secretKeyHex)

#endregion

############################################################
#region effectiveNetworkCommunication
addNodeId = (client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, timestamp}
    route = "/addNodeId"
    signature = await createSignature(payload, route, secretKey)
    return await network.addNodeId(server, publicKey, timestamp, signature)

############################################################
getSecretSpace = (client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, timestamp}
    route = "/getSecretSpace"
    signature = await createSignature(payload, route, secretKey)
    return await network.getSecretSpace(server, publicKey, timestamp, signature)

getSecret = (secretId, client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, secretId, timestamp}
    route = "/getSecret"
    signature = await createSignature(payload, route, secretKey)
    return await network.getSecret(server, publicKey, secretId, timestamp, signature)

############################################################
setSecret = (secretId, secret, client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, secretId, secret, timestamp}
    route = "/setSecret"
    signature = await createSignature(payload, route, secretKey)
    return await network.setSecret(server, publicKey, secretId, secret, timestamp, signature)

deleteSecret = (secretId, client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, secretId, timestamp}
    route = "/deleteSecret"
    signature = await createSignature(payload, route, secretKey)
    return await network.deleteSecret(server, publicKey, secretId, timestamp, signature)

############################################################
acceptSecretsFrom = (fromId, client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, fromId, timestamp}
    route = "/startAcceptingSecretsFrom"
    signature = await createSignature(payload, route, secretKey)
    return await network.startAcceptingSecretsFrom(server, publicKey, fromId, timestamp, signature)

stopAcceptSecretsFrom = (fromId, client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, fromId, timestamp}
    route = "/stopAcceptingSecretsFrom"
    signature = await createSignature(payload, route, secretKey)
    return await network.stopAcceptingSecretsFrom(server, publicKey, fromId, timestamp, signature)

############################################################
shareSecretTo = (shareToId, secretId, secret, client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, shareToId, secretId, secret, timestamp}
    route = "/shareSecretTo"
    signature = await createSignature(payload, route, secretKey)
    return await network.shareSecretTo(server, publicKey, shareToId, secretId, secret, timestamp, signature)

deleteSharedSecret = (sharedToId, secretId, client) ->
    server = client.serverURL
    publicKey = client.publicKeyHex
    secretKey = client.secretKeyHex
    timestamp = ""
    payload = {publicKey, sharedToId, secretId, timestamp}
    route = "/deleteSharedSecret"
    signature = await createSignature(payload, route, secretKey)
    return await network.deleteSharedSecret(server, publicKey, sharedToId, secretId, timestamp, signature)


#endregion

#endregion

############################################################
clientmodule.createClient = (secretKeyHex, publicKeyHex, serverURL) ->
    if !secretKeyHex
        secretKeyHex = tbut.bytesToHex(newSecretBytes())
        publicKeyHex = await noble.getPublicKey(secretKeyHex)
    if !publicKeyHex
        publicKeyHex = await noble.getPublicKey(secretKeyHex)
    return new Client(secretKeyHex, publicKeyHex, serverURL)

module.exports = clientmodule