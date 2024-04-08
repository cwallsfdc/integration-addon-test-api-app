const fp = require('fastify-plugin');
const jwt= require('jsonwebtoken');
const path = require('node:path');

// Customer-provided configuration
const REQUIRED_ORG_ID_18_CONFIG_VAR_NAME = 'ORG_ID_18';
const REQUIRED_ENCODED_PRIVATE_KEY_CONFIG_VAR_NAME = 'ENCODED_PRIVATE_KEY';
const REQUIRED_PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME = 'PRIVATE_KEY_FILEPATH';
const REQUIRED_CONSUMER_KEY_CONFIG_VAR_NAME = 'CONSUMER_KEY';

// For dev only
const OVERRIDE_ACCESS_TOKEN_CONFIG_VAR_NAME = 'OVERRIDE_ACCESS_TOKEN';
const OVERRIDE_IGNORE_INVALID_ORG_ID_CONFIG_VAR_NAME = 'OVERRIDE_IGNORE_INVALID_ORG_ID';
const OVERRIDE_SF_AUDIENCE_CONFIG_VAR_NAME = 'OVERRIDE_SF_AUDIENCE';
const OVERRIDE_MINT_TOKEN_CONFIG_VAR_NAME = 'OVERRIDE_MINT_TOKEN';

// Headers
const HEADER_REQUEST_ID = 'x-request-id';
const HEADER_REQUEST_CONTEXT = 'x-request-context';
const HEADER_ORG_CONTEXT = 'x-org-context';
const HEADER_EXTRA_INFO = 'x-extra-info';
const HEADER_ORG_ID_18 = 'x-org-id-18';

// Other constants
const SANDBOX_AUDIENCE_URL = 'https://test.salesforce.com';
const PROD_AUDIENCE_URL = 'https://login.salesforce.com';

/**
 * Generic error thrower setting status code.
 *
 * @param msg
 * @param statusCode
 * @param requestId
 */
function throwError(msg, statusCode, requestId) {
    if (requestId) {
        msg = `[${this.requestId}] ${msg}`;
    }
    const err = new Error(msg);
    err.statusCode = statusCode;
    throw err;
}

/**
 * Encapsulates proxy config.
 */
class Config {
    constructor(env) {
        this.env = env;
    }

    initialize() {
        // Org config
        this.orgId18 = this.env[REQUIRED_ORG_ID_18_CONFIG_VAR_NAME];
        const encodedPrivateKey = this.env[REQUIRED_ENCODED_PRIVATE_KEY_CONFIG_VAR_NAME];
        if (encodedPrivateKey) {
            this.privateKey = Buffer.from(encodedPrivateKey, 'base64').toString('utf8');
        } else if (this.env[REQUIRED_PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME]) {
            this.privateKey = readFileSync(this.env[REQUIRED_PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME]);
        }
        this.clientId = this.env[REQUIRED_CONSUMER_KEY_CONFIG_VAR_NAME];

        // For dev only
        this.overrideAccessToken = this.env[OVERRIDE_ACCESS_TOKEN_CONFIG_VAR_NAME];
        this.overrideAudience = this.env[OVERRIDE_SF_AUDIENCE_CONFIG_VAR_NAME];
        this.overrideIgnoreInvalidOrgId = this.env[OVERRIDE_IGNORE_INVALID_ORG_ID_CONFIG_VAR_NAME];
        this.overrideMintToken = this.env[OVERRIDE_MINT_TOKEN_CONFIG_VAR_NAME];

        return this;
    }

    validate() {
        const validateRequiredConfig = (name, value) => {
            if (!value) {
                throw Error(`Required config ${name} not found`);
            }
        }

        validateRequiredConfig(REQUIRED_ORG_ID_18_CONFIG_VAR_NAME, this.orgId18);
        validateRequiredConfig(`${REQUIRED_ENCODED_PRIVATE_KEY_CONFIG_VAR_NAME} or ${REQUIRED_PRIVATE_KEY_FILEPATH_CONFIG_VAR_NAME}`,
            this.privateKey);
        validateRequiredConfig(REQUIRED_CONSUMER_KEY_CONFIG_VAR_NAME, this.clientId);

        return this;
    }
}

/**
 * Base context providing utilities for extending classes.
 */
class BaseContext {

    constructor(request, config) {
        this.request = request;
        this.logger = this.request.log;
        this.requestId = this.request.headers[HEADER_REQUEST_ID];
        if (!this.requestId) {
            throwError(`${HEADER_REQUEST_ID} not found`, 400);
        }
        this.config = config;
    }

    decodeAndParse(encodedContext) {
        const decodedContext = Buffer.from(encodedContext, 'base64').toString('utf8');
        return JSON.parse(decodedContext);
    }
}
/**
 * Header 'x-request-context': function request context.
 *
 * Eg:
 *  {
 *     'id': '00Dxx0000006IYJEA2-4Y4W3Lw_LkoskcHdEaZze-uuid-integration-addon-test-api-app-2023-03-23T15:18:53.429-0700',
 *     'appName': 'integration-addon-test-api-app',
 *     'resource': 'https://...',
 *     'source': 'urn:event:from:salesforce/<instance>/<orgId>/<platform origin, eg apex>',
 *     'requestTime': '2023-03-23T15:18:53.429-0700',
 *     'permissionSets': [ 'MyPermissionSet' ]
 *   }
 */
class RequestContext extends BaseContext {

    constructor(request, config) {
        super(request, config);
        this.requestContext = {};
    }

    initialize(encodedContext) {
        try {
            this.requestContext = super.decodeAndParse(encodedContext);
        } catch (err) {
            throwError(`Invalid ${HEADER_REQUEST_CONTEXT} format - expected base64 encoded header: ${err.message}`, 400, this.requestId);
        }

        this.permissionSets = this.requestContext.permissionSets;
        this.parseAuthorizationHeader();

        // For SDK
        this.id = this.requestId;
        this.datacontenttype = this.request.headers['ce-datacontenttype'];
        this.data = this.request.body;
        this.schemaurl = '';
        this.source = this.request.headers['ce-source'];
        // FIXME: Get time of request
        this.time = new Date().getTime();
    }

    /**
     * Expected headers:
     *  - authorization
     *  - x-request-id: request id generated by client that tracks the entire request/response
     *  - x-request-context: context of function request
     *  - x-org-context: Salesforce context - context of invoking Organization
     */
    parseAuthorizationHeader() {
        const headers = this.request.headers;

        if (!headers.authorization) { // TODO: Regex validate
            throwError('Authorization not found', 400, this.requestId);
        }
        if (!headers.authorization.startsWith('Bearer ')) {
            throwError('Invalid Authorization', 400, this.requestId);
        }

        let accessToken = headers.authorization.substring(headers.authorization.indexOf(' ') + 1);
        if (!accessToken) {
            throwError('Authorization accessToken not found', 400, this.requestId);
        }

        if (this.config.overrideAccessToken) {
            this.logger.info(`[${this.requestId}] !!! Overriding Authorization token`);
            accessToken = this.config.overrideAccessToken;
        }

        this.accessToken = accessToken;

        this.logger.info(`[${this.requestId}] Validated request headers - looks good`);
    }

    validate() {
        if (!this.accessToken) {
            throwError('Authorization accessToken not found', 400, this.requestId);
        }

        if (this.permissionSets && !Array.isArray(this.permissionSets)) {
            throwError('Expected array of Permission Sets', 400, this.requestId);
        }
    }

    toJsonEncoded() {
        return Buffer.from(JSON.stringify(this), 'utf8').toString('base64');
    }
}

/**
 * 'userContext' part of header 'x-org-context'.
 *
 *  Eg:
 *  {
 *      'userId': '005xx000001X8Uz',
 *      'username': 'admin@example.com',
 *   }
 */
class UserContext extends BaseContext {

    constructor(request, config) {
        super(request, config);
    }

    initialize(userContext) {
        this.username = userContext.username;
        this.userId = userContext.userId;

        // For SDK
        this.id = userContext.userId;
    }

    validate() {
        if (!this.username) {
            throwError('Username not provided', 400, this.requestId);
        }

        if (!this.userId) {
            throwError('UserId not provided', 400, this.requestId);
        }
    }
}

/**
 * Header 'x-org-context': Contexts of the requesting Organization and user.
 *
 * Eg:
 *  {
 *     'apiVersion': '57.0',
 *     'namespace': '',
 *     'orgId': '00Dxx0000006IYJ',
 *     'orgDomainUrl': 'https://mycompany.my.salesforce.com',
 *     'payloadVersion': '0.1',
 *     'salesforceBaseUrl': 'https://na1.salesforce.com',
 *     'userContext': ...UserContext...
 *   }
 */
class OrgContext extends BaseContext {

    constructor(request, config) {
        super(request, config);
    }

    initialize(encodedContext) {
        try {
           this.orgContext = super.decodeAndParse(encodedContext);
        } catch (err) {
            throwError(`Invalid ${HEADER_ORG_CONTEXT} format - expected base64 encoded header: ${err.message}`, 400, this.requestId);
        }
        this.apiVersion = this.orgContext.apiVersion;
        this.namespace = this.orgContext.namespace;
        this.orgId = this.orgContext.orgId;
        this.orgDomainUrl = this.orgContext.orgDomainUrl;
        this.salesforceBaseUrl = this.orgContext.salesforceBaseUrl;
        this.userContext = new UserContext(this.request, this.config);
        this.userContext.initialize(this.orgContext.userContext);

        // For SDK
        this.salesforceApiVersion = this.apiVersion;
    }

    validate() {
        if (!this.apiVersion) {
            throwError('API Version not provided', 400, this.requestId);
        }

        if (!this.orgId) {
            throwError('Organization ID not provided', 400, this.requestId);
        }

        if (!this.orgDomainUrl) {
            throwError(`OrgDomainUrl not provided`, 400, this.requestId);
        }

        if (!this.salesforceBaseUrl) {
            throwError(`SalesforceBaseUrl not provided`, 400, this.requestId);
        }

        if (!this.userContext) {
            throwError('UserContext not provided', 400, this.requestId);
        }

        this.userContext.validate();
    }
}

/**
 * Handles HTTP requests.
 */
class HttpRequestUtil {


    async request(url, opts, json = true) {
        if (!this.got) {
            const got = await import(path.join('../node_modules/got/dist/source/index.js'));
            this.got = got.got;
        }
        return json ? await this.got(url, opts).json() : await this.got(url, opts);
    }
}

/**
 * Base request handler providing common sync and async handling.
 */
class RequestHandler {

    constructor(config, request, reply) {
        this.config = config;
        this.request = request;
        this.reply = reply;
        this.requestId = this.request.headers[HEADER_REQUEST_ID];
        if (!this.requestId) {
            throwError(`${HEADER_REQUEST_ID} not found`, 400);
        }
        this.requestContext = new RequestContext(request, this.config);
        this.orgContext = new OrgContext(request, this.config);
        this.logger = this.request.log;
        this.httpRequestUtil = new HttpRequestUtil();
    }

    /**
     * Handle sync function request.
     *
     * @returns {Promise<void>}
     */
    async handle() {
        this.logger.info(`[${this.requestId}] Handling app request...`);

        // Parse request initializing expected request and org contexts
        this.initializeContexts();

        // Validate that the context's orgId matches the accessToken
        await this.validateInvokingOrg();

        // Enrich request w/ per-app accessToken and such
        await this.enrich();

        this.logger.info(`[${this.requestId}] Pre-processed request, off to app...`);
    }

    /**
     * Parse and validate 'x-request-context' and 'x-org-context' headers.
     */
    initializeContexts() {
        const headers = this.request.headers;

        // Request context
        const encodedRequestContextHeader = headers[HEADER_REQUEST_CONTEXT];
        if (!encodedRequestContextHeader) {
            throwError(`Request context header ${HEADER_REQUEST_CONTEXT} not found`, 400, this.requestId);
        }
        this.requestContext.initialize(encodedRequestContextHeader);
        this.requestContext.validate();

        // Org context
        const encodedOrgContextHeader = headers[HEADER_ORG_CONTEXT];
        if (!encodedOrgContextHeader) {
            throwError(`Org context header ${HEADER_ORG_CONTEXT} not found`, 400, this.requestId);
        }
        this.orgContext.initialize(encodedOrgContextHeader);
        this.orgContext.validate();

        this.logger.info(`[${this.requestId}] Initialized contexts - well done`);
    }

    /**
     * Assemble Salesforce API URI part.
     *
     * @param baseUrl
     * @param apiVersion
     * @param uriPart
     * @returns {string}
     */
    assembleSalesforceAPIUrl(baseUrl, apiVersion, uriPart) {
        return `${baseUrl}/services/data/v${apiVersion}${uriPart}`;
    }

    /**
     * Assemble Salesforce API Headers.
     *
     * @param accessToken
     * @returns {{Authorization: string, "Content-Type": string}}
     */
    assembleSalesforceAPIHeaders(accessToken) {
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        };
    }

    /**
     * Validate that requesting Organization is expected Organization (orgId18) by using given token to verify Organization info
     * provided by /userinfo API.
     *
     * Alternative approach that is simpler and efficient, but may not be as secure is to validate a
     * key sent by the client.
     *
     */
    async validateInvokingOrg() {
        const orgDomainUrl = this.orgContext.orgDomainUrl;
        const accessToken = this.requestContext.accessToken;
        const url = `${orgDomainUrl}/services/oauth2/userinfo`;
        const opts = {
            method: 'GET',
            headers: this.assembleSalesforceAPIHeaders(accessToken),
            retry: {
                limit: 1
            }
        };

        // Get Org's info via /userinfo API
        let userInfo;
        try {
            userInfo = await this.httpRequest(url, opts);
        } catch (err) {
            throwError(`Unable to validate request (/userinfo): ${err.message}`, this.requestId);
        }

        if (!userInfo || this.config.orgId18 !== userInfo.organization_id) {
            if (this.config.overrideIgnoreInvalidOrgId) {
                this.logger.info(`[${this.requestId}] Ignoring invalid org - invoking from Organization ${userInfo.organization_id}, expected ${this.config.orgId18}`);
            } else {
                this.logger.warn(`Unauthorized invoker from Organization ${userInfo.organization_id}, expected ${this.config.orgId18}`);
                throwError('Unauthorized request', 401, this.requestId);
            }
        }

        this.logger.info(`[${this.requestId}] Validated client - good to go`);
    }

    /**
     * Mint and return function's token for requesting user using configured Connected App.
     *
     * If applicable, activate provided session-based Permission Set(s) to token.
     *
     * TODO: Consider caching tokens for given signature: user, connected app, session-based Permission(s).  If cached,
     *       use /services/oauth2/introspect to determine token validity (eg, timeout).
     *
     * @returns {Promise<Void>}
     */
    async mintToken() {
        if (this.config.overrideMintToken && this.config.overrideAccessToken) {
            this.logger.info(`[${this.requestId}] !!! Overriding token minting.`);
            return;
        }

        const userContext = this.orgContext.userContext;
        const url = `${userContext.orgDomainUrl}/services/oauth2/token`;
        const isTest = (url.includes('.sandbox.') || url.includes('.scratch.'));

        let audience = isTest ? SANDBOX_AUDIENCE_URL : PROD_AUDIENCE_URL;
        if (this.config.overrideAudience) {
            audience = this.config.overrideAudience;
            this.logger.info(`[${this.requestId}] !!! Overriding audience w/ ${audience}`);
        }

        const jwtOpts = {
            issuer: this.config.clientId,
            audience,
            algorithm: 'RS256',
            expiresIn: 360,
        }

        const signedJWT = jwt.sign({prn: userContext.username}, this.config.privateKey, jwtOpts);
        const opts = {
            method: 'POST',
            headers: {
                'content-type': 'application/x-www-form-urlencoded'
                // content-length set by request API
            },
            form: {
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': signedJWT
            },
            retry: {
                limit: 1
            }
        };

        // Mint!
        this.logger.info(`[${this.requestId}] Minting function ${isTest ? 'test ' : ' '}token for user ${userContext.username}, audience ${jwtOpts.audience}, url ${url}, issuer ${jwtOpts.issuer.substring(0, 5)}...`);
        let mintTokenResponse;
        try {
            mintTokenResponse = await this.httpRequest(url, opts);
        } catch (err) {
            let errMsg;
            if (err.response) {
                const errResponse = JSON.parse(err.response.body);
                errMsg = `Unable to mint function token: ${errResponse.error} (${errResponse.error_description})`;
                if (errMsg.includes('invalid_app_access') || errMsg.includes('user hasn\'t approved this consumer')) {
                    errMsg += `. Ensure that the target Connected App is set to "Admin approved users are pre-authorized" and user ${orgContext.userContext.username} is assigned to Connected App via a Permission Set`;
                }
            } else {
                errMsg = err.message;
            }

            this.logger.error(errMsg);
            throwError(errMsg, 403, this.requestId);
        }

        this.requestContext.accessToken(mintTokenResponse.access_token);

        this.logger.info(`[${this.requestId}] Minted app's token - hooray`);
    }

    /**
     * Activate session-based Permission Sets, if applicable.
     *
     * @returns {Promise<void>}
     */
    async activateSessionPermSet() {
        const permissionSets = this.requestContext.permissionSets;
        if (!permissionSets || permissionSets.length === 0) {
            this.logger.info(`[${this.requestId}] Skipping session-based Permission Sets activation`);
            return;
        }

        // Assemble /activateSessionPermSet API body
        const inputs = [];
        permissionSets.forEach(permissionSet => {
            if (permissionSet.includes('__')) {
                inputs.push({
                    PermSetNamespace: permissionSet.substring(0, permissionSet.indexOf('__')),
                    PermSetName: permissionSet.substring(permissionSet.indexOf('__') + 2)
                });
            } else {
                inputs.push({PermSetName: permissionSet});
            }
        });
        this.logger.debug(`[${this.requestId}] POST /actions/standard/activateSessionPermSet: ${JSON.stringify(inputs)}`);

        const url = this.assembleSalesforceAPIUrl(this.orgContext.orgDomainUrl,
            this.orgContext.apiVersion,
            '/actions/standard/activateSessionPermSet');
        const opts = {
            method: 'POST',
            headers: this.assembleSalesforceAPIHeaders(this.requestContext.accessToken),
            json: {inputs: inputs},
            retry: {
                limit: 1
            }
        }

        // Activate!
        let activations;
        try {
            activations = await this.httpRequest(url, opts);
        } catch (err) {
            let errMsg = err.response ? err.response.body : err.message;
            try {
                const errResponses = JSON.parse(errMsg);
                if (errResponses && errResponses.length > 0) {
                    const errMsgs = [];
                    // FIXME: Do array collect or whatever
                    errResponses.forEach(errResponse => errResponse.errors.forEach(error => errMsgs.push(`${error.message} [${error.statusCode}]`)));
                    errMsg = errMsgs.join('; ')
                }
            } catch (parseErr) {
                // ignore
            }
            this.logger.error(errMsg);
            throwError(errMsg, err.statusCode || 503, this.requestId);
        }

        const failedActivations = activations.filter(activation => !activation.isSuccess);
        if (failedActivations && failedActivations.length > 0) {
            // TODO: If available, include failed PermissionSet names from response
            throwError(`Unable to activate session-based Permission Set(s) ${permissionSets.join(', ')}: ${JSON.stringify(failedActivations.map(failedActivation => failedActivation.errors))}`, 503, this.requestId);
        } else {
            this.logger.info(`[${this.requestId}] Activated session-based Permission Set(s): ${permissionSets.join(', ')} - yessir`);
        }
    }

    /**
     * Enrich request with function's accessToken activating session-based Permission Sets, if applicable.
     *
     * @returns {Promise<void>}
     */
    async enrich() {
        // Mint token with configured Connected App
        await this.mintToken();

        // Activate session-based Permission Sets, if applicable
        await this.activateSessionPermSet();

        this.logger.info(`[${this.requestId}] Enriched request - here we go!`);
    }

    async httpRequest(url, opts, json = true) {
        if (url.includes('localhost')) {
            opts.https = { 'rejectUnauthorized': false };
        }
        return await this.httpRequestUtil.request(url, opts, json);
    }
}

// Do on server start up
const config = new Config(process.env);
config.initialize().validate();
const customAsyncHandlers = {};

module.exports = fp(async function (fastify, opts) {

    // Request handler
    fastify.decorateRequest('salesforce', '');

    // Enrich request with Salesforce context
    const salesforcePreHandler = async (request, reply) => {
        const requestHandler = new RequestHandler(config, request, reply);
        await requestHandler.handle();

        requestHandler.orgContext.userContext = {
            orgId: requestHandler.orgContext.orgId,
            salesforceBaseUrl: requestHandler.orgContext.salesforceBaseUrl,
            orgDomainUrl: requestHandler.orgContext.orgDomainUrl,
            userId: requestHandler.orgContext.userContext.userId,
            username: requestHandler.orgContext.userContext.username,
            onBehalfOfUserId: ''
        };
        const salesforceFunctionsCloudEvent = {
            'cloudEvent': requestHandler.requestContext,
            'sfContext': requestHandler.orgContext,
            'sfFunctionContext': requestHandler.requestContext
        };

        // FIXME
        const sfEvent = await import(path.join('../node_modules/@heroku/sf-fx-runtime-nodejs/dist/sdk/invocation-event.js'));
        const orgContext = await import(path.join('../node_modules/@heroku/sf-fx-runtime-nodejs/dist/sdk/context.js'));

        request.salesforce = {
            event: new sfEvent.InvocationEventImpl(salesforceFunctionsCloudEvent),
            context: new orgContext.ContextImpl(salesforceFunctionsCloudEvent, requestHandler.orgContext),
            logger: request.log
        }
    }

    // Async handler
    const asyncHandler = async (request, reply)=> {
        request.log(`Async response for ${request.method} ${request.routeOptions.url}`);
        reply.code(201);
    };

    fastify.addHook('onRoute', (routeOptions) => {
        if (routeOptions.config && routeOptions.config.salesforce && routeOptions.config.salesforce.managed === false) {
            console.log(`${routeOptions.method} ${routeOptions.routePath} - not applying Salesforce mgmt route`);
            // Not handling
            return;
        }

        if (!routeOptions.preHandler) {
            routeOptions.preHandler = [salesforcePreHandler];
            console.log(`${routeOptions.method} ${routeOptions.routePath} - set Salesforce preHandler to route`);
        } else if (Array.isArray(routeOptions.preHandler)) {
            routeOptions.preHandler.push(salesforcePreHandler);
            console.log(`${routeOptions.method} ${routeOptions.routePath} - set Salesforce preHandler[] to route`);
        }

        if (routeOptions.config && routeOptions.config.salesforce && routeOptions.config.salesforce.async === true) {
            const customAsyncHandler = routeOptions.handler;
            routeOptions.handler = asyncHandler;
            customAsyncHandlers[`${routeOptions.method} ${routeOptions.routePath}`] = customAsyncHandler;
            fastify.addHook('onResponse', async (request, reply) => {
                const routeIdx = `${request.method} ${request.routeOptions.url}`;
                if (request.salesforce && request.salesforce.asyncComplete === true) {
                    request.log.info(`${routeIdx} is async complete`);
                    return;
                }

                const customAsyncHandler = customAsyncHandlers[`${routeIdx}`];
                if (customAsyncHandler) {
                    request.log.info(`Found async handle for route index ${routeIdx}`);
                    await customAsyncHandler(request, reply);
                    request.salesforce.asyncComplete = true;
                    request.log.info(`Set async ${routeIdx} completes`);
                }
            });
            console.log(`${routeOptions.method} ${routeOptions.routePath} - set Salesforce async handler to route`);
        }
    });
});