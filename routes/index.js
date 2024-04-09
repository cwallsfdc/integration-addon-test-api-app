'use strict'


module.exports = async function (fastify, opts) {
    /**
     * Return 'Wassup <given name>' message
     */
    fastify.get('/hello', {config: {salesforce: {managed: false}}}, async function (request, reply) {
        return `Wassup ${request.body.name}!`;
    });

    // DIRECT copy of function source
    const copyPasteFunctionCode = async (event, context, logger) => {
        logger.info(
            `Invoking Account API with payload ${JSON.stringify(
                event.data || {}
            )}`
        );

        const count = event.data.count ? event.data.count : 2;
        const query = `SELECT Id, Name FROM Account LIMIT ${count}`;
        const results = await context.org.dataApi.query(query);
        logger.info(JSON.stringify(results));

        return results.records.map(record => record.fields);
    }

   /**
    * Return Accounts given count to retrieve.
    */
    fastify.post('/accounts', async function (request, reply) {
        const event = request.salesforce.event;
        const context = request.salesforce.context;
        const logger = request.salesforce.logger;

        return await copyPasteFunctionCode(event, context, logger);
    });

    /**
     * Worker invoked to retrieve Accounts from specified connection (org).
     */
    fastify.get('/accounts', {config: {salesforce: {managed: false}}}, async function (request, reply) {

        // 1. Get connection token via add-on API
        const integrationApi = request.heroku.integration;
        const accessToken = integrationApi.getToken(process.env['ORG_CONNECTION']);

        // 2. Query org for Accounts

        return [];
    });

   /**
    * Receives a payload containing Account, Contact, and Case details and uses the
    * Unit of Work pattern to assign the corresponding values to to its Record
    * while maintaining the relationships. It then commits the unit of work and
    * returns the Record Id's for each object.
    */
    fastify.post('/unitofwork', {config: {salesforce: {async: true}}}, async function (request, reply) {
        const event = request.salesforce.event;
        const context = request.salesforce.context;
        const logger = request.log;

        logger.info(
            `Invoking Account-Contact-Case API (UnitOfWork) with payload ${JSON.stringify(
                event.data || {}
            )}`
        );

        const validateField = (field, value) => {
            if (!value) throw new Error(`Please provide ${field}`);
        }

        // Validate Input
        const payload = event.data;
        validateField('accountName', payload.accountName);
        validateField('lastName', payload.lastName);
        validateField('subject', payload.subject);

        // Create a unit of work that inserts multiple objects.
        const uow = context.org.dataApi.newUnitOfWork();

        // Register a new Account for Creation
        const accountId = uow.registerCreate({
            type: 'Account',
            fields: {
                Name: payload.accountName
            }
        });

        // Register a new Contact for Creation
        const contactId = uow.registerCreate({
            type: 'Contact',
            fields: {
                FirstName: payload.firstName,
                LastName: payload.lastName,
                AccountId: accountId // Get the ReferenceId from previous operation
            }
        });

        // Register a new Case for Creation
        const serviceCaseId = uow.registerCreate({
            type: 'Case',
            fields: {
                Subject: payload.subject,
                Description: payload.description,
                Origin: 'Web',
                Status: 'New',
                AccountId: accountId, // Get the ReferenceId from previous operation
                ContactId: contactId // Get the ReferenceId from previous operation
            }
        });

        // Register a follow up Case for Creation
        const followupCaseId = uow.registerCreate({
            type: 'Case',
            fields: {
                ParentId: serviceCaseId, // Get the ReferenceId from previous operation
                Subject: 'Follow Up',
                Description: 'Follow up with Customer',
                Origin: 'Web',
                Status: 'New',
                AccountId: accountId, // Get the ReferenceId from previous operation
                ContactId: contactId // Get the ReferenceId from previous operation
            }
        });

        try {
            // Commit the Unit of Work with all the previous registered operations
            const response = await context.org.dataApi.commitUnitOfWork(uow);
            // Construct the result by getting the Id from the successful inserts
            return {
                accountId: response.get(accountId).id,
                contactId: response.get(contactId).id,
                cases: {
                    serviceCaseId: response.get(serviceCaseId).id,
                    followupCaseId: response.get(followupCaseId).id
                }
            };
        } catch (err) {
            const errorMessage = `Failed to insert record. Root Cause : ${err.message}`;
            logger.error(errorMessage);
            throw new Error(errorMessage);
        }
    });
}
