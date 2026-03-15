const { app } = require('@azure/functions');

// per login
const crypto = require('crypto');
const zlib = require('zlib');

// per acs
const { DOMParser } = require('@xmldom/xmldom');
const xpath = require('xpath');

const entra_logout = "https://login.microsoftonline.com/063018e7-e41f-494c-8ace-5dd5451b0d2e/saml2"
const entra_login =  "https://login.microsoftonline.com/063018e7-e41f-494c-8ace-5dd5451b0d2e/saml2"
const entra_id = "https://sts.windows.net/063018e7-e41f-494c-8ace-5dd5451b0d2e/"


const sp_entity_id = "https://entapp-hdd6a2endkancqh5.italynorth-01.azurewebsites.net";
const sp_acs       = "https://entapp-hdd6a2endkancqh5.italynorth-01.azurewebsites.net/api/acs"


// Memoria in-process per correlare AuthnRequest -> Response
// OK per PoC, non per produzione.
const pendingRequests = new Map();

// login
function generateSamlRequestId() {
  // Microsoft Entra richiede che l'ID non inizi con un numero
  return 'id' + crypto.randomUUID().replace(/-/g, '');
}

//login
function buildAuthnRequest({ id, issueInstant, acsUrl, issuer }) {
  return `
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="${id}"
    Version="2.0"
    IssueInstant="${issueInstant}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="${acsUrl}">
    <saml:Issuer>${issuer}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true" />
</samlp:AuthnRequest>`.trim();
}

function encodeForRedirectBinding(xml) {
  // Redirect binding: raw DEFLATE -> Base64 -> URL encode
  const deflated = zlib.deflateRawSync(Buffer.from(xml, 'utf8'));
  return encodeURIComponent(deflated.toString('base64'));
}

function parseFormUrlEncoded(rawBody) {
  return Object.fromEntries(new URLSearchParams(rawBody));
}

function decodeBase64Xml(base64Value) {
  return Buffer.from(base64Value, 'base64').toString('utf8');
}

function getSelector() {
  return xpath.useNamespaces({
    samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
    saml:  'urn:oasis:names:tc:SAML:2.0:assertion'
  });
}

function extractSamlFields(xml) {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const select = getSelector();

  const responseStatus = select('string(/samlp:Response/samlp:Status/samlp:StatusCode/@Value)', doc);
  const responseDestination = select('string(/samlp:Response/@Destination)', doc);
  const inResponseTo = select('string(/samlp:Response/@InResponseTo)', doc);
  const responseIssuer = select('string(/samlp:Response/saml:Issuer)', doc);

  const assertionIssuer = select('string(/samlp:Response/saml:Assertion/saml:Issuer)', doc);
  const nameId = select('string(//saml:Subject/saml:NameID)', doc);

  const recipient = select('string(//saml:SubjectConfirmationData/@Recipient)', doc);
  const notOnOrAfter = select('string(//saml:SubjectConfirmationData/@NotOnOrAfter)', doc);

  const audience = select('string(//saml:AudienceRestriction/saml:Audience)', doc);

  return {
    responseStatus,
    responseDestination,
    inResponseTo,
    responseIssuer,
    assertionIssuer,
    nameId,
    recipient,
    notOnOrAfter,
    audience,
    rawXml: xml
  };
}

function validateAcsResponse(fields, relayState) {
  const errors = [];

  // 1) Status
  if (fields.responseStatus !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
    errors.push(`SAML Status non valido: ${fields.responseStatus}`);
  }

  // 2) InResponseTo
  if (!fields.inResponseTo) {
    errors.push('InResponseTo mancante nella Response');
  } else if (!pendingRequests.has(fields.inResponseTo)) {
    errors.push(`Nessuna AuthnRequest pendente trovata per InResponseTo=${fields.inResponseTo}`);
  } else {
    const pending = pendingRequests.get(fields.inResponseTo);

    // RelayState non è crittografico da solo, ma ci aiuta a correlare il flow applicativo
    if (relayState && pending.relayState !== relayState) {
      errors.push(`RelayState non coerente. Atteso=${pending.relayState}, ricevuto=${relayState}`);
    }
  }

  // 3) Destination / Recipient -> ACS
  if (fields.responseDestination !== sp_acs) {
    errors.push(`Destination non coerente. Atteso=${sp_acs}, ricevuto=${fields.responseDestination}`);
  }

  if (fields.recipient !== sp_acs) {
    errors.push(`Recipient non coerente. Atteso=${sp_acs}, ricevuto=${fields.recipient}`);
  }

  // 4) Audience -> Entity ID
  if (fields.audience !== sp_entity_id) {
    errors.push(`Audience non coerente. Atteso=${sp_entity_id}, ricevuto=${fields.audience}`);
  }

  // 5) Issuer -> IdP
  // Accettiamo sia Response Issuer che Assertion Issuer, purché corrispondano all'IdP Entra
  if (fields.responseIssuer && fields.responseIssuer !== entra_id) {
    errors.push(`Response Issuer non coerente. Atteso=${entra_id}, ricevuto=${fields.responseIssuer}`);
  }

  if (fields.assertionIssuer && fields.assertionIssuer !== entra_id) {
    errors.push(`Assertion Issuer non coerente. Atteso=${entra_id}, ricevuto=${fields.assertionIssuer}`);
  }

  return errors;
}

app.http('samlLogin', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'login',
  handler: async (request, context) => {
    const requestId = generateSamlRequestId();
    const issueInstant = new Date().toISOString();
    const relayState = crypto.randomUUID();

    pendingRequests.set(requestId, {
      createdAt: Date.now(),
      relayState
    });

    const authnRequestXml = buildAuthnRequest({
      id: requestId,
      issueInstant,
      acsUrl: sp_acs,
      issuer: sp_entity_id
    });

    context.log('Generated AuthnRequest ID:', requestId);
    context.log('Generated AuthnRequest XML:', authnRequestXml);

    const samlRequest = encodeForRedirectBinding(authnRequestXml);

    const redirectUrl =
      `${entra_login}?SAMLRequest=${samlRequest}&RelayState=${encodeURIComponent(relayState)}`;

    return {
      status: 302,
      headers: {
        Location: redirectUrl,
        'Cache-Control': 'no-store'
      }
    };
  }
});

app.http('samlAcs', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'acs',
  handler: async (request, context) => {
    context.log(`POST /api/acs called - url: ${request.url}`);

    // In Azure Functions Node v4, leggere il body come testo è uno scenario standard
    const rawBody = await request.text();

    // ACS riceve form-urlencoded con almeno SAMLResponse
    const form = parseFormUrlEncoded(rawBody);
    const samlResponse = form.SAMLResponse;
    const relayState = form.RelayState || null;

    if (!samlResponse) {
      return {
        status: 400,
        jsonBody: {
          ok: false,
          error: 'Parametro SAMLResponse mancante nel body POST'
        }
      };
    }

    let xml;
    try {
      xml = decodeBase64Xml(samlResponse);
    } catch (err) {
      return {
        status: 400,
        jsonBody: {
          ok: false,
          error: 'Impossibile decodificare la SAMLResponse in Base64',
          details: err.message
        }
      };
    }

    let fields;
    try {
      fields = extractSamlFields(xml);
    } catch (err) {
      return {
        status: 400,
        jsonBody: {
          ok: false,
          error: 'Impossibile fare parsing XML della SAMLResponse',
          details: err.message,
          xmlPreview: xml.substring(0, 1000)
        }
      };
    }

    const errors = validateAcsResponse(fields, relayState);

    if (errors.length > 0) {
      return {
        status: 400,
        jsonBody: {
          ok: false,
          message: 'SAMLResponse ricevuta ma validazione base fallita',
          errors,
          extracted: {
            inResponseTo: fields.inResponseTo,
            destination: fields.responseDestination,
            recipient: fields.recipient,
            audience: fields.audience,
            nameId: fields.nameId,
            responseIssuer: fields.responseIssuer,
            assertionIssuer: fields.assertionIssuer,
            relayState
          }
        }
      };
    }

    // A questo punto, per PoC, consideriamo la risposta "accettata".
    // In produzione qui devi:
    // - verificare la firma XML
    // - creare una sessione locale/cookie
    // - eventualmente fare redirect alla tua home autenticata

    pendingRequests.delete(fields.inResponseTo);

    return {
      status: 200,
      jsonBody: {
        ok: true,
        message: 'SAMLResponse validata (controlli base) - PoC OK',
        user: {
          nameId: fields.nameId
        },
        saml: {
          inResponseTo: fields.inResponseTo,
          destination: fields.responseDestination,
          recipient: fields.recipient,
          audience: fields.audience,
          issuer: fields.assertionIssuer || fields.responseIssuer,
          relayState
        }
      }
    };
  }
});

app.http('samlLogout', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'logout',
  handler: async (request, context) => {
    context.log(`GET /api/logout called - url: ${request.url}`);

    return {
      status: 200,
      jsonBody: {
        ok: true,
        message: 'Logout endpoint ready'
      }
    };
  }
});
