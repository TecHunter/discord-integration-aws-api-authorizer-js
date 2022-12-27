import { sign } from 'tweetnacl'

// Your public key can be found on your application in the Developer Portal
const expectedKid = process.env.PUBLIC_KEY;

export async function handler(event) {
  const context = {
    sig: event.headers['X-Signature-Ed25519'],
    timestamp: event.headers['X-Signature-Timestamp']
  };
  const body = event.body; // rawBody is expected to be a string, not raw bytes
  let isVerified = false;
  try {
    isVerified = sign.detached.verify(
      Buffer.from(context.timestamp + body),
      Buffer.from(context.sig, 'hex'),
      Buffer.from(expectedKid, 'hex')
    );
  } catch (e) {
    console.log(e);
  }

  if (!isVerified) {
    return {
      principalId: 'me',
      context,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Action: 'execute-api:Invoke',
          Effect: "Deny",
          Resource: event.methodArn
        }]
      }
    };
  }

  // Return the result of the verification
  return {
    principalId: 'me',
    context,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Action: 'execute-api:Invoke',
        Effect: "Allow",
        Resource: event.methodArn
      }]
    }
  }
};
