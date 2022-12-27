import { sign } from 'tweetnacl'

// Your public key can be found on your application in the Developer Portal
const expectedKid = process.env.PUBLIC_KEY;

export async function handler(event) {
  const token = event.authorizationToken;
  
  const signature = event.headers['X-Signature-Ed25519'];
  const timestamp = event.headers['X-Signature-Timestamp'];
  const body = event.body; // rawBody is expected to be a string, not raw bytes
  
  const isVerified = sign.detached.verify(
    Buffer.from(timestamp + body),
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedKid, 'hex')
  );
  
  if (!isVerified) {
    return {
      statusCode: 401,
      body: JSON.stringify({
        message: 'Invalid signature'
      })
    };
  }

  // Return the result of the verification
  return {
    principalId: decodedToken.sub,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: event.methodArn
        }
      ]
    }
  };
};
