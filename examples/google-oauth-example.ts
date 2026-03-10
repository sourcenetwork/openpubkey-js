/**
 * Complete example of Google OAuth authentication with OpenPubKey
 *
 * This example demonstrates the full flow:
 * 1. Create Google OAuth provider
 * 2. Authenticate with Google (opens browser)
 * 3. Receive and verify PK Token
 * 4. Extract user information
 */

import {
  newGoogleOp,
  newGoogleOpWithOptions,
  OpkClient,
  Verifier,
  ExpirationPolicies,
  parseOidcClaims,
  type GoogleOptions,
} from '../src/index.js';

/**
 * Google OAuth with default settings
 */
async function exampleGoogleAuthDefault() {
  try {
    // Create Google provider with default options
    // This will use the OpenPubKey project's public OAuth client
    const googleOp = newGoogleOp();
    // Create OpenPubKey client
    const client = await OpkClient.newClient(googleOp);
    console.log('OpenPubKey client created');
    // Authenticate with Google
    // This will:
    // 1. Start a local callback server
    // 2. Open your browser to Google sign-in
    // 3. Wait for OAuth callback
    // 4. Exchange code for tokens
    // 5. Return a PK Token
    console.log('Starting Google authentication...');
    console.log('Your browser will open shortly...');
    const pkToken = await client.auth();
    console.log('\n✅ Authentication successful!');
    console.log('PK Token created');
    // Extract user information from the token
    const claims = parseOidcClaims(JSON.parse(new TextDecoder().decode(pkToken.payload)));
    console.log('\nUser Information:');
    console.log('- Subject (ID):', claims.sub);
    console.log('- Email:', claims.email);
    console.log('- Name:', claims.given_name, claims.family_name);
    console.log('- Issuer:', claims.iss);
    // Serialize the PK Token for storage or transmission
    const compact = await pkToken.compact();
    console.log('\nPK Token (compact):', new TextDecoder().decode(compact).substring(0, 100) + '...');
    // Verify the token
    const verifier = await Verifier.newVerifier(googleOp, {
      expirationPolicy: ExpirationPolicies.MAX_AGE_24HOURS,
    });
    await verifier.verifyPKToken(pkToken);
    console.log('\n✅ PK Token verified successfully');
    return pkToken;
  } catch (error) {
    console.error('❌ Authentication failed:', error);
    throw error;
  }
}

/**
 * Google OAuth with custom client ID
 */
async function exampleGoogleAuthCustom() {
  // You can use your own OAuth client by creating one at:
  // https://console.cloud.google.com/apis/credentials
  const customOptions: Partial<GoogleOptions> = {
    clientID: 'YOUR_CLIENT_ID',
    clientSecret: 'YOUR_CLIENT_SECRET',
    redirectURIs: ['http://localhost:3000/login-callback'],
    scopes: ['openid', 'profile', 'email'],
    promptType: 'consent',
    accessType: 'offline', // Request refresh token
  };
  try {
    const googleOp = newGoogleOpWithOptions(customOptions);
    const client = await OpkClient.newClient(googleOp);
    console.log('Custom Google OAuth client created');
    console.log('Using client ID:', customOptions.clientID?.substring(0, 20) + '...');
    // Note: This will fail unless you provide a real client ID above
    // Uncomment to test with your own credentials:
    // const pkToken = await client.auth();
    // console.log('Authenticated successfully!');
    console.log('\nTo use this example:');
    console.log('1. Create OAuth credentials at https://console.cloud.google.com/apis/credentials');
    console.log('2. Set authorized redirect URIs to include http://localhost:3000/login-callback');
    console.log('3. Replace YOUR_CLIENT_ID and YOUR_CLIENT_SECRET above');
  } catch (error) {
    console.error('Error:', error);
  }
}

/**
 * Token refresh
 */
async function exampleTokenRefresh() {
  try {
    const googleOp = newGoogleOp();
    const client = await OpkClient.newClient(googleOp);
    // Authenticate (this will get initial tokens including refresh token)
    console.log('Initial authentication...');
    const pkToken = await client.auth();
    console.log('✅ Initial authentication successful');
    // Get the refresh token (if available)
    const refreshToken = client.getOp() as any; // Access to refresh token depends on implementation
    // Later, you can refresh the token without requiring user interaction
    // Note: This requires that the provider was configured with access_type: 'offline'
    console.log('\nRefreshing token...');
    // const newPkToken = await client.refresh();
    // console.log('✅ Token refreshed successfully');
    console.log('\nNote: Token refresh requires access_type: "offline" in OAuth options');
  } catch (error) {
    console.error('Error:', error);
  }
}

/**
 * Example 4: Without opening browser automatically
 */
async function exampleManualBrowser() {
  const options: Partial<GoogleOptions> = {
    openBrowser: false, // Don't auto-open browser
  };
  try {
    const googleOp = newGoogleOpWithOptions(options);
    const client = await OpkClient.newClient(googleOp);
    console.log('Starting authentication...');
    console.log('Browser will NOT open automatically');
    console.log('Watch for the URL in the console and open it manually');
    const pkToken = await client.auth();
    console.log('✅ Authentication successful');
  } catch (error) {
    console.error('Error:', error);
  }
}

/**
 * Complete workflow with verification
 */
async function exampleCompleteWorkflow() {
  try {
    // Setup
    console.log('Step 1: Setting up Google OAuth provider...');
    const googleOp = newGoogleOp();
    const client = await OpkClient.newClient(googleOp);
    // Authenticate
    console.log('\nStep 2: Authenticating with Google...');
    console.log('(Browser will open for Google sign-in)');
    const pkToken = await client.auth();
    console.log('✅ Authentication complete');
    // Extract claims
    console.log('\nStep 3: Extracting user claims...');
    const claims = parseOidcClaims(JSON.parse(new TextDecoder().decode(pkToken.payload)));
    console.log('User:', claims.email);
    // Serialize token
    console.log('\nStep 4: Serializing PK Token...');
    const compact = await pkToken.compact();
    console.log('Token size:', compact.length, 'bytes');
    // Verify token
    console.log('\nStep 5: Verifying PK Token...');
    const verifier = await Verifier.newVerifier(googleOp, {
      expirationPolicy: ExpirationPolicies.MAX_AGE_24HOURS,
    });
    await verifier.verifyPKToken(pkToken);
    console.log('✅ Verification successful');
    // Store/transmit token
    console.log('\nStep 6: Token ready for use');
    console.log('You can now:');
    console.log('- Store it in a database');
    console.log('- Send it in HTTP headers');
    console.log('- Use it for authentication');
    return { pkToken, claims, compact };
  } catch (error) {
    console.error('❌ Workflow failed:', error);
    throw error;
  }
}

/**
 * Main function
 */
async function main() {
  console.log('OpenPubKey Google OAuth Examples');
  console.log('=================================\n');
  console.log('These examples demonstrate Google OAuth integration');
  console.log('You will need an internet connection and a Google account\n');
  // Choose which example to run
  const args = process.argv.slice(2);
  const example = args[0] || '1';
  switch (example) {
    case '1':
      await exampleGoogleAuthDefault();
      break;
    case '2':
      await exampleGoogleAuthCustom();
      break;
    case '3':
      await exampleTokenRefresh();
      break;
    case '4':
      await exampleManualBrowser();
      break;
    case '5':
      await exampleCompleteWorkflow();
      break;
    default:
      console.log('Usage: node google-oauth-example.js [1|2|3|4|5]');
      console.log('  1: Default Google OAuth (recommended)');
      console.log('  2: Custom OAuth client');
      console.log('  3: Token refresh');
      console.log('  4: Manual browser opening');
      console.log('  5: Complete workflow');
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { main };
