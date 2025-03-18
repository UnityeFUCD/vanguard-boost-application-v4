// Express server setup
const express = require('express');
const axios = require('axios');
const Airtable = require('airtable');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3195;

// Secret key for token generation - would typically be in environment variables
const SECRET_KEY = process.env.TOKEN_SECRET || 'vanguard-boost-verification-secret';

// Track verification attempts (would use Redis in production)
const verificationAttempts = new Map();

// Function to generate a verification token with timestamp for expiry
function generateVerificationToken(nickname, submissionId, timestamp = Date.now()) {
  // Normalize inputs for consistency
  const normalizedNickname = String(nickname).trim();
  const normalizedSubmissionId = String(submissionId).trim();
  
  const data = `${normalizedNickname}:${normalizedSubmissionId}:${timestamp}:${SECRET_KEY}`;
  return `${crypto.createHash('sha256').update(data).digest('hex')}.${timestamp}`;
}

// Function to validate a verification token
function validateVerificationToken(nickname, submissionId, token) {
  try {
    // Handle old tokens without timestamp
    if (!token.includes('.')) {
      // Legacy validation for older tokens
      const data = `${nickname}:${submissionId}:${SECRET_KEY}`;
      const expectedToken = crypto.createHash('sha256').update(data).digest('hex');
      return token === expectedToken;
    }
    
    // New token format with timestamp
    const [hash, timestamp] = token.split('.');
    
    // Optional: Check if token is expired (e.g., 48 hours)
    const now = Date.now();
    if (now - parseInt(timestamp) > 48 * 60 * 60 * 1000) {
      console.log('Token expired');
      return false;
    }
    
    // Normalize inputs the same way as when generating
    const normalizedNickname = String(nickname).trim();
    const normalizedSubmissionId = String(submissionId).trim();
    
    const data = `${normalizedNickname}:${normalizedSubmissionId}:${timestamp}:${SECRET_KEY}`;
    const expectedHash = crypto.createHash('sha256').update(data).digest('hex');
    
    return hash === expectedHash;
  } catch (err) {
    console.error('Token validation error:', err);
    return false;
  }
}

// Middleware to parse JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the root directory
app.use(express.static(__dirname));

// Airtable setup
let base;
let table;
try {
  if (process.env.AIRTABLE_API_KEY && process.env.AIRTABLE_BASE_ID && process.env.AIRTABLE_TABLE_NAME) {
    base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY }).base(process.env.AIRTABLE_BASE_ID);
    table = base(process.env.AIRTABLE_TABLE_NAME);
    console.log('Airtable configured successfully');
  } else {
    console.log('Missing Airtable environment variables, Airtable integration disabled');
  }
} catch (error) {
  console.error('Error configuring Airtable:', error);
}

// Bungie API credentials from environment variables
const { BUNGIE_CLIENT_ID, BUNGIE_CLIENT_SECRET, BUNGIE_API_KEY, REDIRECT_URI } = process.env;

// Root route - serve the index.html file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Thank you page route
app.get('/thank-you.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'thank-you.html'));
});

// Form submission handler
app.post('/submit-form', (req, res) => {
  console.log('Form submitted:', req.body);
  
  // Generate a unique application ID if not provided
  const applicationId = req.body.applicationId || `APP-${Date.now().toString(36)}`;
  
  // Store form data in Airtable if API key is configured
  if (table) {
    try {
      const recordData = {
        nickname: req.body.nickname || '',
        email: req.body.email || '',
        discord: req.body.discord || '',
        bungieID: req.body.nickname || '',
        applicationId: applicationId,
        submissionDate: new Date().toISOString(),
        verified: false
      };
      
      // Add any additional fields from the form
      Object.keys(req.body).forEach(key => {
        if (!recordData[key] && req.body[key]) {
          recordData[key] = req.body[key];
        }
      });
      
      table.create(recordData, function(err, record) {
        if (err) {
          console.error('Error saving to Airtable:', err);
        } else {
          console.log('Saved to Airtable:', record.getId());
        }
      });
    } catch (error) {
      console.error('Airtable error:', error);
    }
  }
  
  res.redirect('/thank-you.html?applicationId=' + encodeURIComponent(applicationId));
});

// OAuth callback route
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Rate limiting - prevent abuse
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const ipKey = `ip:${clientIp}`;
  
  // Basic rate limiting (would use Redis in production)
  if (!verificationAttempts.has(ipKey)) {
    verificationAttempts.set(ipKey, { count: 1, timestamp: Date.now() });
  } else {
    const attempt = verificationAttempts.get(ipKey);
    const now = Date.now();
    
    // Reset counter after 1 hour
    if (now - attempt.timestamp > 60 * 60 * 1000) {
      verificationAttempts.set(ipKey, { count: 1, timestamp: now });
    } else if (attempt.count > 10) {
      // Too many attempts
      console.warn(`Rate limit exceeded for IP: ${clientIp}`);
      return res.status(429).send(`
        <html>
          <head>
            <title>Too Many Attempts</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Too Many Verification Attempts</h1>
              <p>Please wait a while before trying again.</p>
            </div>
          </body>
        </html>
      `);
    } else {
      attempt.count++;
      verificationAttempts.set(ipKey, attempt);
    }
  }

  // Handle OAuth errors from Bungie
  if (error) {
    console.error(`OAuth error: ${error} - ${error_description}`);
    return res.status(400).send(`
      <html>
        <head>
          <title>Verification Error</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #ff3e3e; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Verification Error</h1>
            <p>${error_description || error}</p>
            <p>Please try again or contact support if the issue persists.</p>
          </div>
        </body>
      </html>
    `);
  }

  if (!code || !state) {
    return res.status(400).send("Missing authorization code or state parameter.");
  }

  // Decode the state parameter to get the applicant's information
  console.log("Raw state parameter:", state);
  let userNickname = '';
  let applicationId = '';
  let submissionId = '';
  
  try {
    const decodedState = decodeURIComponent(state);
    let stateData = {};
    
    try {
      stateData = JSON.parse(decodedState);
    } catch (parseError) {
      console.error("Failed to parse state as JSON:", parseError);
      // Try to extract information from state if it's not valid JSON
      const stateMatch = decodedState.match(/nickname[:="']+(.*?)["'&]+/i);
      if (stateMatch) userNickname = stateMatch[1];
      
      const submissionMatch = decodedState.match(/submissionId[:="']+(.*?)["'&]+/i);
      if (submissionMatch) submissionId = submissionMatch[1];
      
      const appIdMatch = decodedState.match(/applicationId[:="']+(.*?)["'&]+/i);
      if (appIdMatch) applicationId = appIdMatch[1];
    }
    
    if (stateData.nickname) userNickname = stateData.nickname;
    if (stateData.applicationId) applicationId = stateData.applicationId;
    if (stateData.submissionId) submissionId = stateData.submissionId;
    
    console.log("Extracted from state - Nickname:", userNickname);
    console.log("Extracted from state - Application ID:", applicationId);
    console.log("Extracted from state - Submission ID:", submissionId);
  } catch (error) {
    console.error("Error decoding state parameter:", error);
    return res.status(400).send("Invalid state parameter.");
  }
  
  // If no submissionId, try to get from applicationId
  if (!submissionId && applicationId && table) {
    try {
      const records = await table.select({
        filterByFormula: `{applicationId} = '${applicationId}'`
      }).firstPage();
      
      if (records.length > 0) {
        submissionId = records[0].id;
        console.log("Found submissionId from applicationId:", submissionId);
      }
    } catch (error) {
      console.error("Error looking up submissionId from applicationId:", error);
    }
  }
  
  console.log(`Received application nickname: ${userNickname}`);
  console.log(`Received application ID: ${applicationId}`);
  console.log(`Received submission ID: ${submissionId}`);

  try {
    // Exchange authorization code for an access token
    console.log('Exchanging code for access token...');
    const tokenResponse = await axios.post(
      'https://www.bungie.net/platform/app/oauth/token/',
      `grant_type=authorization_code&code=${code}&client_id=${BUNGIE_CLIENT_ID}&client_secret=${BUNGIE_CLIENT_SECRET}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-API-Key': BUNGIE_API_KEY
        }
      }
    );

    const { access_token, token_type } = tokenResponse.data;
    if (!access_token) {
      console.error('Access token not found in response:', tokenResponse.data);
      throw new Error('Failed to obtain access token');
    }
    console.log('Access token obtained. Fetching user info from Bungie...');

    // Retrieve Bungie user info using the access token
    const userResponse = await axios.get(
      'https://www.bungie.net/platform/User/GetMembershipsForCurrentUser/',
      {
        headers: {
          'Authorization': `${token_type} ${access_token}`,
          'X-API-Key': BUNGIE_API_KEY
        }
      }
    );
    console.log('Bungie user info received.');

    // Extract the Bungie display name and unique code
    let bungieUsername = null;
    let bungieCode = null;
    let fullBungieName = null;

    if (userResponse.data && userResponse.data.Response && userResponse.data.Response.bungieNetUser) {
      bungieUsername = userResponse.data.Response.bungieNetUser.displayName;

      if (userResponse.data.Response.bungieNetUser.uniqueName) {
        const parts = userResponse.data.Response.bungieNetUser.uniqueName.split('#');
        if (parts.length > 1) {
          bungieCode = parts[1];
        }
      }

      // Fallback if uniqueName doesn't provide the code
      if (!bungieCode && userResponse.data.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode !== undefined) {
        bungieCode = userResponse.data.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode;
      }

      if (bungieUsername) {
        fullBungieName = bungieCode ? `${bungieUsername}#${bungieCode}` : bungieUsername;
      }
    }

    console.log(`Bungie username: ${fullBungieName}`);
    console.log(`Application nickname: ${userNickname}`);

    if (!fullBungieName) {
      console.error('Error: Bungie username not retrieved.');
      return res.status(400).send(`
        <html>
          <head>
            <title>Verification Failed</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Verification Failed</h1>
              <p>Unable to retrieve your Bungie username. Please ensure you're logged in on Bungie.net and try again.</p>
            </div>
          </body>
        </html>
      `);
    }

    // Clean and normalize both strings for comparison
    const normalizedBungieName = String(fullBungieName).toLowerCase().trim();
    
    // Extract just the nickname from the stateData for comparison
    let nicknameForComparison = userNickname;
    
    // If userNickname looks like JSON, try to parse it to get just the nickname value
    if (typeof userNickname === 'string' && userNickname.includes('"nickname"')) {
      try {
        // It might be a stringified JSON object
        const parsedData = JSON.parse(userNickname);
        if (parsedData && parsedData.nickname) {
          nicknameForComparison = parsedData.nickname;
          console.log(`Extracted nickname from JSON: ${nicknameForComparison}`);
        }
      } catch (e) {
        console.warn('Failed to parse JSON nickname, using as-is:', e);
      }
    }
    
    // Normalize by removing spaces, converting to lowercase, and controlling for common variations
    const normalizedUserNickname = String(nicknameForComparison).toLowerCase().trim();
    
    // Prepare sanitized versions for more forgiving comparison (remove spaces, special chars)
    const sanitizedBungieName = normalizedBungieName.replace(/\s+/g, '').replace(/#/g, '');
    const sanitizedUserNickname = normalizedUserNickname.replace(/\s+/g, '').replace(/#/g, '');
    
    console.log(`Comparing normalized values: "${normalizedBungieName}" vs. "${normalizedUserNickname}"`);
    console.log(`Sanitized values: "${sanitizedBungieName}" vs. "${sanitizedUserNickname}"`);

    // Try multiple comparison strategies
    // 1. Exact match (preferred)
    // 2. Match without the #code part
    // 3. Sanitized match (most lenient)
    const exactMatch = normalizedBungieName === normalizedUserNickname;
    const nameOnlyMatch = normalizedBungieName.split('#')[0] === normalizedUserNickname.split('#')[0];
    const sanitizedMatch = sanitizedBungieName === sanitizedUserNickname;
    
    const matched = exactMatch || 
                    (nameOnlyMatch && (normalizedBungieName.includes('#') && normalizedUserNickname.includes('#'))) || 
                    sanitizedMatch;
    
    if (matched) {
      console.log(`Match found: Exact: ${exactMatch}, NameOnly: ${nameOnlyMatch}, Sanitized: ${sanitizedMatch}`);

      // Update Airtable record (if found)
      if (table) {
        let recordsToUpdate = [];
        
        try {
          // First try to look up by submissionId (most reliable)
          if (submissionId) {
            const recordById = await table.find(submissionId).catch(e => null);
            if (recordById) {
              recordsToUpdate.push(recordById);
            }
          }
          
          // If no record found by submissionId, try applicationId
          if (recordsToUpdate.length === 0 && applicationId) {
            const recordsByAppId = await table.select({
              filterByFormula: `{applicationId} = '${applicationId}'`
            }).firstPage();
            
            if (recordsByAppId.length > 0) {
              recordsToUpdate = recordsByAppId;
            }
          }
          
          // Last resort: try to find by nickname
          if (recordsToUpdate.length === 0) {
            const normalizedNickname = userNickname.toLowerCase().trim();
            const recordsByName = await table.select({
              filterByFormula: `LOWER({nickname}) = '${normalizedNickname}'`
            }).firstPage();
            
            if (recordsByName.length > 0) {
              recordsToUpdate = recordsByName;
            }
          }
          
          // Update all matching records (should usually be just one)
          for (const record of recordsToUpdate) {
            await table.update(record.id, {
              verified: true,
              verificationDate: new Date().toISOString(),
              bungieUsername: fullBungieName,
              verificationMethod: 'bungie'
            });
            
            // Store in memory verification status (temporary, would use Redis/DB in production)
            verificationAttempts.set(`verified:${record.id}`, {
              verified: true,
              timestamp: Date.now(),
              method: 'bungie',
              bungieName: fullBungieName
            });
            
            console.log(`Updated Airtable record: ${record.id}`);
          }
        } catch (error) {
          console.error('Error updating Airtable record:', error);
        }
      }

      return res.send(`
        <html>
          <head>
            <title>Verification Successful</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #c4ff00; }
              .success-icon { font-size: 64px; margin-bottom: 20px; color: #c4ff00; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="success-icon">✓</div>
              <h1>Verification Successful!</h1>
              <p>Your Bungie account (<strong>${fullBungieName}</strong>) has been verified.</p>
              <p>You may now close this window and return to Discord.</p>
            </div>
          </body>
        </html>
      `);
    } else {
      console.log('Username verification failed - Bungie ID must match EXACTLY what was entered in the form');
      return res.status(400).send(`
        <html>
          <head>
            <title>Verification Failed</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
              .details { text-align: left; background: rgba(255,62,62,0.1); padding: 15px; border-radius: 5px; margin-top: 20px; }
              .suggestion { background: rgba(196, 255, 0, 0.1); padding: 15px; border-radius: 5px; margin-top: 20px; text-align: left; }
              .buttons { margin-top: 25px; }
              .btn { display: inline-block; padding: 10px 20px; background-color: #c4ff00; color: #000; text-decoration: none; border-radius: 4px; margin: 0 10px; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Verification Failed</h1>
              <div class="details">
                <p><strong>Your Bungie Account:</strong> ${fullBungieName}</p>
                <p><strong>Application Nickname:</strong> ${userNickname}</p>
              </div>
              <div class="suggestion">
                <p><strong>Common Issues:</strong></p>
                <ul style="text-align: left;">
                  <li>Exact character matching - ensure the Bungie ID is exactly the same</li>
                  <li>Double-check the # code numbers after your name</li>
                  <li>Watch for spaces or special characters</li>
                </ul>
              </div>
              <p>Please ensure you're using the same Bungie account as you entered in your application.</p>
              <div class="buttons">
                <a href="/email-verify?nickname=${encodeURIComponent(fullBungieName)}&submissionId=${encodeURIComponent(submissionId)}&token=${encodeURIComponent(generateVerificationToken(fullBungieName, submissionId))}" class="btn">Try with Current Bungie ID</a>
                <a href="javascript:history.back()" class="btn" style="background-color: #333; color: #fff;">Go Back</a>
              </div>
            </div>
          </body>
        </html>
      `);
    }
  } catch (err) {
    console.error('Error during verification:', err);
    return res.status(500).send(`
      <html>
        <head>
          <title>Verification Error</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #ff3e3e; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Verification Error</h1>
            <p>An unexpected error occurred. Please try again later.</p>
            <p>Error details: ${err.message}</p>
          </div>
        </body>
      </html>
    `);
  }
});

// Handle form submissions from Netlify
app.get('/success', (req, res) => {
  console.log('Form submitted successfully via Netlify:', req.query);
  res.redirect('/thank-you.html?applicationId=' + encodeURIComponent(req.query.applicationId || ''));
});

// Email verification endpoint
app.get('/email-verify', async (req, res) => {
  const { nickname, submissionId, token } = req.query;
  
  // Rate limiting
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const ipKey = `ip:${clientIp}`;
  
  // Basic rate limiting
  if (!verificationAttempts.has(ipKey)) {
    verificationAttempts.set(ipKey, { count: 1, timestamp: Date.now() });
  } else {
    const attempt = verificationAttempts.get(ipKey);
    const now = Date.now();
    
    // Reset counter after 1 hour
    if (now - attempt.timestamp > 60 * 60 * 1000) {
      verificationAttempts.set(ipKey, { count: 1, timestamp: now });
    } else if (attempt.count > 10) {
      // Too many attempts
      console.warn(`Rate limit exceeded for IP: ${clientIp}`);
      return res.status(429).send(`
        <html>
          <head>
            <title>Too Many Attempts</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Too Many Verification Attempts</h1>
              <p>Please wait a while before trying again.</p>
            </div>
          </body>
        </html>
      `);
    } else {
      attempt.count++;
      verificationAttempts.set(ipKey, attempt);
    }
  }
  
  if (!nickname || !submissionId || !token) {
    return res.status(400).send(`
      <html>
        <head>
          <title>Verification Error</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #ff3e3e; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Verification Error</h1>
            <p>Missing required verification parameters.</p>
            <p>Please use the link provided in your email or contact support.</p>
          </div>
        </body>
      </html>
    `);
  }
  
  // Check if already verified (in memory cache)
  const verificationKey = `verified:${submissionId}`;
  if (verificationAttempts.has(verificationKey)) {
    const verification = verificationAttempts.get(verificationKey);
    if (verification.verified) {
      return res.send(`
        <html>
          <head>
            <title>Already Verified</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #c4ff00; }
              .success-icon { font-size: 64px; margin-bottom: 20px; color: #c4ff00; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="success-icon">✓</div>
              <h1>Already Verified</h1>
              <p>Your Bungie identity <strong>(${verification.bungieName || nickname})</strong> has already been verified successfully.</p>
              <p>No further action is needed. Your application is being reviewed by our team.</p>
            </div>
          </body>
        </html>
      `);
    }
  }
  
  // Validate the token
  if (!validateVerificationToken(nickname, submissionId, token)) {
    console.warn('Invalid token:', token);
    
    // Try to help the user by checking Airtable
    if (table) {
      try {
        // Try to find the record
        let recordFound = null;
        if (submissionId) {
          try {
            recordFound = await table.find(submissionId).catch(e => null);
          } catch (e) {
            // Likely not a valid record ID format, continue with other lookup methods
          }
        }
        
        // If not found by ID, try by nickname
        if (!recordFound) {
          const normalizedNickname = String(nickname).toLowerCase().trim();
          const records = await table.select({
            filterByFormula: `LOWER({nickname}) = '${normalizedNickname}'`
          }).firstPage();
          
          if (records.length > 0) {
            recordFound = records[0];
          }
        }
        
        if (recordFound) {
          // Check if already verified
          if (recordFound.get('verified') === true) {
            // Already verified - show success message
            return res.send(`
              <html>
                <head>
                  <title>Already Verified</title>
                  <style>
                    body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                    .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                    h1 { color: #c4ff00; }
                    .success-icon { font-size: 64px; margin-bottom: 20px; color: #c4ff00; }
                  </style>
                </head>
                <body>
                  <div class="container">
                    <div class="success-icon">✓</div>
                    <h1>Already Verified</h1>
                    <p>Your Bungie identity <strong>(${recordFound.get('bungieUsername') || nickname})</strong> has already been verified successfully.</p>
                    <p>No further action is needed. Your application is being reviewed by our team.</p>
                  </div>
                </body>
              </html>
            `);
          }
          
          // Record exists but needs verification - generate new token and provide link
          const recordId = recordFound.id;
          const storedNickname = recordFound.get('nickname');
          const newToken = generateVerificationToken(storedNickname, recordId);
          
          return res.status(403).send(`
            <html>
              <head>
                <title>Verification Token Error</title>
                <style>
                  body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                  .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                  h1 { color: #ff3e3e; }
                  .btn { display: inline-block; padding: 10px 20px; background-color: #c4ff00; color: #000; text-decoration: none; border-radius: 4px; margin-top: 20px; font-weight: bold; }
                </style>
              </head>
              <body>
                <div class="container">
                  <h1>Verification Token Error</h1>
                  <p>The verification link you used appears to be invalid or expired.</p>
                  <p>We found your application, but the security token doesn't match.</p>
                  <p>Please use the updated link below:</p>
                  <a href="/email-verify?nickname=${encodeURIComponent(storedNickname)}&submissionId=${encodeURIComponent(recordId)}&token=${encodeURIComponent(newToken)}" class="btn">USE UPDATED VERIFICATION LINK</a>
                </div>
              </body>
            </html>
          `);
        }
      } catch (error) {
        console.error('Error checking verification in Airtable:', error);
      }
    }
    
    // If we get here, no record found or other error - show generic error
    return res.status(403).send(`
      <html>
        <head>
          <title>Verification Error</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #ff3e3e; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Verification Error</h1>
            <p>Invalid verification token.</p>
            <p>Please use the link provided in your email or contact support.</p>
          </div>
        </body>
      </html>
    `);
  }
  
  // Final check with Airtable (token is valid at this point)
  if (table) {
    try {
      let recordFound = null;
      
      // Try to find by submissionId first (direct lookup)
      if (submissionId) {
        try {
          recordFound = await table.find(submissionId).catch(e => null);
        } catch (e) {
          // Not a valid record ID format, continue with query
        }
      }
      
      // If not found directly, try query
      if (!recordFound) {
        const records = await table.select({
          filterByFormula: `OR({submissionId} = '${submissionId}', LOWER({nickname}) = '${String(nickname).toLowerCase().trim()}')`
        }).firstPage();
        
        if (records.length > 0) {
          recordFound = records[0];
        }
      }
      
      if (recordFound) {
        // If already verified, show success message
        if (recordFound.get('verified') === true) {
          return res.send(`
            <html>
              <head>
                <title>Already Verified</title>
                <style>
                  body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                  .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                  h1 { color: #c4ff00; }
                  .success-icon { font-size: 64px; margin-bottom: 20px; color: #c4ff00; }
                </style>
              </head>
              <body>
                <div class="container">
                  <div class="success-icon">✓</div>
                  <h1>Already Verified</h1>
                  <p>Your Bungie identity <strong>(${recordFound.get('bungieUsername') || nickname})</strong> has already been verified successfully.</p>
                  <p>No further action is needed. Your application is being reviewed by our team.</p>
                </div>
              </body>
            </html>
          `);
        }
      } else {
        // No record found with this submissionId, but token is valid - strange case
        return res.send(`
          <html>
            <head>
              <title>Verification Error</title>
              <style>
                body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                h1 { color: #ff3e3e; }
                .suggestion { background: rgba(196, 255, 0, 0.1); padding: 15px; border-radius: 5px; margin-top: 20px; text-align: left; }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>Verification Error</h1>
                <p>We couldn't find your application record with ID: <strong>${submissionId}</strong></p>
                <div class="suggestion">
                  <p><strong>Possible Solutions:</strong></p>
                  <ul style="text-align: left;">
                    <li>Your token is valid but we can't find your record - try submitting your application again</li>
                    <li>The database might be experiencing issues - try again later</li>
                    <li>Contact support if you continue having problems</li>
                  </ul>
                </div>
              </div>
            </body>
          </html>
        `);
      }
    } catch (error) {
      console.error('Error checking verification status:', error);
    }
  }
  
  // If we got here, the user needs to verify - redirect to Bungie OAuth
  const state = encodeURIComponent(JSON.stringify({
    nickname,
    submissionId
  }));
  
  const authUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${BUNGIE_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}`;
  
  res.redirect(authUrl);
});

// Netlify form handling - this is a fallback in case the Netlify forms handling doesn't work
app.post('/', (req, res) => {
  console.log('Form submitted via POST to root:', req.body);
  res.redirect('/thank-you.html?applicationId=' + encodeURIComponent(req.body.applicationId || ''));
});

// Development utility route to generate verification links (should be disabled in production)
app.get('/generate-email-link', (req, res) => {
  const { nickname, submissionId } = req.query;
  
  if (!nickname || !submissionId) {
    return res.status(400).send('Missing required parameters: nickname and submissionId');
  }
  
  const token = generateVerificationToken(nickname, submissionId);
  const verificationUrl = `${req.protocol}://${req.get('host')}/email-verify?nickname=${encodeURIComponent(nickname)}&submissionId=${encodeURIComponent(submissionId)}&token=${token}`;
  
  res.send(`
    <html>
      <head>
        <title>Verification Link Generator</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; padding: 20px; }
          .container { max-width: 800px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
          h1 { color: #c4ff00; }
          .link-box { background: #1a1a1a; padding: 15px; border-radius: 5px; margin: 20px 0; word-break: break-all; }
          .warning { color: #ff3e3e; margin-top: 20px; padding: 10px; border: 1px solid #ff3e3e; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Verification Link Generator</h1>
          <p><strong>Nickname:</strong> ${nickname}</p>
          <p><strong>Submission ID:</strong> ${submissionId}</p>
          <p><strong>Generated URL:</strong></p>
          <div class="link-box">
            <a href="${verificationUrl}" style="color: #c4ff00;">${verificationUrl}</a>
          </div>
          <p>Click the link above to test the verification process.</p>
          <div class="warning">
            <strong>Warning:</strong> This utility endpoint should be disabled in production to prevent security issues.
          </div>
        </div>
      </body>
    </html>
  `);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to access the application`);
});