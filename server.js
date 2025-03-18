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
// Track in-process verifications to prevent concurrent attempts on the same ID
const verificationLocks = new Map();

// Function to generate a verification token with timestamp for expiry
function generateVerificationToken(nickname, submissionId, timestamp = Date.now()) {
  // Normalize and sanitize inputs for consistency
  const normalizedNickname = String(nickname).trim();
  const normalizedSubmissionId = String(submissionId).trim();
  
  const data = `${normalizedNickname}:${normalizedSubmissionId}:${timestamp}:${SECRET_KEY}`;
  return `${crypto.createHash('sha256').update(data).digest('hex')}.${timestamp}`;
}

// Function to validate a verification token
function validateVerificationToken(nickname, submissionId, token, clockDriftToleranceMs = 5000) {
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
    
    // Parse timestamp and check if token is expired (e.g., 48 hours)
    const tokenTime = parseInt(timestamp);
    const now = Date.now();
    
    if (isNaN(tokenTime) || now - tokenTime > 48 * 60 * 60 * 1000) {
      console.log('Token expired or invalid timestamp');
      return false;
    }
    
    // Normalize inputs the same way as when generating
    const normalizedNickname = String(nickname).trim();
    const normalizedSubmissionId = String(submissionId).trim();
    
    // Check potential valid timestamps to account for clock drift
    const timestampsToCheck = [
      tokenTime, 
      tokenTime - clockDriftToleranceMs, 
      tokenTime + clockDriftToleranceMs
    ];
    
    for (const ts of timestampsToCheck) {
      const data = `${normalizedNickname}:${normalizedSubmissionId}:${ts}:${SECRET_KEY}`;
      const expectedHash = crypto.createHash('sha256').update(data).digest('hex');
      
      if (hash === expectedHash) {
        return true;
      }
    }
    
    return false;
  } catch (err) {
    console.error('Token validation error:', err);
    return false;
  }
}

// Acquire a lock for verification to prevent race conditions
async function acquireVerificationLock(id, timeoutMs = 30000) {
  const lockKey = `lock:${id}`;
  if (verificationLocks.has(lockKey)) {
    return false; // Already locked
  }
  
  const lockData = {
    timestamp: Date.now(),
    timeout: timeoutMs
  };
  
  verificationLocks.set(lockKey, lockData);
  
  // Auto-release lock after timeout
  setTimeout(() => {
    if (verificationLocks.has(lockKey) && 
        verificationLocks.get(lockKey).timestamp === lockData.timestamp) {
      verificationLocks.delete(lockKey);
      console.log(`Auto-released lock for ${id} due to timeout`);
    }
  }, timeoutMs);
  
  return true;
}

// Release a verification lock
function releaseVerificationLock(id) {
  const lockKey = `lock:${id}`;
  verificationLocks.delete(lockKey);
}

// Record verification result safely with error handling
async function recordVerification(submissionId, bungieName, method = 'bungie') {
  if (!table || !submissionId) return false;
  
  // Try to acquire lock first
  if (!await acquireVerificationLock(submissionId)) {
    console.log(`Verification already in progress for ${submissionId}`);
    return false;
  }
  
  try {
    // Lookup record
    let record;
    try {
      record = await table.find(submissionId);
    } catch (error) {
      console.error(`Error finding record ${submissionId}:`, error);
      releaseVerificationLock(submissionId);
      return false;
    }
    
    if (!record) {
      console.warn(`Record not found for ID: ${submissionId}`);
      releaseVerificationLock(submissionId);
      return false;
    }
    
    // Check if already verified
    if (record.get('verified') === true) {
      console.log(`Record ${submissionId} already verified`);
      // Update memory cache
      verificationAttempts.set(`verified:${submissionId}`, {
        verified: true,
        timestamp: Date.now(),
        method,
        bungieName: bungieName || record.get('bungieUsername')
      });
      releaseVerificationLock(submissionId);
      return true;
    }
    
    // Update record with verification details
    try {
      await table.update(record.id, {
        verified: true,
        verificationDate: new Date().toISOString(),
        bungieUsername: bungieName,
        verificationMethod: method
      });
      
      // Update memory cache
      verificationAttempts.set(`verified:${submissionId}`, {
        verified: true,
        timestamp: Date.now(),
        method,
        bungieName
      });
      
      console.log(`Successfully verified record ${submissionId}`);
      releaseVerificationLock(submissionId);
      return true;
    } catch (error) {
      console.error(`Error updating record ${submissionId}:`, error);
      releaseVerificationLock(submissionId);
      return false;
    }
  } catch (error) {
    console.error(`Unexpected error in recordVerification:`, error);
    releaseVerificationLock(submissionId);
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

// Add persistent health check for Airtable connection
let airtableHealthy = !!table; // Initial status based on connection
const HEALTH_CHECK_INTERVAL = 15 * 60 * 1000; // 15 minutes

// Health check and reconnection function
async function checkAirtableHealth() {
  try {
    if (!process.env.AIRTABLE_API_KEY || !process.env.AIRTABLE_BASE_ID) {
      console.log('Airtable not configured - skipping health check');
      airtableHealthy = false;
      return;
    }
    
    if (!table) {
      // Try to reinitialize
      try {
        console.log('Attempting to reinitialize Airtable connection...');
        const base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY }).base(process.env.AIRTABLE_BASE_ID);
        table = base('Applications');
        console.log('Airtable connection reinitialized');
      } catch (error) {
        console.error('Failed to reinitialize Airtable connection:', error);
        airtableHealthy = false;
        return;
      }
    }
    
    // Perform a small query to confirm connection works
    const testQuery = await table.select({
      maxRecords: 1,
      view: 'Grid view'
    }).firstPage();
    
    airtableHealthy = true;
    console.log('Airtable connection healthy');
  } catch (error) {
    console.error('Airtable health check failed:', error);
    airtableHealthy = false;
  }
}

// Initial health check
checkAirtableHealth();

// Schedule regular health checks
setInterval(checkAirtableHealth, HEALTH_CHECK_INTERVAL);

// Add basic error reporting
process.on('uncaughtException', (error) => {
  console.error('UNCAUGHT EXCEPTION:', error);
  // Keep the process running
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED PROMISE REJECTION:', reason);
  // Keep the process running
});

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
  
  // Set default timeout for the request
  req.setTimeout(60000); // 60 second timeout

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
            <p>${escapeHtml(error_description || error)}</p>
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
    
    // Sanitize inputs
    userNickname = escapeHtml(userNickname);
    applicationId = escapeHtml(applicationId);
    submissionId = escapeHtml(submissionId);
    
    console.log("Extracted from state - Nickname:", userNickname);
    console.log("Extracted from state - Application ID:", applicationId);
    console.log("Extracted from state - Submission ID:", submissionId);
  } catch (error) {
    console.error("Error decoding state parameter:", error);
    return res.status(400).send("Invalid state parameter.");
  }
  
  // Determine primary identifier for record lookup
  let primaryId = submissionId || '';
  
  // If no submissionId, try to get from applicationId
  if (!primaryId && applicationId && table) {
    try {
      const records = await table.select({
        filterByFormula: `{applicationId} = '${sanitizeForFormula(applicationId)}'`
      }).firstPage();
      
      if (records.length > 0) {
        primaryId = records[0].id;
        console.log("Found record ID from applicationId:", primaryId);
      }
    } catch (error) {
      console.error("Error looking up submissionId from applicationId:", error);
    }
  }
  
  // If we still don't have a primary ID, we can't proceed correctly
  if (!primaryId) {
    console.error("No primary ID found for verification");
  }
  
  console.log(`Received application nickname: ${userNickname}`);
  console.log(`Received application ID: ${applicationId}`);
  console.log(`Received submission ID: ${submissionId}`);

  try {
    // Exchange the authorization code for an access token
    // Set up API request timeout to prevent hanging
    const axiosWithTimeout = axios.create({
      timeout: 30000 // 30 second timeout
    });
    
    const tokenResponse = await axiosWithTimeout.post('https://www.bungie.net/platform/app/oauth/token/', 
      `grant_type=authorization_code&code=${code}&client_id=${BUNGIE_CLIENT_ID}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    if (!tokenResponse.data || !tokenResponse.data.access_token) {
      console.error('No access token returned from Bungie API');
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
              <p>Failed to get access token from Bungie. Please try again.</p>
            </div>
          </body>
        </html>
      `);
    }
    
    const accessToken = tokenResponse.data.access_token;
    
    // Fetch the user's Bungie profile
    const userResponse = await axiosWithTimeout.get('https://www.bungie.net/Platform/User/GetCurrentBungieNetUser/', {
      headers: {
        'X-API-Key': BUNGIE_API_KEY,
        'Authorization': `Bearer ${accessToken}`
      }
    }).catch(error => {
      console.error('Failed to fetch user profile:', error.message);
      if (error.response) {
        console.error('Error response:', error.response.data);
      }
      throw new Error('Failed to fetch user profile from Bungie API');
    });
    
    let bungieUsername = '';
    let bungieCode = '';
    let fullBungieName = '';
    
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
    
    // Sanitize the Bungie name for safety
    fullBungieName = escapeHtml(fullBungieName);
    
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

      // Use the transaction-safe recordVerification function
      const verificationSuccess = await recordVerification(primaryId, fullBungieName, 'bungie');
      
      if (!verificationSuccess && !table) {
        console.warn('Verification recorded only in memory - Airtable not configured');
        // Store in memory verification status (temporary, would use Redis/DB in production)
        verificationAttempts.set(`verified:${primaryId}`, {
          verified: true,
          timestamp: Date.now(),
          method: 'bungie',
          bungieName: fullBungieName
        });
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
              <p>Your Bungie account (<strong>${escapeHtml(fullBungieName)}</strong>) has been verified.</p>
              <p>You may now close this window and return to Discord.</p>
            </div>
          </body>
        </html>
      `);
    }
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
              <p><strong>Your Bungie Account:</strong> ${escapeHtml(fullBungieName)}</p>
              <p><strong>Application Nickname:</strong> ${escapeHtml(userNickname)}</p>
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
              <a href="/email-verify?nickname=${encodeURIComponent(fullBungieName)}&submissionId=${encodeURIComponent(primaryId)}&token=${encodeURIComponent(generateVerificationToken(fullBungieName, primaryId))}" class="btn">Try with Current Bungie ID</a>
              <a href="javascript:history.back()" class="btn" style="background-color: #333; color: #fff;">Go Back</a>
            </div>
          </div>
        </body>
      </html>
    `);
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

// Email verification route with improved error handling
app.get('/email-verify', async (req, res) => {
  const { nickname, submissionId, token } = req.query;
  
  // Show initial loading screen
  res.write(`
    <html>
      <head>
        <title>Verification In Progress</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
          .loader-container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
          h1 { color: #c4ff00; }
          .spinner { border: 4px solid rgba(255, 255, 255, 0.3); border-radius: 50%; border-top: 4px solid #c4ff00; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
          @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
          .message { margin: 20px 0; font-size: 18px; }
        </style>
        <script>
          // This will let us update the UI with verification progress
          function updateStatus(status) {
            document.getElementById('status-message').innerText = status;
          }
        </script>
      </head>
      <body>
        <div class="loader-container">
          <h1>Verifying Your Identity</h1>
          <div class="spinner"></div>
          <div id="status-message" class="message">Please wait while we verify your information...</div>
        </div>
      </body>
    </html>
  `);
  res.flushHeaders();
  
  try {
    // Input validation
    if (!nickname || !submissionId || !token) {
      const missingParams = [];
      if (!nickname) missingParams.push('nickname');
      if (!submissionId) missingParams.push('submissionId');
      if (!token) missingParams.push('token');
      
      return res.end(`
        <script>
          document.open();
          document.write(\`
            <html>
              <head>
                <title>Verification Failed</title>
                <style>
                  body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                  .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                  h1 { color: #ff3e3e; }
                  .error-icon { font-size: 64px; margin-bottom: 20px; color: #ff3e3e; }
                  .btn { display: inline-block; padding: 10px 20px; background-color: #c4ff00; color: #000; text-decoration: none; border-radius: 4px; margin-top: 20px; }
                </style>
              </head>
              <body>
                <div class="container">
                  <div class="error-icon">⚠️</div>
                  <h1>Verification Failed</h1>
                  <p>Missing required parameters: ${missingParams.join(', ')}</p>
                  <p>Please ensure you use the exact link provided in your email.</p>
                </div>
              </body>
            </html>
          \`);
          document.close();
        </script>
      `);
    }
    
    // Create a request ID for tracking
    const requestID = req.requestId;
    req.log.info(`Starting email verification`, { nickname, submissionId, requestID });
    
    // Validate the token
    const isValid = validateVerificationToken(nickname, submissionId, token);
    if (!isValid) {
      req.log.warn(`Invalid or expired token`, { nickname, submissionId, requestID });
      
      // Check if the token is expired
      const isExpired = token.includes('.') && 
                        Date.now() - parseInt(token.split('.')[1]) > 48 * 60 * 60 * 1000;
      
      if (isExpired) {
        // Provide a refresh link for expired tokens
        const refreshUrl = `/refresh-token?nickname=${encodeURIComponent(nickname)}&submissionId=${encodeURIComponent(submissionId)}`;
        
        return res.end(`
          <script>
            document.open();
            document.write(\`
              <html>
                <head>
                  <title>Verification Link Expired</title>
                  <style>
                    body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                    .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                    h1 { color: #ff9d00; }
                    .warning-icon { font-size: 64px; margin-bottom: 20px; color: #ff9d00; }
                    .btn { display: inline-block; padding: 10px 20px; background-color: #c4ff00; color: #000; text-decoration: none; border-radius: 4px; margin-top: 20px; }
                  </style>
                </head>
                <body>
                  <div class="container">
                    <div class="warning-icon">⚠️</div>
                    <h1>Verification Link Expired</h1>
                    <p>The verification link you're using has expired.</p>
                    <p>Verification links are valid for 48 hours after they are created.</p>
                    <a href="${refreshUrl}" class="btn">Generate New Verification Link</a>
                  </div>
                </body>
              </html>
            \`);
            document.close();
          </script>
        `);
      }
      
      return res.end(`
        <script>
          document.open();
          document.write(\`
            <html>
              <head>
                <title>Invalid Verification Link</title>
                <style>
                  body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                  .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                  h1 { color: #ff3e3e; }
                  .error-icon { font-size: 64px; margin-bottom: 20px; color: #ff3e3e; }
                  .btn { display: inline-block; padding: 10px 20px; background-color: #c4ff00; color: #000; text-decoration: none; border-radius: 4px; margin-top: 20px; }
                </style>
              </head>
              <body>
                <div class="container">
                  <div class="error-icon">⚠️</div>
                  <h1>Invalid Verification Link</h1>
                  <p>The verification link is invalid.</p>
                  <p>Please check your email for the correct link or contact support for assistance.</p>
                  <a href="/refresh-token?nickname=${encodeURIComponent(nickname)}&submissionId=${encodeURIComponent(submissionId)}" class="btn">Try New Verification Link</a>
                </div>
              </body>
            </html>
          \`);
          document.close();
        </script>
      `);
    }
    
    // Check if this record is already verified
    const verificationKey = `verified:${submissionId}`;
    if (verificationAttempts.has(verificationKey)) {
      const verificationData = verificationAttempts.get(verificationKey);
      
      if (verificationData.verified) {
        req.log.info(`Record already verified`, { 
          submissionId, 
          method: verificationData.method,
          verifiedAt: new Date(verificationData.timestamp).toISOString()
        });
        
        trackVerificationSuccess();
        
        return res.end(`
          <script>
            document.open();
            document.write(\`
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
                    <p>Your identity has already been verified on ${new Date(verificationData.timestamp).toLocaleString()}.</p>
                    <p>No further action is needed. You can now close this window.</p>
                  </div>
                </body>
              </html>
            \`);
            document.close();
          </script>
        `);
      }
    }
    
    // Record verification - this uses our transaction-safe recordVerification function
    req.log.info(`Attempting to record verification`, { submissionId, method: 'email' });
    const verificationResult = await recordVerification(submissionId, nickname, 'email');
    
    if (verificationResult) {
      req.log.info(`Verification successful`, { submissionId });
      trackVerificationSuccess();
      
      return res.end(`
        <script>
          document.open();
          document.write(\`
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
                  <h1>Verification Successful</h1>
                  <p>Your identity has been verified successfully.</p>
                  <p>Thank you for completing this step of the application process.</p>
                </div>
              </body>
            </html>
          \`);
          document.close();
        </script>
      `);
    } else {
      req.log.warn(`Verification recording failed`, { submissionId });
      
      // Use our degraded service helper if the confirmation didn't go through
      return res.end(`
        <script>
          document.open();
          document.write(\`
            <html>
              <head>
                <title>Verification Issue</title>
                <style>
                  body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                  .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                  h1 { color: #ff9d00; }
                  .warning-icon { font-size: 64px; margin-bottom: 20px; color: #ff9d00; }
                </style>
              </head>
              <body>
                <div class="container">
                  <div class="warning-icon">⚠️</div>
                  <h1>Verification Status Uncertain</h1>
                  <p>We've received your verification request, but we're having trouble updating your record.</p>
                  <p>This could be due to temporary database issues. Please check back later, or contact support if the problem persists.</p>
                  <p>Reference ID: ${requestID}</p>
                </div>
              </body>
            </html>
          \`);
          document.close();
        </script>
      `);
    }
  } catch (error) {
    req.log.error('Error during email verification', error, { nickname, submissionId });
    
    return res.end(`
      <script>
        document.open();
        document.write(\`
          <html>
            <head>
              <title>Verification Error</title>
              <style>
                body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                h1 { color: #ff3e3e; }
                .error-icon { font-size: 64px; margin-bottom: 20px; color: #ff3e3e; }
              </style>
            </head>
            <body>
              <div class="container">
                <div class="error-icon">⚠️</div>
                <h1>Verification Error</h1>
                <p>An error occurred during verification. Please try again or contact support.</p>
                <p>Error reference: ${req.requestId}</p>
              </div>
            </body>
          </html>
        \`);
        document.close();
      </script>
    `);
  }
});

// Development utility route to generate verification links (should be disabled in production)
app.get('/generate-email-link', (req, res) => {
  const { nickname, submissionId } = req.query;
  
  // In production, this endpoint should be disabled or require authentication
  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction) {
    const randomDelay = Math.floor(Math.random() * 2000) + 500; // Random delay between 500-2500ms
    setTimeout(() => {
      return res.status(404).send('Not found');
    }, randomDelay);
    return;
  }
  
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

// Utility functions for security

// Sanitize input for Airtable formula queries
function sanitizeForFormula(input) {
  if (!input) return '';
  // Escape single quotes and other special characters
  return String(input)
    .replace(/'/g, "\\'")
    .replace(/\\/g, "\\\\")
    .trim();
}

// Escape HTML to prevent XSS
function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Memory cleanup for verification attempts (run periodically)
const CLEANUP_INTERVAL = 12 * 60 * 60 * 1000; // 12 hours
setInterval(() => {
  const now = Date.now();
  const expiryTime = 48 * 60 * 60 * 1000; // 48 hours
  
  // Clean up old verification attempts
  for (const [key, data] of verificationAttempts.entries()) {
    if (data.timestamp && now - data.timestamp > expiryTime) {
      verificationAttempts.delete(key);
    }
  }
  
  console.log(`Cleaned up verification attempts map. Current size: ${verificationAttempts.size}`);
}, CLEANUP_INTERVAL);

// Add middleware for security headers
app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Basic CSP - can be expanded based on requirements
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' https://www.bungie.net; style-src 'self' 'unsafe-inline';");
  
  // Redirect HTTP to HTTPS in production
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(`https://${req.hostname}${req.url}`);
  }
  
  next();
});

// Global application state
let systemState = {
  bungieApiHealthy: true,
  airtableHealthy: !!table,
  maintenanceMode: false,
  degradedServices: [],
  startTime: Date.now(),
  lastCheckedBungie: null,
  verificationSuccessRate: {
    attempts: 0,
    success: 0,
    lastReset: Date.now()
  }
};

// Advanced rate limiting with progressive backoff
const rateLimiter = {
  attempts: new Map(),
  blacklist: new Set(),
  
  // Check if IP is rate limited
  isLimited: function(ip, endpoint) {
    if (this.blacklist.has(ip)) return true;
    
    const key = `${ip}:${endpoint}`;
    if (!this.attempts.has(key)) return false;
    
    const data = this.attempts.get(key);
    const now = Date.now();
    
    // Reset after cooldown period
    if (now - data.firstAttempt > 3600000) { // 1 hour
      this.attempts.delete(key);
      return false;
    }
    
    // Calculate allowed attempts based on time
    const timeSinceFirstAttempt = now - data.firstAttempt;
    const timeFactorHours = timeSinceFirstAttempt / 3600000; // Convert to hours
    
    // Base rate of 30/hour, decreasing based on number of attempts
    const allowedAttempts = Math.max(5, Math.floor(30 - (data.count * 2 * timeFactorHours)));
    
    // Progressive backoff - require longer waits after more attempts
    if (data.count > allowedAttempts) {
      // Calculate wait time with progressive backoff
      const waitTime = Math.min(30000, Math.pow(2, data.count - allowedAttempts) * 1000);
      
      if (now - data.lastAttempt < waitTime) {
        return true;
      }
    }
    
    return false;
  },
  
  // Record an attempt
  recordAttempt: function(ip, endpoint) {
    const key = `${ip}:${endpoint}`;
    const now = Date.now();
    
    if (!this.attempts.has(key)) {
      this.attempts.set(key, {
        count: 1,
        firstAttempt: now,
        lastAttempt: now
      });
    } else {
      const data = this.attempts.get(key);
      data.count++;
      data.lastAttempt = now;
      this.attempts.set(key, data);
      
      // Auto-blacklist if too many attempts in short time
      if (data.count > 100 && (now - data.firstAttempt) < 300000) { // 100 attempts in 5 minutes
        console.warn(`IP ${ip} blacklisted for suspicious activity`);
        this.blacklist.add(ip);
        
        // Auto-remove from blacklist after 24 hours
        setTimeout(() => {
          this.blacklist.delete(ip);
        }, 24 * 60 * 60 * 1000);
      }
    }
  },
  
  // Get wait time if limited
  getWaitTime: function(ip, endpoint) {
    const key = `${ip}:${endpoint}`;
    if (!this.attempts.has(key)) return 0;
    
    const data = this.attempts.get(key);
    const now = Date.now();
    
    // Calculate allowed attempts based on time
    const timeSinceFirstAttempt = now - data.firstAttempt;
    const timeFactorHours = timeSinceFirstAttempt / 3600000; // Convert to hours
    const allowedAttempts = Math.max(5, Math.floor(30 - (data.count * 2 * timeFactorHours)));
    
    if (data.count <= allowedAttempts) return 0;
    
    // Calculate wait time with progressive backoff
    const waitTime = Math.min(30000, Math.pow(2, data.count - allowedAttempts) * 1000);
    const timeRemaining = Math.max(0, waitTime - (now - data.lastAttempt));
    
    return timeRemaining;
  },
  
  // Clean up old attempts every hour
  cleanup: function() {
    const now = Date.now();
    const hourAgo = now - 3600000;
    
    for (const [key, data] of this.attempts.entries()) {
      if (data.lastAttempt < hourAgo) {
        this.attempts.delete(key);
      }
    }
    
    // Schedule next cleanup
    setTimeout(() => this.cleanup(), 3600000); // 1 hour
  }
};

// Start the rate limiter cleanup
rateLimiter.cleanup();

// Check Bungie API health
async function checkBungieApiHealth() {
  if (!BUNGIE_API_KEY) {
    console.log('Bungie API not configured - skipping health check');
    systemState.bungieApiHealthy = false;
    return;
  }
  
  try {
    // Set up API request timeout to prevent hanging
    const axiosWithTimeout = axios.create({
      timeout: 5000 // 5 second timeout for health check
    });
    
    // Make a simple request to check if API is working
    const response = await axiosWithTimeout.get('https://www.bungie.net/Platform/Settings/', {
      headers: {
        'X-API-Key': BUNGIE_API_KEY
      }
    });
    
    if (response.status === 200 && response.data && response.data.ErrorCode === 1) {
      systemState.bungieApiHealthy = true;
      systemState.lastCheckedBungie = Date.now();
    } else {
      systemState.bungieApiHealthy = false;
      systemState.degradedServices.push('bungie-api');
      console.warn('Bungie API returned unexpected response:', response.status, response.data?.ErrorCode);
    }
  } catch (error) {
    systemState.bungieApiHealthy = false;
    if (!systemState.degradedServices.includes('bungie-api')) {
      systemState.degradedServices.push('bungie-api');
    }
    console.error('Bungie API health check failed:', error.message);
  }
}

// Initial health checks
checkBungieApiHealth();

// Schedule regular Bungie API health checks
setInterval(checkBungieApiHealth, 5 * 60 * 1000); // Every 5 minutes

// Middleware for all verification endpoints
function verificationMiddleware(req, res, next) {
  const endpoint = req.path;
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  // Check for maintenance mode
  if (systemState.maintenanceMode && !req.path.includes('/admin/')) {
    return res.status(503).send(`
      <html>
        <head>
          <title>Maintenance</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #ff9d00; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>System Maintenance</h1>
            <p>The verification system is currently undergoing maintenance.</p>
            <p>Please try again later. We apologize for the inconvenience.</p>
          </div>
        </body>
      </html>
    `);
  }
  
  // Check for rate limiting
  if (rateLimiter.isLimited(clientIp, endpoint)) {
    const waitTime = rateLimiter.getWaitTime(clientIp, endpoint);
    const waitSeconds = Math.ceil(waitTime / 1000);
    
    return res.status(429).send(`
      <html>
        <head>
          <title>Too Many Requests</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #ff3e3e; }
            .countdown { font-size: 30px; margin: 20px 0; color: #ff9d00; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Too Many Requests</h1>
            <p>Please wait before trying again.</p>
            <p class="countdown">${waitSeconds} seconds</p>
          </div>
        </body>
      </html>
    `);
  }
  
  // Record this attempt
  rateLimiter.recordAttempt(clientIp, endpoint);
  
  // Check for degraded services
  if (endpoint.includes('/verify') || endpoint.includes('/callback')) {
    systemState.verificationSuccessRate.attempts++;
    
    // Check necessary services health
    if (!systemState.bungieApiHealthy && endpoint.includes('/callback')) {
      return res.status(503).send(`
        <html>
          <head>
            <title>Service Unavailable</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Verification Service Degraded</h1>
              <p>The Bungie API is currently unavailable. This is likely a temporary issue.</p>
              <p>Please try again in a few minutes. If the problem persists, please contact support.</p>
            </div>
          </body>
        </html>
      `);
    }
    
    if (!systemState.airtableHealthy && table) {
      console.warn('Airtable connection unhealthy, falling back to in-memory storage');
      // Continue processing but with a warning - will use in-memory fallback
    }
  }
  
  next();
}

// Apply the verification middleware to relevant routes
app.use(['/verify', '/email-verify', '/callback', '/generate-email-link'], verificationMiddleware);

// Status/health endpoint for monitoring
app.get('/health', (req, res) => {
  // Only accessible from localhost or with admin token
  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const isLocalhost = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.includes('192.168.');
  const hasAdminToken = req.query.token === process.env.ADMIN_TOKEN;
  
  if (!isLocalhost && !hasAdminToken) {
    return res.status(403).send('Forbidden');
  }
  
  // Calculate uptime
  const uptime = Math.floor((Date.now() - systemState.startTime) / 1000);
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  
  // Calculate verification success rate
  const successRate = systemState.verificationSuccessRate.attempts > 0 
    ? (systemState.verificationSuccessRate.success / systemState.verificationSuccessRate.attempts * 100).toFixed(2)
    : 'N/A';
  
  // Return detailed health status
  const health = {
    status: systemState.degradedServices.length === 0 ? 'healthy' : 'degraded',
    uptime: `${days}d ${hours}h ${minutes}m`,
    bungieApi: systemState.bungieApiHealthy ? 'healthy' : 'unhealthy',
    airtable: systemState.airtableHealthy ? 'healthy' : 'unhealthy',
    degradedServices: systemState.degradedServices,
    maintenanceMode: systemState.maintenanceMode,
    verificationStats: {
      attempts: systemState.verificationSuccessRate.attempts,
      successful: systemState.verificationSuccessRate.success,
      successRate: `${successRate}%`,
      verificationAttemptsInMemory: verificationAttempts.size,
      activeVerificationLocks: verificationLocks.size
    },
    rateLimiting: {
      ipTracking: rateLimiter.attempts.size,
      blacklistedIPs: rateLimiter.blacklist.size
    }
  };
  
  res.json(health);
});

// Helper function for improved user feedback on verification errors
function renderVerificationError(res, title, message, details = null, retryLink = null) {
  let detailsHtml = '';
  if (details) {
    detailsHtml = `
      <div class="details">
        ${details}
      </div>
    `;
  }
  
  let retryHtml = '';
  if (retryLink) {
    retryHtml = `
      <div class="retry">
        <a href="${escapeHtml(retryLink)}" class="btn">Try Again</a>
      </div>
    `;
  }
  
  return res.send(`
    <html>
      <head>
        <title>${escapeHtml(title)}</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
          .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
          h1 { color: #ff3e3e; }
          .details { background: rgba(255,255,255,0.1); padding: 15px; border-radius: 5px; margin: 20px 0; text-align: left; }
          .error-icon { font-size: 64px; margin-bottom: 20px; color: #ff3e3e; }
          .btn { display: inline-block; padding: 10px 20px; background-color: #c4ff00; color: #000; text-decoration: none; border-radius: 4px; margin-top: 20px; }
          code { background: rgba(0,0,0,0.3); padding: 2px 4px; border-radius: 3px; font-family: monospace; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="error-icon">⚠️</div>
          <h1>${escapeHtml(title)}</h1>
          <p>${escapeHtml(message)}</p>
          ${detailsHtml}
          ${retryHtml}
        </div>
      </body>
    </html>
  `);
}

// Helper function for rendering success responses
function renderVerificationSuccess(res, title, message, additionalDetails = null) {
  let detailsHtml = '';
  if (additionalDetails) {
    detailsHtml = `
      <div class="details">
        ${additionalDetails}
      </div>
    `;
  }
  
  return res.send(`
    <html>
      <head>
        <title>${escapeHtml(title)}</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
          .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
          h1 { color: #c4ff00; }
          .details { background: rgba(255,255,255,0.1); padding: 15px; border-radius: 5px; margin: 20px 0; text-align: left; }
          .success-icon { font-size: 64px; margin-bottom: 20px; color: #c4ff00; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success-icon">✓</div>
          <h1>${escapeHtml(title)}</h1>
          <p>${escapeHtml(message)}</p>
          ${detailsHtml}
        </div>
      </body>
    </html>
  `);
}

// Track verification success in the system state
function trackVerificationSuccess() {
  systemState.verificationSuccessRate.success++;
  
  // Reset counters daily
  const now = Date.now();
  if (now - systemState.verificationSuccessRate.lastReset > 24 * 60 * 60 * 1000) {
    systemState.verificationSuccessRate.attempts = 1;
    systemState.verificationSuccessRate.success = 1;
    systemState.verificationSuccessRate.lastReset = now;
  }
}

// Simple admin panel for system health and configuration
app.get('/admin', (req, res) => {
  // Only accessible with admin token
  const hasAdminToken = req.query.token === process.env.ADMIN_TOKEN;
  if (!hasAdminToken) {
    return res.status(403).send('Forbidden - Admin token required');
  }
  
  // Calculate uptime
  const uptime = Math.floor((Date.now() - systemState.startTime) / 1000);
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  
  // Success rate
  const successRate = systemState.verificationSuccessRate.attempts > 0 
    ? (systemState.verificationSuccessRate.success / systemState.verificationSuccessRate.attempts * 100).toFixed(1)
    : 'N/A';
  
  // Format the admin panel HTML
  res.send(`
    <html>
      <head>
        <title>Verification System Admin</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; padding: 20px; }
          h1, h2 { color: #c4ff00; }
          .panel { background: rgba(0,0,0,0.5); padding: 20px; border-radius: 8px; margin-bottom: 20px; }
          .stat { display: flex; justify-content: space-between; margin: 10px 0; padding: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; }
          .stat-name { font-weight: bold; }
          .healthy { color: #c4ff00; }
          .degraded { color: #ff9d00; }
          .unhealthy { color: #ff3e3e; }
          .btn { display: inline-block; padding: 8px 16px; background-color: #c4ff00; color: #000; text-decoration: none; border-radius: 4px; margin-right: 10px; }
          .danger { background-color: #ff3e3e; color: white; }
        </style>
      </head>
      <body>
        <h1>Verification System Administration</h1>
        <div class="panel">
          <h2>System Status</h2>
          <div class="stat">
            <span class="stat-name">Overall Status:</span>
            <span class="${systemState.degradedServices.length === 0 ? 'healthy' : 'degraded'}">
              ${systemState.degradedServices.length === 0 ? 'Healthy' : 'Degraded'}
            </span>
          </div>
          <div class="stat">
            <span class="stat-name">Uptime:</span>
            <span>${days}d ${hours}h</span>
          </div>
          <div class="stat">
            <span class="stat-name">Bungie API:</span>
            <span class="${systemState.bungieApiHealthy ? 'healthy' : 'unhealthy'}">
              ${systemState.bungieApiHealthy ? 'Healthy' : 'Unhealthy'}
            </span>
          </div>
          <div class="stat">
            <span class="stat-name">Airtable Connection:</span>
            <span class="${systemState.airtableHealthy ? 'healthy' : 'unhealthy'}">
              ${systemState.airtableHealthy ? 'Healthy' : 'Unhealthy'}
            </span>
          </div>
          <div class="stat">
            <span class="stat-name">Maintenance Mode:</span>
            <span class="${systemState.maintenanceMode ? 'degraded' : 'healthy'}">
              ${systemState.maintenanceMode ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        </div>
        
        <div class="panel">
          <h2>Verification Statistics</h2>
          <div class="stat">
            <span class="stat-name">Verification Attempts:</span>
            <span>${systemState.verificationSuccessRate.attempts}</span>
          </div>
          <div class="stat">
            <span class="stat-name">Successful Verifications:</span>
            <span>${systemState.verificationSuccessRate.success}</span>
          </div>
          <div class="stat">
            <span class="stat-name">Success Rate:</span>
            <span>${successRate}%</span>
          </div>
          <div class="stat">
            <span class="stat-name">Active Memory Records:</span>
            <span>${verificationAttempts.size}</span>
          </div>
          <div class="stat">
            <span class="stat-name">Active Verification Locks:</span>
            <span>${verificationLocks.size}</span>
          </div>
        </div>
        
        <div class="panel">
          <h2>System Controls</h2>
          <a href="/admin/toggle-maintenance?token=${encodeURIComponent(process.env.ADMIN_TOKEN)}" class="btn ${systemState.maintenanceMode ? 'danger' : ''}">
            ${systemState.maintenanceMode ? 'Disable Maintenance Mode' : 'Enable Maintenance Mode'}
          </a>
          <a href="/admin/reset-stats?token=${encodeURIComponent(process.env.ADMIN_TOKEN)}" class="btn">
            Reset Statistics
          </a>
          <a href="/admin/clear-rate-limits?token=${encodeURIComponent(process.env.ADMIN_TOKEN)}" class="btn">
            Clear Rate Limits
          </a>
        </div>
        
        <div class="panel">
          <h2>Rate Limiting</h2>
          <div class="stat">
            <span class="stat-name">IPs Being Tracked:</span>
            <span>${rateLimiter.attempts.size}</span>
          </div>
          <div class="stat">
            <span class="stat-name">Blacklisted IPs:</span>
            <span>${rateLimiter.blacklist.size}</span>
          </div>
        </div>
      </body>
    </html>
  `);
});

// Admin controls endpoints
app.get('/admin/toggle-maintenance', (req, res) => {
  if (req.query.token !== process.env.ADMIN_TOKEN) {
    return res.status(403).send('Forbidden');
  }
  
  systemState.maintenanceMode = !systemState.maintenanceMode;
  console.log(`Maintenance mode ${systemState.maintenanceMode ? 'enabled' : 'disabled'} by admin`);
  
  res.redirect(`/admin?token=${encodeURIComponent(process.env.ADMIN_TOKEN)}`);
});

app.get('/admin/reset-stats', (req, res) => {
  if (req.query.token !== process.env.ADMIN_TOKEN) {
    return res.status(403).send('Forbidden');
  }
  
  systemState.verificationSuccessRate = {
    attempts: 0,
    success: 0,
    lastReset: Date.now()
  };
  
  console.log('Verification statistics reset by admin');
  res.redirect(`/admin?token=${encodeURIComponent(process.env.ADMIN_TOKEN)}`);
});

app.get('/admin/clear-rate-limits', (req, res) => {
  if (req.query.token !== process.env.ADMIN_TOKEN) {
    return res.status(403).send('Forbidden');
  }
  
  rateLimiter.attempts.clear();
  rateLimiter.blacklist.clear();
  
  console.log('Rate limiting data cleared by admin');
  res.redirect(`/admin?token=${encodeURIComponent(process.env.ADMIN_TOKEN)}`);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to access the application`);
});

// Startup environment validation
function validateEnvironment() {
  const requiredVars = [
    { name: 'SECRET_KEY', minLength: 32 },
    { name: 'BUNGIE_CLIENT_ID', required: false },
    { name: 'BUNGIE_API_KEY', required: false },
    { name: 'AIRTABLE_API_KEY', required: false },
    { name: 'AIRTABLE_BASE_ID', required: false },
    { name: 'ADMIN_TOKEN', minLength: 16 }
  ];
  
  const issues = [];
  
  for (const v of requiredVars) {
    const value = process.env[v.name];
    
    if (v.required !== false && (!value || value.trim() === '')) {
      issues.push(`Missing required environment variable: ${v.name}`);
    } else if (value && v.minLength && value.length < v.minLength) {
      issues.push(`Environment variable ${v.name} is too short (minimum ${v.minLength} characters)`);
    }
  }
  
  // Special check for SECRET_KEY entropy
  if (process.env.SECRET_KEY) {
    const uniqueChars = new Set(process.env.SECRET_KEY.split('')).size;
    if (uniqueChars < 12) {
      issues.push('SECRET_KEY has low entropy - please use a more random string');
    }
  }
  
  if (issues.length > 0) {
    console.warn('⚠️ Environment validation issues:');
    issues.forEach(issue => console.warn(`  - ${issue}`));
    console.warn('Application will continue, but some features may not work correctly');
  } else {
    console.log('✅ Environment validation passed');
  }
  
  // Set a default admin token if not provided (development only)
  if (process.env.NODE_ENV !== 'production' && !process.env.ADMIN_TOKEN) {
    process.env.ADMIN_TOKEN = 'dev-admin-token-not-for-production';
    console.warn('⚠️ Using default development admin token - NOT SECURE FOR PRODUCTION');
  }
}

// Run environment validation at startup
validateEnvironment();

// Request ID middleware for logging correlation
app.use((req, res, next) => {
  req.requestId = crypto.randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', req.requestId);
  
  // Add request-scoped logger
  req.log = {
    info: (message, data = {}) => {
      console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'INFO',
        requestId: req.requestId,
        message,
        ...sanitizeLogData(data)
      }));
    },
    warn: (message, data = {}) => {
      console.warn(JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'WARN',
        requestId: req.requestId,
        message,
        ...sanitizeLogData(data)
      }));
    },
    error: (message, error, data = {}) => {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'ERROR',
        requestId: req.requestId,
        message,
        error: error?.message || error,
        stack: process.env.NODE_ENV !== 'production' ? error?.stack : undefined,
        ...sanitizeLogData(data)
      }));
    }
  };
  
  next();
});

// Sanitize sensitive data in logs
function sanitizeLogData(data) {
  const sanitized = { ...data };
  
  // List of keys that might contain sensitive data
  const sensitiveKeys = [
    'token', 'accessToken', 'apiKey', 'secret', 'password', 'authorization', 
    'BUNGIE_CLIENT_SECRET', 'BUNGIE_API_KEY', 'AIRTABLE_API_KEY', 'SECRET_KEY', 'ADMIN_TOKEN'
  ];
  
  // Recursively sanitize objects
  function sanitizeObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    
    const result = Array.isArray(obj) ? [...obj] : { ...obj };
    
    for (const key in result) {
      if (sensitiveKeys.some(k => key.toLowerCase().includes(k.toLowerCase()))) {
        result[key] = '[REDACTED]';
      } else if (typeof result[key] === 'object') {
        result[key] = sanitizeObject(result[key]);
      }
    }
    
    return result;
  }
  
  return sanitizeObject(sanitized);
}

// Add cache control middleware for sensitive routes
app.use(['/admin', '/verify', '/email-verify', '/callback', '/health'], (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// Track last health check time to prevent race conditions
let lastHealthCheckTime = {
  airtable: 0,
  bungie: 0
};

// Add health check mutex to prevent race conditions
const healthCheckMutex = {
  airtable: false,
  bungie: false
};

// Improved checkAirtableHealth function with mutex protection
async function checkAirtableHealth() {
  // Prevent concurrent health checks
  if (healthCheckMutex.airtable) {
    return;
  }
  
  // Check if a health check was performed recently
  const now = Date.now();
  if (now - lastHealthCheckTime.airtable < 30000) { // 30 seconds
    return;
  }
  
  try {
    // Acquire mutex
    healthCheckMutex.airtable = true;
    lastHealthCheckTime.airtable = now;
    
    if (!process.env.AIRTABLE_API_KEY || !process.env.AIRTABLE_BASE_ID) {
      console.log('Airtable not configured - skipping health check');
      systemState.airtableHealthy = false;
      return;
    }
    
    if (!table) {
      // Try to reinitialize
      try {
        console.log('Attempting to reinitialize Airtable connection...');
        const base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY }).base(process.env.AIRTABLE_BASE_ID);
        table = base('Applications');
        console.log('Airtable connection reinitialized');
      } catch (error) {
        console.error('Failed to reinitialize Airtable connection:', error);
        systemState.airtableHealthy = false;
        return;
      }
    }
    
    // Perform a small query to confirm connection works
    const testQuery = await table.select({
      maxRecords: 1,
      view: 'Grid view'
    }).firstPage();
    
    systemState.airtableHealthy = true;
    
    // Remove from degraded services list if it was there
    const index = systemState.degradedServices.indexOf('airtable');
    if (index !== -1) {
      systemState.degradedServices.splice(index, 1);
    }
    
    console.log('Airtable connection healthy');
  } catch (error) {
    console.error('Airtable health check failed:', error);
    systemState.airtableHealthy = false;
    
    // Add to degraded services if not already there
    if (!systemState.degradedServices.includes('airtable')) {
      systemState.degradedServices.push('airtable');
    }
  } finally {
    // Release mutex
    healthCheckMutex.airtable = false;
  }
}

// Improved checkBungieApiHealth function with mutex protection
async function checkBungieApiHealth() {
  // Prevent concurrent health checks
  if (healthCheckMutex.bungie) {
    return;
  }
  
  // Check if a health check was performed recently
  const now = Date.now();
  if (now - lastHealthCheckTime.bungie < 30000) { // 30 seconds
    return;
  }
  
  try {
    // Acquire mutex
    healthCheckMutex.bungie = true;
    lastHealthCheckTime.bungie = now;
    
    if (!BUNGIE_API_KEY) {
      console.log('Bungie API not configured - skipping health check');
      systemState.bungieApiHealthy = false;
      return;
    }
    
    // Set up API request timeout to prevent hanging
    const axiosWithTimeout = axios.create({
      timeout: 5000 // 5 second timeout for health check
    });
    
    // Make a simple request to check if API is working
    const response = await axiosWithTimeout.get('https://www.bungie.net/Platform/Settings/', {
      headers: {
        'X-API-Key': BUNGIE_API_KEY
      }
    });
    
    if (response.status === 200 && response.data && response.data.ErrorCode === 1) {
      systemState.bungieApiHealthy = true;
      systemState.lastCheckedBungie = now;
      
      // Remove from degraded services list if it was there
      const index = systemState.degradedServices.indexOf('bungie-api');
      if (index !== -1) {
        systemState.degradedServices.splice(index, 1);
      }
    } else {
      systemState.bungieApiHealthy = false;
      if (!systemState.degradedServices.includes('bungie-api')) {
        systemState.degradedServices.push('bungie-api');
      }
      console.warn('Bungie API returned unexpected response:', response.status, response.data?.ErrorCode);
    }
  } catch (error) {
    systemState.bungieApiHealthy = false;
    if (!systemState.degradedServices.includes('bungie-api')) {
      systemState.degradedServices.push('bungie-api');
    }
    console.error('Bungie API health check failed:', error.message);
  } finally {
    // Release mutex
    healthCheckMutex.bungie = false;
  }
}

// Add token refresh capability to email-verify endpoint
app.get('/refresh-token', (req, res) => {
  const { nickname, submissionId } = req.query;
  
  if (!nickname || !submissionId) {
    return renderVerificationError(
      res, 
      'Missing Information', 
      'Both nickname and submission ID are required to refresh your verification token.'
    );
  }
  
  try {
    // Generate new token with current timestamp
    const newToken = generateVerificationToken(nickname, submissionId);
    const verificationUrl = `${req.protocol}://${req.get('host')}/email-verify?nickname=${encodeURIComponent(nickname)}&submissionId=${encodeURIComponent(submissionId)}&token=${encodeURIComponent(newToken)}`;
    
    return res.send(`
      <html>
        <head>
          <title>New Verification Link</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #c4ff00; }
            .link-container { 
              background: rgba(255,255,255,0.1); 
              padding: 15px; 
              border-radius: 5px; 
              margin: 20px 0; 
              word-break: break-all;
              text-align: left;
            }
            .btn { 
              display: inline-block; 
              padding: 10px 20px; 
              background-color: #c4ff00; 
              color: #000; 
              text-decoration: none; 
              border-radius: 4px; 
              margin-top: 20px;
              font-weight: bold;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>New Verification Link</h1>
            <p>A new verification link has been generated for you:</p>
            <div class="link-container">
              <a href="${escapeHtml(verificationUrl)}">${escapeHtml(verificationUrl)}</a>
            </div>
            <p>This link will expire in 48 hours.</p>
            <a href="${escapeHtml(verificationUrl)}" class="btn">VERIFY NOW</a>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    req.log.error('Error generating refresh token', error, { nickname, submissionId });
    return renderVerificationError(
      res, 
      'Token Generation Failed', 
      'An error occurred while generating a new verification token. Please try again or contact support.'
    );
  }
});