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
    
    // Check if token is expired (e.g., 48 hours)
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

// Email verification endpoint
app.get('/email-verify', async (req, res) => {
  const { nickname, submissionId, token } = req.query;
  
  // First, immediately show a loading screen while we process
  res.write(`
    <html>
      <head>
        <title>Verifying Your Identity</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
          .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
          h1 { color: #c4ff00; }
          .loader { 
            border: 5px solid rgba(0,0,0,0.3);
            border-top: 5px solid #c4ff00;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        </style>
        <script>
          // This prevents the "loading" page from being stored in browser history
          window.history.replaceState(null, document.title, window.location.href);
        </script>
      </head>
      <body>
        <div class="container">
          <h1>Verifying Your Identity</h1>
          <div class="loader"></div>
          <p>Please wait while we verify your Bungie identity...</p>
        </div>
      </body>
    </html>
  `);

  // Process verification after showing loading screen
  try {
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
        return finishResponse(res, `
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
      return finishResponse(res, `
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
        return finishResponse(res, `
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
      
      // Try to help the user - STRICT: Only lookup by submissionId
      if (table && submissionId) {
        try {
          // Try to find the record ONLY by submissionId - no nickname lookups for security
          let recordFound = null;
          try {
            recordFound = await table.find(submissionId).catch(e => null);
          } catch (e) {
            // Not a valid record ID format
            console.warn('Invalid submission ID format:', submissionId);
          }
          
          if (recordFound) {
            // Check if already verified
            if (recordFound.get('verified') === true) {
              // Already verified - show success message
              return finishResponse(res, `
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
            
            return finishResponse(res, `
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
      return finishResponse(res, `
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
    
    // Final check with Airtable (token is valid at this point) - STRICT: Only lookup by submissionId
    if (table && submissionId) {
      try {
        let recordFound = null;
        
        // Try to find by submissionId only - direct lookup
        try {
          recordFound = await table.find(submissionId).catch(e => null);
        } catch (e) {
          // Not a valid record ID format - handle this case explicitly
          return finishResponse(res, `
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
                  <p>Invalid submission ID format.</p>
                  <p>Please use the exact link provided in your email.</p>
                </div>
              </body>
            </html>
          `);
        }
        
        if (recordFound) {
          // If already verified, show success message
          if (recordFound.get('verified') === true) {
            return finishResponse(res, `
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
          // No record found with this submissionId, but token is valid - show clear error
          return finishResponse(res, `
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
                      <li>Ensure you've submitted your application</li>
                      <li>Try again later - sometimes database updates take a moment</li>
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
        return finishResponse(res, `
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
                <p>An error occurred while checking your verification status.</p>
                <p>Please try again later or contact support.</p>
              </div>
            </body>
          </html>
        `);
      }
    }
    
    // If we got here, the token is valid but we need to redirect to Bungie OAuth for verification
    const state = encodeURIComponent(JSON.stringify({
      nickname,
      submissionId
    }));
    
    const authUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${BUNGIE_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}`;
    
    return finishResponse(res, null, authUrl);
  } catch (error) {
    console.error('Unexpected error in email verification:', error);
    return finishResponse(res, `
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
            <p>An unexpected error occurred during verification.</p>
            <p>Please try again later or contact support.</p>
          </div>
        </body>
      </html>
    `);
  }
});

// Helper function to finish streaming response
function finishResponse(res, html, redirectUrl = null) {
  if (!res.headersSent) {
    if (redirectUrl) {
      return res.redirect(redirectUrl);
    } else {
      return res.send(html);
    }
  } else {
    // For streaming responses where headers were already sent
    res.write(`
      <script>
        document.open();
        document.write(\`${html.replace(/`/g, '\\`')}\`);
        document.close();
        ${redirectUrl ? `window.location.href = "${redirectUrl}";` : ''}
      </script>
    `);
    return res.end();
  }
}

// Netlify form handling - this is a fallback in case the Netlify forms handling doesn't work
app.post('/', (req, res) => {
  console.log('Form submitted via POST to root:', req.body);
  res.redirect('/thank-you.html?applicationId=' + encodeURIComponent(req.body.applicationId || ''));
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

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to access the application`);
});