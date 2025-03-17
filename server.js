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

// Function to generate a verification token
function generateVerificationToken(nickname, submissionId) {
  const data = `${nickname}:${submissionId}:${SECRET_KEY}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Function to validate a verification token
function validateVerificationToken(nickname, submissionId, token) {
  const expectedToken = generateVerificationToken(nickname, submissionId);
  return token === expectedToken;
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
            <p>Please try again.</p>
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
    // Try to parse state as a JSON object
    const decodedState = decodeURIComponent(state);
    if (decodedState.startsWith('{') && decodedState.includes('"nickname"')) {
      try {
        // It's a JSON object
        const stateData = JSON.parse(decodedState);
        userNickname = stateData.nickname || '';
        applicationId = stateData.applicationId || '';
        submissionId = stateData.submissionId || '';
        console.log(`Parsed from JSON - Nickname: ${userNickname}, ApplicationId: ${applicationId}, SubmissionId: ${submissionId}`);
      } catch (jsonError) {
        console.error('Error parsing JSON state:', jsonError);
        userNickname = decodedState;
      }
    } else {
      // It's just a simple string (old format)
      userNickname = decodedState;
      console.log(`Using direct format - Nickname: ${userNickname}`);
    }
  } catch (e) {
    // Fallback for any decoding errors
    try {
      userNickname = state; // Use raw state as fallback
      console.log(`Using raw state: ${userNickname}`);
    } catch (decodeErr) {
      console.error('Failed to decode state parameter:', decodeErr);
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
    
    const normalizedUserNickname = String(nicknameForComparison).toLowerCase().trim();

    console.log(`Comparing normalized values: "${normalizedBungieName}" vs. "${normalizedUserNickname}"`);

    // ONLY do exact matching - nothing else is acceptable
    const matched = normalizedBungieName === normalizedUserNickname;
    
    if (matched) {
      console.log('Username verified successfully - exact match!');

      // Update Airtable record (if found)
      if (table) {
        try {
          let records = [];
          
          // First try to find a record by submissionId (most reliable)
          if (submissionId) {
            records = await table.select({
              filterByFormula: `{submissionId} = '${submissionId}'`
            }).firstPage();
            
            if (records.length > 0) {
              console.log('Found record by submissionId');
            }
          }
          
          // Next try applicationId
          if (records.length === 0 && applicationId) {
            records = await table.select({
              filterByFormula: `{applicationId} = '${applicationId}'`
            }).firstPage();
            
            if (records.length > 0) {
              console.log('Found record by applicationId');
            }
          }
          
          // If no records found, try nickname as fallback
          if (records.length === 0) {
            records = await table.select({
              filterByFormula: `OR({nickname} = '${userNickname}', {bungieID} = '${normalizedUserNickname}')`
            }).firstPage();
            
            if (records.length > 0) {
              console.log('Found record by nickname');
            }
          }

          if (records.length > 0) {
            await table.update(records[0].id, {
              verified: true,
              bungieUsername: fullBungieName,
              verificationDate: new Date().toISOString()
            });
            console.log('Airtable record updated successfully.');
          } else {
            console.warn('No matching Airtable record found for submissionId, applicationId, or nickname:', submissionId, applicationId, userNickname);
            // Try one more time with a substring search
            try {
              const fuzzyRecords = await table.select({
                filterByFormula: `OR(SEARCH('${normalizedUserNickname}', LOWER({nickname})), SEARCH('${normalizedUserNickname}', LOWER({bungieID})))`
              }).firstPage();
              
              if (fuzzyRecords.length > 0) {
                await table.update(fuzzyRecords[0].id, {
                  verified: true,
                  bungieUsername: fullBungieName,
                  verificationDate: new Date().toISOString()
                });
                console.log('Airtable record updated via fuzzy match.');
              }
            } catch (fuzzyError) {
              console.error('Error with fuzzy search:', fuzzyError);
            }
          }
        } catch (atError) {
          console.error('Error updating Airtable:', atError);
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
            </style>
          </head>
          <body>
            <div class="container">
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
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Verification Failed</h1>
              <div class="details">
                <p><strong>Bungie Username:</strong> ${fullBungieName}</p>
                <p><strong>Your Nickname:</strong> ${userNickname}</p>
              </div>
              <p>Please ensure you're using the same Bungie account as you entered in your application.</p>
              <p>Note: Make sure to include the full ID with "#" and numbers.</p>
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
            <p>Please use the link provided in your email.</p>
          </div>
        </body>
      </html>
    `);
  }
  
  // Validate the token
  if (!validateVerificationToken(nickname, submissionId, token)) {
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
  
  // Check if this submission is already verified
  if (table) {
    try {
      const records = await table.select({
        filterByFormula: `{submissionId} = '${submissionId}'`
      }).firstPage();
      
      if (records.length > 0) {
        const record = records[0];
        
        // If already verified, show success message
        if (record.get('verified') === true) {
          return res.send(`
            <html>
              <head>
                <title>Already Verified</title>
                <style>
                  body { font-family: Arial, sans-serif; background-color: #101114; color: #fff; text-align: center; padding: 50px 20px; }
                  .container { max-width: 600px; margin: auto; background: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
                  h1 { color: #c4ff00; }
                </style>
              </head>
              <body>
                <div class="container">
                  <h1>Already Verified</h1>
                  <p>Your Bungie identity has already been verified successfully.</p>
                  <p>No further action is needed. Your application is being reviewed.</p>
                </div>
              </body>
            </html>
          `);
        }
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