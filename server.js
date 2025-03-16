// Express server setup
const express = require('express');
const axios = require('axios');
require('dotenv').config();
const app = express();
const PORT = process.env.PORT || 3195;

// Serve static files from the public directory
app.use(express.static('public'));

// Airtable setup
const Airtable = require('airtable');
const base = new Airtable({ apiKey: process.env.AIRTABLE_API_KEY }).base(process.env.AIRTABLE_BASE_ID);
const table = base(process.env.AIRTABLE_TABLE_NAME);

// Bungie API credentials
const BUNGIE_CLIENT_ID = process.env.BUNGIE_CLIENT_ID;
const BUNGIE_CLIENT_SECRET = process.env.BUNGIE_CLIENT_SECRET;
const BUNGIE_API_KEY = process.env.BUNGIE_API_KEY;
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://vanguard-bungie-verify-c7de395776dd.herokuapp.com/callback';

// Middleware to parse JSON
app.use(express.json());

app.get('/callback', async (req, res) => {
  try {
    // Get the authorization code and state (which holds the application nickname) from the URL
    const { code, state, error, error_description } = req.query;
    
    // Handle error cases from Bungie OAuth
    if (error) {
      console.log(`OAuth error: ${error} - ${error_description}`);
      return res.status(400).send(`
        <html>
          <head>
            <title>Verification Error</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #ffffff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: 0 auto; background-color: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
              .error-icon { font-size: 60px; color: #ff3e3e; margin-bottom: 20px; }
              .details { text-align: left; background-color: rgba(255,62,62,0.1); padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="error-icon">✗</div>
              <h1>Verification Error</h1>
              <p>${error_description || error}</p>
              <p>Please try again with the correct parameters.</p>
            </div>
          </body>
        </html>
      `);
    }
    
    if (!code) return res.status(400).send('Authorization code missing');
    if (!state) return res.status(400).send('State parameter missing');

    // The state parameter contains the nickname provided by the applicant
    const userNickname = decodeURIComponent(state);
    console.log('Received nickname from state parameter:', userNickname);

    // Exchange the authorization code for an access token, including the client secret
    console.log('Exchanging code for token...');
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
    
    console.log('Token response received');
    const accessToken = tokenResponse.data.access_token;
    const tokenType = tokenResponse.data.token_type;
    
    if (!accessToken) {
      console.log('No access token in response:', tokenResponse.data);
      throw new Error('Failed to get access token');
    }
    
    console.log('Access token obtained, fetching user info...');

    // Retrieve Bungie user info using the access token
    const userResponse = await axios.get(
      'https://www.bungie.net/platform/User/GetMembershipsForCurrentUser/',
      {
        headers: {
          'Authorization': `${tokenType} ${accessToken}`,
          'X-API-Key': BUNGIE_API_KEY
        }
      }
    );

    console.log('User API response received');
    console.log('Response status:', userResponse.status);
    console.log('Response data structure:', JSON.stringify(Object.keys(userResponse.data)));
    
    if (userResponse.data && userResponse.data.Response) {
      console.log('Response content:', JSON.stringify(userResponse.data.Response, null, 2));
    }

    // Try to get the display name from the Bungie.net profile
    let bungieUsername = null;
    let bungieCode = null;
    let fullBungieName = null;
    
    if (userResponse.data && 
        userResponse.data.Response && 
        userResponse.data.Response.bungieNetUser) {
        
      bungieUsername = userResponse.data.Response.bungieNetUser.displayName;
      
      // Try to get the unique code if it exists
      if (userResponse.data.Response.bungieNetUser.uniqueName) {
        const uniqueNameParts = userResponse.data.Response.bungieNetUser.uniqueName.split('#');
        if (uniqueNameParts.length > 1) {
          bungieCode = uniqueNameParts[1];
        }
      }
      
      // If we couldn't get the code from uniqueName, check for it directly
      if (!bungieCode && 
          userResponse.data.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode !== undefined) {
        bungieCode = userResponse.data.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode;
      }
      
      // Combine into full name
      if (bungieUsername) {
        if (bungieCode) {
          fullBungieName = `${bungieUsername}#${bungieCode}`;
        } else {
          fullBungieName = bungieUsername;
        }
      }
    }

    console.log('Bungie username:', bungieUsername);
    console.log('Bungie code:', bungieCode);
    console.log('Full Bungie name:', fullBungieName);
    console.log('Application nickname:', userNickname);

    // Check if we have a valid Bungie name to compare
    if (!fullBungieName) {
      console.log('Error: Could not retrieve Bungie username');
      return res.status(400).send(`
        <html>
          <head>
            <title>Verification Failed</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #ffffff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: 0 auto; background-color: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
              .error-icon { font-size: 60px; color: #ff3e3e; margin-bottom: 20px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="error-icon">✗</div>
              <h1>Verification Failed</h1>
              <p>We couldn't retrieve your Bungie username. Please make sure you're logged into Bungie.net and try again.</p>
            </div>
          </body>
        </html>
      `);
    }

    // Compare the full Bungie name with the nickname from the application (case-insensitive)
    // Both must be strings to use toLowerCase()
    const bungieNameLower = String(fullBungieName).toLowerCase();
    const userNicknameLower = String(userNickname).toLowerCase();
    
    console.log(`Comparing "${bungieNameLower}" with "${userNicknameLower}"`);
    
    if (bungieNameLower === userNicknameLower) {
      console.log('Username verified successfully!');

      // After successful verification, update the Airtable record
      try {
        const records = await table.select({
          filterByFormula: `{nickname} = '${userNickname}'`
        }).firstPage();

        if (records.length > 0) {
          // Update the record to mark it as verified and store the full Bungie username
          await table.update(records[0].id, {
            verified: true,
            bungieUsername: fullBungieName
          });
          console.log('Airtable record updated successfully');
        } else {
          console.log('Could not find matching record in Airtable');
          // Verification is considered successful even if the record isn't found
        }
      } catch (airtableError) {
        console.error('Error updating Airtable:', airtableError);
      }

      return res.send(`
        <html>
          <head>
            <title>Verification Successful</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #ffffff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: 0 auto; background-color: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #c4ff00; }
              .success-icon { font-size: 60px; color: #c4ff00; margin-bottom: 20px; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="success-icon">✓</div>
              <h1>Verification Successful!</h1>
              <p>Your Bungie account has been successfully verified.</p>
              <p>You may now close this window and return to Discord.</p>
            </div>
          </body>
        </html>
      `);
    } else {
      console.log('Verification failed: username mismatch');
      console.log(`Comparing "${bungieNameLower}" with "${userNicknameLower}"`);
      
      return res.status(400).send(`
        <html>
          <head>
            <title>Verification Failed</title>
            <style>
              body { font-family: Arial, sans-serif; background-color: #101114; color: #ffffff; text-align: center; padding: 50px 20px; }
              .container { max-width: 600px; margin: 0 auto; background-color: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
              h1 { color: #ff3e3e; }
              .error-icon { font-size: 60px; color: #ff3e3e; margin-bottom: 20px; }
              .details { text-align: left; background-color: rgba(255,62,62,0.1); padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="error-icon">✗</div>
              <h1>Verification Failed</h1>
              <p>The Bungie username does not match the nickname you provided in your application.</p>
              <div class="details">
                <p><strong>Bungie Username:</strong> ${fullBungieName}</p>
                <p><strong>Application Nickname:</strong> ${userNickname}</p>
              </div>
              <p>Please make sure you're logged in with the correct Bungie account and try again.</p>
            </div>
          </body>
        </html>
      `);
    }
  } catch (error) {
    console.error('Error during verification:', error);
    
    // Log detailed error information
    if (error.response) {
      console.log('Error response status:', error.response.status);
      console.log('Error response data:', JSON.stringify(error.response.data, null, 2));
    }
    
    let errorMessage = 'An unexpected error occurred during verification.';
    if (error.response) {
      if (error.response.status === 401) {
        errorMessage = 'Authentication failed. Please try again.';
      } else if (error.response.data && error.response.data.error_description) {
        errorMessage = error.response.data.error_description;
      }
    }
    
    return res.status(500).send(`
      <html>
        <head>
          <title>Verification Error</title>
          <style>
            body { font-family: Arial, sans-serif; background-color: #101114; color: #ffffff; text-align: center; padding: 50px 20px; }
            .container { max-width: 600px; margin: 0 auto; background-color: rgba(0,0,0,0.5); padding: 30px; border-radius: 8px; }
            h1 { color: #ff3e3e; }
            .error-icon { font-size: 60px; color: #ff3e3e; margin-bottom: 20px; }
            .details { text-align: left; background-color: rgba(255,62,62,0.1); padding: 15px; border-radius: 5px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="error-icon">✗</div>
            <h1>Verification Error</h1>
            <p>${errorMessage}</p>
            <p>Please try again later.</p>
          </div>
        </body>
      </html>
    `);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});