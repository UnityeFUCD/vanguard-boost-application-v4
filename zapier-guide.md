# Zapier Integration Guide for Vanguard Boost Application Email Verification

This guide explains how to set up a Zapier workflow that sends verification emails to applicants with secure verification links.

## Overview

When a new application is submitted:
1. Netlify Form submission triggers Zapier
2. Zapier creates a record in Airtable
3. Zapier generates a verification token
4. Zapier sends an email with the secure verification link
5. User clicks the link and completes Bungie verification

## Step 1: Trigger - New Netlify Form Submission

1. Choose "Netlify" as your app
2. Select "New Form Submission" as the trigger
3. Connect your Netlify account
4. Select "applicationForm" as the form

## Step 2: Airtable Record Creation

1. Add an Airtable action
2. Choose "Create Record" as the action
3. Connect your Airtable account
4. Select your base and table
5. Map the following fields:
   - `nickname`: The submitted Bungie ID
   - `email`: The submitted email
   - `discord`: The submitted Discord handle
   - Other fields as needed

## Step 3: Generate Verification Token

1. Add a "Code by Zapier" action
2. Select "Run JavaScript" as the action
3. Use this code to generate a token:

```javascript
const crypto = require('crypto');

function generateVerificationToken(nickname, submissionId) {
  // The secret should match what's on your server
  const SECRET_KEY = 'vanguard-boost-verification-secret';
  const data = `${nickname}:${submissionId}:${SECRET_KEY}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Get values from previous steps
const nickname = inputData.nickname;
const submissionId = inputData.id; // Airtable record ID

const token = generateVerificationToken(nickname, submissionId);

return {
  token: token
};
```

## Step 4: Send Verification Email

1. Add an "Email by Zapier" or "Gmail" action
2. Select "Send Email" as the action
3. Configure the email fields:
   - **To**: Use the applicant's email
   - **Subject**: "Vanguard Boost Application Confirmation - Action Required"
   - **Body**: Use the HTML email template with the following variables replaced:
     - `{{nickname}}`: The applicant's Bungie ID from the form
     - `{{submissionId}}`: The Airtable record ID
     - `{{verificationToken}}`: The token from step 3
     - `{{verificationUrl}}`: The full URL (or construct it in the template)

## Important Security Notes

1. The `SECRET_KEY` in Zapier must match the one on your server
2. Always encode the nickname and submissionId in the URL parameters
3. For production, consider moving the token generation to a secure server/API
4. The system is secure against attempts to modify the verification parameters because of the token validation

## Testing

After setting up the Zap, you can test it by:
1. Submitting your form manually
2. Checking if the email is received with the correct verification link
3. Clicking the link and ensuring it redirects to Bungie OAuth
4. Completing verification and confirming the Airtable record is updated

## Troubleshooting

- If the verification link doesn't work, check if the token generation in Zapier matches the server
- Ensure URL parameters are properly encoded
- Check server logs for more detailed error information

For more advanced setup or custom needs, contact the development team. 