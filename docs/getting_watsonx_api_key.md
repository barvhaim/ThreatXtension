# Getting a Watsonx.ai API Key
To obtain a Watsonx.ai API key, follow these steps:

1. **Sign up for IBM Cloud**:
    - Go to the [IBM Cloud](https://cloud.ibm.com/) website.
    - If you do not have an account, click on "Create an IBM Cloud account" and follow the instructions to sign up.

2. **Create a Watsonx.ai Service**:
    - Once logged in, navigate to the IBM Cloud Dashboard.
    - Click on "Catalog" in the top menu.
    - Search for "Watsonx.ai" and select the service.
    - Click on "Create" to provision the service.

3. **Generate an API Key**:
    - After the service is created, go to the "Manage" tab of your Watsonx.ai service instance.
    - Click on "Service credentials" in the left-hand menu.
    - Click on "New credential" to generate a new API key.
    - Provide a name for the credential and click "Add".
    - Your new API key will be displayed. Copy this key for use in your application.

4. **Configure the API Key in Your Application**:
    - Open the `.env` file in your project.
    - Add the following line, replacing `YOUR_API_KEY` with the API key you copied:
      ```dotenv
      WATSONX_API_KEY=YOUR_API_KEY
      ```

By following these steps, you will obtain and configure your Watsonx.ai API key for use in your application.

You can find the IBM Watsonx.ai API documentation at the following link:
[IBM Watsonx.ai API Documentation](https://cloud.ibm.com/apidocs/watsonx-ai)
