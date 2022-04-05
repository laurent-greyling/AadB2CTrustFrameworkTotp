# Setup Azure Active Directory B2C

`AAD B2C` provides business-to-customer identity as a service. Customers use their provided identities to get single sign-on access to the applications and APIs.

`AAD B2C` is a customer identity access management `(CIAM)` solution capable of supporting millions of users and billions of authentications per day. It takes care of the scaling and safety of the authentication platform, monitoring, and automatically handling threats like denial-of-service, password spray, or brute force attacks.

`AAD B2C` is a separate service from Azure Active Directory (Azure AD). It is built on the same technology as Azure AD but for a different purpose. It allows you to build customer facing applications, and then allow anyone who is invited into the tenant to have access to these applications.

## Create AAD B2C tenant

1. Switch to the `subscription` which will contain the tenant
2. Register `AAD` for use in the subscription
    - Open powershell (Admin) and run the following commands in order:

```powershell

# Login to your azure account
az login

# Set the subscription that will contain the AAD B2C
az account set --subscription "<your subscription name>"

# register AAD
az provider register --namespace Microsoft.AzureActiveDirectory

```

3. Navigate to the resource group that will hold the `AAD B2C`.
4. Click on the create resource
5. In the search bar, type `b2c` and select `Azure Active Directory B2C` and create
6. Select `Create a new Azure AD B2C Tenant`
7. A screen will appear allowing you to fill in the resource details. For naming:

|Field|Dev Name|Acceptance Name|Prod Name|
|--|--|--|--|
|Organization Name|B2C Dev|B2C Accept|B2C Prod|
|Initial domain name|b2c`company`dev|b2c`company`acc|b2c`company`prod|
|Country/Region|Netherlands|Netherlands|Netherlands|
|Subscription|Dev Sub|Acceptance Sub|Prod/Client Sub|
|Resource Group|Selected|Selected|Selected|

8. Click next to create and review and create the `AAD B2C` resource
9. Once the creation is complete, you should be able to find the tenant in your resource group and navigate to the tenant.
   - On Overview page click on `Open B2C Tenant`, this will navigate you to the newly created B2C tenant

## Link AAD B2C tenant to subscription (Billing)

1. Sign in to the Azure portal.
2. Make sure you're using the directory that has your Azure AD subscription, and not the directory containing your `AAD B2C` tenant. Select the Directories + subscriptions icon in the portal toolbar.
3. On the `Portal settings | Directories + subscriptions` page, find your Azure AD directory (main sub) in the Directory name list, and then select Switch.
4. Select Create a resource, and then, in the Search services and Marketplace field, search for and select `Azure Active Directory B2C`.
5. Select Create.
6. Select Link an existing `AAD B2C` Tenant to my Azure subscription.
7. Select an `AAD B2C` Tenant from the dropdown. Only tenants for which you're a global administrator and that are not already linked to a subscription are shown. The `AAD B2C` Resource name field is populated with the domain name of the `AAD B2C` tenant you select.
8. Select an active Azure Subscription of which you're an administrator.
9. Under Resource group, select Create new, and then specify the Resource group location. The resource group settings here have no impact on your Azure AD B2C tenant location, performance, or billing status.
10. Select Create.

## Register Application

1. Sign in to the Azure portal.
2. Make sure you're using the directory that contains your `AAD B2C` tenant. Select the Directories + subscriptions icon in the portal toolbar.
3. On the Portal settings | Directories + subscriptions page, find your `AAD B2C` directory in the Directory name list, and then select Switch.
4. In the Azure portal, search for and select `AAD B2C`.
5. Select `App registrations`, and then select `New registration`.
6. Enter a Name for the application. For example, `webapp.company.dev`.
7. Under Supported account types, select `Accounts in any identity provider or organizational directory (for authenticating users with user flows)`.
8. Under Redirect URI, select Web, and then enter https://jwt.ms in the URL text box.

The redirect URI is the endpoint to which the user is sent by the authorization server (`AAD B2C`, in this case) after completing its interaction with the user, and to which an access token or authorization code is sent upon successful authorization. In a production application, it's typically a publicly accessible endpoint where your app is running, like https://contoso.com/auth-response. For testing purposes like this tutorial, you can set it to https://jwt.ms, a Microsoft-owned web application that displays the decoded contents of a token (the contents of the token never leave your browser). During app development, you might add the endpoint where your application listens locally, like https://localhost:5000. You can add and modify redirect URIs in your registered applications at any time.

The following restrictions apply to redirect URIs:

   - The reply URL must begin with the scheme `https`.
   - The reply URL is case-sensitive. Its case must match the case of the URL path of your running application. For example, if your application includes as part of its path `.../abc/response-oidc`, do not specify `.../ABC/response-oidc` in the reply URL. Because the web browser treats paths as case-sensitive, cookies associated with `.../abc/response-oidc` may be excluded if redirected to the case-mismatched `.../ABC/response-oidc URL`.

9. Under Permissions, select the `Grant admin consent to openid and offline_access permissions` check box.
10. Select Register.
11. In `App Registration ` select the app you registered
12. Under `Manage\Authentication` you can add a platform
13. As we will be developing a single page application `Click on Add Platform and select Single-page application`
14. For the redirect Uris in development add `https://localhost:{PORT}/signin-oidc`.
    - Once saved, add `https://localhost:{PORT}/authentication/login-callback`
    - `https://localhost:44442`
15. Under `Manage\Authentication` click check boxes for:
    - Access tokens (used for implicit flows)
    - ID tokens (used for implicit and hybrid flows)
16. Save
17. Make note of the `Application (client) ID` for later use in application
    - Under `Overview`

# Create user flows and custom policies in AAD B2C

For the purpose of this document

- User cannot sign-up only sign-in after invite
- User need to be forced to change password on first sign-in or after password reset
- User should be able to change own password
- Custom RBAC should be implemented for a user (special flow)
- User only uses Authenticator App for MFA
- Banned password list - can be expanded (see `TrustFrameworkExtension.xml` for current)

## Add signing and encryption keys for Identity Experience Framework applications

1. Go to `AAD B2C` tenant or sub containing it
2. On the overview page, under Policies, select `Identity Experience Framework`
3. Select Policy Keys and then select Add
4. For Options, choose Generate.
5. In Name, enter `TokenSigningKeyContainer`. The prefix B2C_1A_ might be added automatically.
6. For Key type, select `RSA`.
7. For Key usage, select Signature.
8. Select Create.
9. Select Policy Keys and then select Add.
10. For Options, choose Generate.
11. In Name, enter TokenEncryptionKeyContainer. The prefix B2C_1A_ might be added automatically.
12. For Key type, select RSA.
13. For Key usage, select Encryption.
14. Select Create.

## Register Identity Experience Framework applications

`AAD B2C` requires you to register two applications that it uses to sign up and sign in users with local accounts: `IdentityExperienceFramework`, a web API, and `ProxyIdentityExperienceFramework`, a native app with delegated permission to the IdentityExperienceFramework app. Local accounts exist only in your Azure AD B2C tenant.

You need to register these two applications in your `AAD B2C` tenant only once.

### Register the IdentityExperienceFramework application

1. Select `App registrations`, and then select `New registration`.
2. For Name, enter `IdentityExperienceFramework`.
3. Under Supported account types, `select Accounts in this organizational directory only`.
4. Under Redirect URI, select Web, and then enter `https://your-tenant-name.b2clogin.com/your-tenant-name.onmicrosoft.com`, where your-tenant-name is your `AAD B2C` tenant domain name.
5. Under Permissions, select the `Grant admin consent to openid and offline_access permissions` check box.
6. Select Register.
7. Record the Application (client) ID for use in a later step (Custom Templates).

Next, expose the API by adding a scope:

1. In the left menu, under `Manage`, select `Expose an API`.
2. Select `Add a scope`, then select Save and continue to accept the default application ID URI.
3. Enter the following values to create a scope that allows custom policy execution in your `AAD B2C` tenant:
   - Scope name: `user_impersonation`
   - Admin consent display name: `Access IdentityExperienceFramework`
   - Admin consent description: `Allow the application to access IdentityExperienceFramework on behalf of the signed-in user.
4. Select Add scope`

### Register the ProxyIdentityExperienceFramework application

1. Select App registrations, and then select New registration.
2. For Name, enter `ProxyIdentityExperienceFramework`.
3. Under Supported account types, select Accounts in this organizational directory only.
5. Under Redirect URI, use the drop-down to select `Public client/native (mobile & desktop)`.
6. For Redirect URI, enter `myapp://auth` (for now add fake my app name - e.g. `companyapp`).
    - Once we have a mobile app, we will change this accordingly
7. Under Permissions, select the `Grant admin consent to openid and offline_access permissions` check box.
8. Select Register.
9. Record the Application (client) ID for use in a later step.

Next, specify that the application should be treated as a public client:

1. In the left menu, under `Manage`, select `Authentication`.
2. Under `Advanced settings`, in the Allow public client flows section, set Enable the following mobile and desktop flows to Yes.
3. Select Save.
4. Ensure that `allowPublicClient`: true is set in the application manifest:
    - In the left menu, under Manage, select Manifest to open application manifest.
    - Find `allowPublicClient` key and ensure its value is set to true.

Now, grant permissions to the API scope you exposed earlier in the `IdentityExperienceFramework` registration:

1. In the left menu, under `Manage`, select `API permissions`.
2. Under `Configured permissions`, select `Add a permission`.
3. Select the My APIs tab, then select the `IdentityExperienceFramework` application.
4. Under Permission, select the `user_impersonation` scope that you defined earlier.
5. Select `Add permissions`. As directed, wait a few minutes before proceeding to the next step.
6. Select Grant admin consent for `your tenant name`.
7. Select Yes.
8. Select Refresh, and then verify that `Granted for ...` appears under Status for the scope.

# AAD B2C Custom templates

Custom policies are a set of `XML` files you upload to `AAD B2C` tenant to define technical profiles and user journeys.

The folder `TOTP_Rbac` contains the custom template for signin with features for:

- Custom Rbac => needs a function/api to assign the role to the JWT token
- Force Password reset on first signin or after a password reset
- MFA with authentication app
- Forgot password flow
- User cannot sign-up only sign-in after invite
- Banned password list - can be expanded (see `TrustFrameworkExtension.xml` for current)

To get the full set of custom templates, unmodified for this portion, you can go to:

- https://github.com/azure-ad-b2c/samples/tree/master/policies
- https://github.com/Azure-Samples/active-directory-b2c-custom-policy-starterpack/tree/3b4898fec3bf0014b320beffa6eb52ad68eb6111

Templates:

|||
|--|--|
|TrustFrameworkBase| Base trust framework, does not need to be changed|
|TrustFrameworkLocalization| For localization purposes, add and change language settings. The Localization file also has example for adding translations, see file|
|TrustFrameworkExtensions| Heavy customization to allow for the different components and user journeys|
|SignUpOrSignin| For the normal signin flow, signUp is disabled in our template|
|PasswordReset| Handles Password forgot flow|

## Usage

Before we can use these templates there are a few things to update in the templates. __NOTE__ do not change the templates with secret info in the git branch, use a copy to do this and upload. __DO NOT__ check in any secret info.

1. For all of the templates, change `yourtenant` to the the tenant you created. In all of them you will come across the following section of code to change

```xml

  TenantId="yourtenant.onmicrosoft.com" 
  PolicyId="B2C_1A_PasswordReset" 
  PublicPolicyUri="http://yourtenant.onmicrosoft.com/B2C_1A_PasswordReset">

  <BasePolicy>
    <TenantId>yourtenant.onmicrosoft.com</TenantId>
    <PolicyId>B2C_1A_TrustFrameworkExtensions</PolicyId>
  </BasePolicy>

```

2. In the `TrustFrameworkExtensions.xml` find the following node

```XML
<DisplayName>Local Account SignIn</DisplayName>
      <TechnicalProfiles>
         <TechnicalProfile Id="login-NonInteractive">
          <Metadata>
            <Item Key="client_id">ProxyIdentityExperienceFramework</Item>
            <Item Key="IdTokenAudience">IdentityExperienceFramework</Item>
          </Metadata>
          <InputClaims>
            <InputClaim ClaimTypeReferenceId="client_id" DefaultValue="ProxyIdentityExperienceFramework" />
            <InputClaim ClaimTypeReferenceId="resource_id" PartnerClaimType="resource" DefaultValue="IdentityExperienceFramework" />
            <InputClaim ClaimTypeReferenceId="continueOnPasswordExpiration" DefaultValue="true"/>
          </InputClaims>
          <OutputClaims>
            <!-- Indicates whether user needs to reset the password.
            If yes, this is the only claim that returns. Other claims aren't return-->
            <OutputClaim ClaimTypeReferenceId="forceChangePasswordNextLogin" PartnerClaimType="passwordExpired"/>
          </OutputClaims>
        </TechnicalProfile>

```

Update the `client_id` and `resource_id` with that of the Application (Client) Id of the registered apps. 
    - You can find them in your tenant under `Manage` and then `App Registration`

3. In the `TrustFrameworkExtensions.xml` find the Node that will call Function to add the custom role

```xml

    <ClaimsProvider>
      <DisplayName>Rest Api</DisplayName>
      <TechnicalProfiles>
        <TechnicalProfile Id="REST-UserMembershipValidator">
        <DisplayName>Validate user role claim</DisplayName>
        <Protocol Name="Proprietary" Handler="Web.TPEngine.Providers.RestfulProvider, Web.TPEngine, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
          <Metadata>
            <Item Key="ServiceUrl">https://testroleb2c.azurewebsites.net/api/GetRoles?code=9UxMPAGXk7OM9tbNI7RHrpdWea8DGxtyet30JyvTwP1AJSKWsoyKk==</Item>
            <Item Key="AuthenticationType">None</Item>
            <Item Key="SendClaimsIn">Body</Item>
            <Item Key="AllowInsecureAuthInProduction">true</Item>
          </Metadata>
          <InputClaims>
            <InputClaim ClaimTypeReferenceId="signInNames.emailAddress" PartnerClaimType="emails"/>
            <InputClaim ClaimTypeReferenceId="email" PartnerClaimType="email"/>
          </InputClaims>
          <OutputClaims>
            <OutputClaim ClaimTypeReferenceId="role" PartnerClaimType="role" />
          </OutputClaims>
        </TechnicalProfile>
      </TechnicalProfiles>
    </ClaimsProvider>

```

- Replace the `ServiceUrl` with the `function/api` Uri that need to trigger the role to be added
- For production `AllowInsecureAuthInProduction` should be false and `AuthenticationType` bearer. For development this can stay as is for now.
- For information on how to add custom roles and setup the function see [Add Roles To Your App In Less Than 10 Minutes](https://www.youtube.com/watch?v=C9qN6QqnxQ8) or [Define a RESTful technical profile in an Azure Active Directory B2C custom policy](https://docs.microsoft.com/en-us/azure/active-directory-b2c/restful-technical-profile)

    For the flow to work, update the `TrustFrameworkExtensions.xml` first with your `client_id` and `IdTokenAudience`. These are the app registered as per the [documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-create-user-flows?pivots=b2c-custom-policy)

    Update the `yourtenant` in the templates with the tenant name you created.

4. Select the `Identity Experience Framework` menu item in your B2C tenant in the Azure portal.
5. Select Upload custom policy
6. In this order, upload the policy files:
   - TrustFrameworkBase.xml
   - TrustFrameworkLocalization.xml
   - TrustFrameworkExtensions.xml
   - SignUpOrSignin.xml
   - PasswordReset.xml

### Add a test user to test the flow

1. Go to your `AAD B2C` tenant
2. Under `Manage` select `Users`
3. Click `New User`
   - You might see your account as a user, ignore this account as it is your owner or Admin account to manage the tenant.
   - You can add your own email as a user here as well as a user to login via B2C
4. On the next Blade
   - Select `Create Azure AD B2C user`
   - Sign-in method Select email and add user email as value (e.g. Test@mail.com)
   - For name, put in the name of the user
   - Leave the `Autogenerate password` selected, we will force the user to change the password on first sign-in or after password reset.
   - You can select show password, in order to be able to use the password on first sign in. Copy it if need to use it
   - First and Last name, fill in user details

### Test the flow

1. Go back to `AAD B2C` Tenant
2. Select `Policies\Identity Experience Framework`
3. Click on `B2C_1A_SIGNUP_SIGNIN`
4. For the `Select reply url` click on drop down and select `https://jwt.ms`
5. Click on `Run now`
6. Enter the email and password for your test user you added.
7. Click `Sign In` and you should be prompted to add `2FA` to authenticator app
   - Follow the steps
8. Once you signed in you should be navigated to `https://jwt.ms`
   - If you added your Function app correctly, you should see that `role` was added to your JWT token with the value you assigned to that user.
9. Test different flows like reset password and others.

### Change Branding

1. Go to `AAD B2C` tenant
2. Under `Manage` and `Company Branding`
3. Select `Configure`
4. Update branding by following on screen instructions

### More custom flow documentation

|||
|--|--|
|Reset password on first signin| <ul><li>https://docs.microsoft.com/en-us/answers/questions/547586/azure-b2c-password-reset-sending-to-wrong-userjour.html</li><li>https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/active-directory-b2c/force-password-reset.md</li></ul>|
|A Walkthrough For Azure AD B2C Custom Policy|https://tsmatz.wordpress.com/2020/05/12/azure-ad-b2c-ief-custom-policy-walkthrough/|
|MFA/2FA Authenticator App|<ul><li>https://github.com/azure-ad-b2c/samples/blob/master/policies/totp/policy/TrustFrameworkExtensionsTOTP.xml</li><li>https://docs.microsoft.com/en-us/azure/active-directory-b2c/display-controls</li></ul>|
|AAD b2C best practices|https://docs.microsoft.com/en-us/azure/active-directory-b2c/best-practices|


# Setup Application (Blazor)

For the this document we will make use of Blazor Server side application.

1. Create a `Blazor Server Application`
2. Give project a valid name, following the naming conventions as per project
3. In the additional information part
   - Select `.net lts`
   - `Authentication type` select `Microsoft identity platform`. This will add most components you will need for the app.
4. In the `appsettings.json` add the following component

```json

"AzureB2C": {
    "Instance": "https://yourtenant.b2clogin.com",
    "Domain": "yourtenant.onmicrosoft.com",
    "ClientId": "appliction (client) id as per registered app",
    "TenantId": "common",
    "CallbackPath": "/signin-oidc",
    "SignedOutCallbackPath ": "/signout-callback-oidc",
    "SignUpSignInPolicyId": "B2C_1A_SIGNUP_SIGNIN",
    "ResetPasswordPolicyId": "B2C_1A_PASSWORDRESET"
  },

```

5. In the `program.cs`, change the the following

```csharp

builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));

```
to

```csharp

builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureB2C"));

```

6. Add a class that will read the `Auth Claim` and return the role of the user for RBAC purpose

```csharp

using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorApp.Server
{
    public class AuthRoleClaim
    {
        public string RoleValue => GetRole().GetAwaiter().GetResult();

        private readonly AuthenticationStateProvider _provider;

        public AuthRoleClaim(AuthenticationStateProvider provider)
        {
            _provider = provider;
        }

        public async Task<string> GetRole()
        {
            var authState = await _provider.GetAuthenticationStateAsync();
            var user = authState.User;

            var role = user.Claims?.FirstOrDefault(x => x.Type.Contains("role"))?.Value;

            return role ?? "";
        }
    }
}

```

And in `Program.cs` add

```csharp

builder.Services.AddScoped<AuthRoleClaim>();

```

7. To use this in your HTML to hide or display elements based on the role

  - Inject the class that handles the role claim
  - Add `AuthorizeView` and `Authorized` tags around the section that need a user to be Authorized to view the section
  - Add the condition that handles the role and should validate the role

See example:

```html

@inject AuthRoleClaim Role

<div class="top-row ps-3 navbar navbar-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="">BlazorApp.Server</a>
        <button title="Navigation menu" class="navbar-toggler" @onclick="ToggleNavMenu">
            <span class="navbar-toggler-icon"></span>
        </button>
    </div>
</div>

<div class="@NavMenuCssClass" @onclick="ToggleNavMenu">
    <nav class="flex-column">
        <div class="nav-item px-3">
            <NavLink class="nav-link" href="" Match="NavLinkMatch.All">
                <span class="oi oi-home" aria-hidden="true"></span> Home
            </NavLink>
        </div>
        <div class="nav-item px-3">
            <NavLink class="nav-link" href="counter">
                <span class="oi oi-plus" aria-hidden="true"></span> Counter
            </NavLink>
        </div>
        <AuthorizeView>
            <Authorized>
                @if(Role.RoleValue == "Basic")
                {
                    <div class="nav-item px-3">
                        <NavLink class="nav-link" href="fetchdata">
                            <span class="oi oi-list-rich" aria-hidden="true"></span> Fetch data
                         </NavLink>
                    </div>
                }
            </Authorized>
        </AuthorizeView>
    </nav>
</div>

```

With this flow, only users that is authorized can see the `Fetch Data` can view it, if they belong to the role of `Basic`. Any other user will not be able to view this element. 