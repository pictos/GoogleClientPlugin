using System;
using static System.Diagnostics.Debug;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Plugin.GoogleClient.Shared;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.System;
using Windows.UI.Xaml.Navigation;
using System.Linq;
using Windows.Data.Json;
using System.Net.Http;

namespace Plugin.GoogleClient
{
    /// <summary>
    /// Implementation for GoogleClient
    /// </summary>
    public class GoogleClientManager : IGoogleClientManager
    {
        const string clientID = "581786658708-r4jimt0msgjtp77b15lonfom92ko6aeg.apps.googleusercontent.com";
        const string redirectURI = "pw.oauth2:/oauth2redirect";
        const string authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        const string tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";
        const string userInfoEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo";

        // const string clientSecret = "3f6NggMbPtrmIBpgx-MK2xXK"; // Talvez eu use

        public string ActiveToken => throw new NotImplementedException();

        public event EventHandler<GoogleClientResultEventArgs<GoogleUser>> OnLogin;
        public event EventHandler OnLogout;
        public event EventHandler<GoogleClientErrorEventArgs> OnError;

        public Task<GoogleResponse<GoogleUser>> LoginAsync() =>
            GoogleLoginAsync();

        Task<GoogleResponse<GoogleUser>> GoogleLoginAsync()
        {
            var state = RandomDataBase64url(32);
            var code_verifier = RandomDataBase64url(32);
            var code_challenge = Base64urlencodeNoPadding(Sha256(code_verifier));
            const string code_challenge_method = "S256";


            var localSettings = ApplicationData.Current.LocalSettings;
            localSettings.Values["state"] = state;
            localSettings.Values["code_verifier"] = code_verifier;

            string authorizationRequest = $"{authorizationEndpoint}?response_type=code&scope=openid%20profile&redirect_uri={Uri.EscapeDataString(redirectURI)}&client_id={clientID}&state={state}&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}";

            WriteLine("Opening authorization request URI: " + authorizationRequest);

            // Opens the Authorization URI in the browser.
            var success = Launcher.LaunchUriAsync(new Uri(authorizationRequest));

            var response = new GoogleResponse<GoogleUser>(new GoogleUser(),GoogleActionStatus.Completed);
            return Task.FromResult(response);
        }

        public async Task UserInfo(object o)
        {
            if (!(o is NavigationEventArgs e))
                return;
            // Gets URI from navigation parameters.

            if (e.Parameter is Uri authorizationResponse)
            {
                var queryString = authorizationResponse.Query;
                WriteLine("MainPage received authorizationResponse: " + authorizationResponse);

                // Parses URI params into a dictionary
                // ref: http://stackoverflow.com/a/11957114/72176
                var queryStringParams = queryString.Substring(1).Split('&')
                                        .ToDictionary(c => c.Split('=')[0],
                                           c => Uri.UnescapeDataString(c.Split('=')[1]));

                if (queryStringParams.ContainsKey("error"))
                {
                    WriteLine(string.Format("OAuth authorization error: {0}.", queryStringParams["error"]));
                    return;
                }

                if (!queryStringParams.ContainsKey("code")
                    || !queryStringParams.ContainsKey("state"))
                {
                    WriteLine("Malformed authorization response. " + queryString);
                    return;
                }

                // Gets the Authorization code & state
                string code = queryStringParams["code"];
                string incoming_state = queryStringParams["state"];

                // Retrieves the expected 'state' value from local settings (saved when the request was made).
                ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
                string expected_state = (string)localSettings.Values["state"];

                // Compares the receieved state to the expected value, to ensure that
                // this app made the request which resulted in authorization
                if (incoming_state != expected_state)
                {
                    WriteLine(string.Format("Received request with invalid state ({0})", incoming_state));
                    return;
                }

                // Resets expected state value to avoid a replay attack.
                localSettings.Values["state"] = null;

                // Authorization Code is now ready to use!
                WriteLine(Environment.NewLine + "Authorization code: " + code);

                var code_verifier = (string)localSettings.Values["code_verifier"];
                await PerformCodeExchangeAsync(code, code_verifier);
            }
            else
            {
                WriteLine(e.Parameter);
            }
        }

        public void Logout()
        {
            throw new NotImplementedException();
        }

        public Task<GoogleResponse<GoogleUser>> SilentLoginAsync()
        {
            throw new NotImplementedException();
        }

        #region [ Helpers ]

        async Task PerformCodeExchangeAsync(string code, string code_verifier)
        {
            // Builds the Token request
            var tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&scope=&grant_type=authorization_code",
                code,
                Uri.EscapeDataString(redirectURI),
                clientID,
                code_verifier
                );
            var content = new StringContent(tokenRequestBody, Encoding.UTF8, "application/x-www-form-urlencoded");

            // Performs the authorization code exchange.
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = true
            };
            var client = new HttpClient(handler);

            WriteLine(Environment.NewLine + "Exchanging code for tokens...");
            var response = await client.PostAsync(tokenEndpoint, content);
            string responseString = await response.Content.ReadAsStringAsync();
            WriteLine(responseString);

            if (!response.IsSuccessStatusCode)
            {
                WriteLine("Authorization code exchange failed.");
                return;
            }

            // Sets the Authentication header of our HTTP client using the acquired access token.
            var tokens = JsonObject.Parse(responseString);
            var accessToken = tokens.GetNamedString("access_token");
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            // Makes a call to the Userinfo endpoint, and prints the results.
            WriteLine("Making API Call to Userinfo...");
            HttpResponseMessage userinfoResponse = client.GetAsync(userInfoEndpoint).Result;
            var userinfoResponseContent = await userinfoResponse.Content.ReadAsStringAsync();
            WriteLine(userinfoResponseContent);
        }

        public static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        public static string RandomDataBase64url(uint length)
        {
            var buffer = CryptographicBuffer.GenerateRandom(length);
            return Base64urlencodeNoPadding(buffer);
        }


        public static IBuffer Sha256(string inputStirng)
        {
            var sha = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            var buff = CryptographicBuffer.ConvertStringToBinary(inputStirng, BinaryStringEncoding.Utf8);
            return sha.HashData(buff);
        }

        public static string Base64urlencodeNoPadding(IBuffer buffer)
        {
            string base64 = CryptographicBuffer.EncodeToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

        #endregion
    }
}
