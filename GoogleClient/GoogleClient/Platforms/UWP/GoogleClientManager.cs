using System;
using System.Collections.Generic;
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
        const string clientSecret = "3f6NggMbPtrmIBpgx-MK2xXK"; // Talvez eu use



        public string ActiveToken => throw new NotImplementedException();

        public event EventHandler<GoogleClientResultEventArgs<GoogleUser>> OnLogin;
        public event EventHandler OnLogout;
        public event EventHandler<GoogleClientErrorEventArgs> OnError;

        public Task<GoogleResponse<GoogleUser>> LoginAsync()
        {
            return GoogleLogin();
        }

        async Task<GoogleResponse<GoogleUser>> GoogleLogin()
        {
            var state = randomDataBase64url(32);
            var code_verifier = randomDataBase64url(32);
            var code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
            const string code_challenge_method = "S256";

            var redirectURI = string.Format("http://{0}:{1}/", IPAddress.Loopback, GetRandomUnusedPort());

            var localSettings = ApplicationData.Current.LocalSettings;
            localSettings.Values["state"] = state;
            localSettings.Values["code_verifier"] = code_verifier;

            // Creates the OAuth 2.0 authorization request.
            var authorizationRequest = string.Format("{0}?response_type=code&scope=openid%20profile&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
                                                        authorizationEndpoint,
                                                        Uri.EscapeDataString(redirectURI),
                                                        clientID,
                                                        state,
                                                        code_challenge,
                                                        code_challenge_method);
            var http = new HttpListener();
            http.Prefixes.Add(redirectURI);
            http.Start();

            var success = await Launcher.LaunchUriAsync(new Uri(authorizationRequest));

            var context = await http.GetContextAsync();

            return null;
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

        public static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        public static string randomDataBase64url(uint length)
        {
            var buffer = CryptographicBuffer.GenerateRandom(length);
            return base64urlencodeNoPadding(buffer);
        }

      
        public static IBuffer sha256(string inputStirng)
        {
            var sha = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            var buff = CryptographicBuffer.ConvertStringToBinary(inputStirng, BinaryStringEncoding.Utf8);
            return sha.HashData(buff);
        }

        public static string base64urlencodeNoPadding(IBuffer buffer)
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
