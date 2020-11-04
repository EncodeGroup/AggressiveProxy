using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace LetMeOutSharp
{
    public static class UserAgents
    {
        //Default User-Agents
        public static readonly string NOUA = "";

        public static readonly string CHUA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36";

        public static readonly string EDUA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36 Edge/86.0.622.51";

        public static readonly string WHUA = "WinHttp-Autoproxy-Service/5.1";

        public static readonly string FFUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0";
    }

    public class ConfigPair
    {
        public Uri URL { get; set; }
        public string UserAgent { get; set; }
        public string URLString
        {
            get
            {
                if (URL == null)
                {
                    return "";
                }
                else
                {
                    return URL.ToString();
                }
            }
        }
        public override string ToString()
        {
            string url = "";
            if (URL != null)
            {
                url = URL.ToString();
            }
            return string.Format("\tProxy URL: {0} - UA: {1}", url, UserAgent);
        }
    }

    public static class Enumerator
    {
        //Get entries from the registry
        public static ConfigPair GetRegistry(string key, string value, string UA)
        {
            ConfigPair ret = null;
            try
            {
                var regkey = Registry.GetValue(key, value, null);
                if (regkey != null)
                {
                    ret = new ConfigPair { URL = regkey.ToString().ToUri(), UserAgent = UA };
                }
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex);
#endif
            }
            return ret;
        }


        //Retrieve the PAC URL for IE via the registry
        public static List<ConfigPair> GetIEPAC()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            List<ConfigPair> ret = new List<ConfigPair>();

            //Read PAC URL from HKCU
            var pacurl_hkcu = GetRegistry("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\", "AutoConfigURL", UserAgents.WHUA);
            if (pacurl_hkcu != null && !ret.Any(x => x.URL.Equals(pacurl_hkcu.URL)))
            {
                ret.Add(pacurl_hkcu);
            }

            //Read PAC URL from HKLM
            var pacurl_hklm = GetRegistry("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\", "AutoConfigURL", UserAgents.WHUA);
            if (pacurl_hklm != null && !ret.Any(x => x.URL.Equals(pacurl_hklm.URL)))
            {
                ret.Add(pacurl_hklm);
            }

#if DEBUG
            Console.WriteLine("\t{0} PAC", ret.Count);
            foreach (var pac in ret)
            {
                Console.WriteLine("\tPAC: {0}", pac);
            }
#endif
            return ret;
        }

        //Retrieve the PAC URL for Chrome via the registry
        public static List<ConfigPair> GetChromePAC()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            List<ConfigPair> ret = new List<ConfigPair>();

            //Read PAC URL from HKCU
            var pacurl_hkcu = GetRegistry("HKEY_CURRENT_USER\\Software\\Policies\\Google\\Chrome\\", "ProxyPacUrl", UserAgents.CHUA);
            if (pacurl_hkcu != null && !ret.Any(x => x.URL.Equals(pacurl_hkcu.URL)))
            {
                ret.Add(pacurl_hkcu);
            }

            //Read PAC URL from HKLM
            var pacurl_hklm = GetRegistry("HKEY_LOCAL_MACHINE\\Software\\Policies\\Google\\Chrome\\", "ProxyPacUrl", UserAgents.CHUA);
            if (pacurl_hklm != null && !ret.Any(x => x.URL.Equals(pacurl_hklm.URL)))
            {
                ret.Add(pacurl_hklm);
            }

#if DEBUG
            Console.WriteLine("\t{0} PAC", ret.Count);
            foreach (var pac in ret)
            {
                Console.WriteLine("\tPAC: {0}", pac);
            }
#endif
            return ret;
        }

        //Retrieve the PAC URL for Firefox via the prefs file
        public static List<ConfigPair> GetFirefoxPAC()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif

            List<ConfigPair> ret = new List<ConfigPair>();
            try
            {
                string profiles = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +
                                  "\\Mozilla\\Firefox\\Profiles\\";
                if (Directory.Exists(profiles))
                {
                    foreach (string dir in Directory.GetDirectories(profiles))
                    {
                        Uri pacURL = null;
                        string prefFile = string.Format("{0}\\{1}", dir, "prefs.js");
                        if (File.Exists(prefFile))
                        {
                            string[] readText = File.ReadAllLines(prefFile);
                            foreach (string line in readText)
                            {
                                if (line.Contains("network.proxy.autoconfig_url\""))
                                {
                                    pacURL = line.Split(',')[1].Trim().Split('"')[1].ToUri();
                                    ret.Add(new ConfigPair { URL = pacURL, UserAgent = UserAgents.FFUA });
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }

#if DEBUG
            Console.WriteLine("\t{0} PAC", ret.Count);
            foreach (var pac in ret)
            {
                Console.WriteLine("\tPAC: {0}", pac);
            }
#endif
            return ret;
        }

        //Retrieve Proxy URL for Chrome
        public static List<ConfigPair> GetChromeProxy()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            List<ConfigPair> ret = new List<ConfigPair>();

            string profiles = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) +
                                  "\\Google\\";
            if (Directory.Exists(profiles))
            {
                //Chrome is installed. Will also try to get the system proxy and use the chrome UA
                try
                {
                    Uri site_to_check = new Uri("https://www.google.com");
                    Uri proxy = System.Net.WebRequest.GetSystemWebProxy().GetProxy(site_to_check);
                    if (proxy != null && proxy != site_to_check)
                    {
                        if (!ret.Any(x => x.URL.Equals(proxy)))
                        {
                            ret.Add(new ConfigPair { URL = proxy, UserAgent = UserAgents.CHUA });
                        }
                    }
                }
                catch (Exception ex)
                {
#if DEBUG
                    Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
                }
            }

            //Read proxy from HKCU
            var proxy_hkcu = GetRegistry("HKEY_CURRENT_USER\\Software\\Policies\\Google\\Chrome\\", "ProxyServer", UserAgents.CHUA);
            if (proxy_hkcu != null && !ret.Any(x => x.URL.Equals(proxy_hkcu.URL)))
            {
                ret.Add(proxy_hkcu);
            }

            //Read proxy from HKLM
            var proxy_hklm = GetRegistry("HKEY_LOCAL_MACHINE\\Software\\Policies\\Google\\Chrome\\", "ProxyServer", UserAgents.CHUA);
            if (proxy_hklm != null && !ret.Any(x => x.URL.Equals(proxy_hklm.URL)))
            {
                ret.Add(proxy_hklm);
            }

            //Get value from CommandLine
            try
            {
                foreach (var process in System.Diagnostics.Process.GetProcessesByName("chrome"))
                {
                    string proxyServer = process.GetCommandLine();
                    if (!string.IsNullOrEmpty(proxyServer))
                    {
                        Uri proxyUri = proxyServer.ToUri();
                        if (!ret.Any(x => x.URL.Equals(proxyUri)))
                        {
                            ret.Add(new ConfigPair { URL = proxyUri, UserAgent = UserAgents.CHUA });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }

#if DEBUG
            Console.WriteLine("\t{0} proxies", ret.Count);
            foreach (var proxy in ret)
            {
                Console.WriteLine(proxy);
            }
#endif
            return ret;
        }

        //Retrieve Proxy URL for IE from the registry
        public static List<ConfigPair> GetIEProxy()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            List<ConfigPair> ret = new List<ConfigPair>();

            //Get value from HKCU
            var proxy_hkcu = GetRegistry("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\", "ProxyServer", UserAgents.EDUA);
            if (proxy_hkcu != null)
            {
                ret.Add(proxy_hkcu);
            }

            //Get value from HKLM
            var proxy_hklm = GetRegistry("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\", "ProxyServer", UserAgents.EDUA);
            if (proxy_hklm != null && !ret.Any(x => x.URL.Equals(proxy_hklm.URL)))
            {
                ret.Add(proxy_hklm);
            }

            //Get proxy for google via GetSystemWebProxy
            try
            {
                Uri site_to_check = new Uri("https://www.google.com");
                Uri proxy = System.Net.WebRequest.GetSystemWebProxy().GetProxy(site_to_check);
                if (proxy != null && proxy != site_to_check)
                {
                    if (!ret.Any(x => x.URL.Equals(proxy)))
                    {
                        ret.Add(new ConfigPair { URL = proxy, UserAgent = UserAgents.EDUA });
                    }
                }
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }

#if DEBUG
            Console.WriteLine("\t{0} proxies", ret.Count);
            foreach (var proxy in ret)
            {
                Console.WriteLine(proxy);
            }
#endif
            return ret;
        }

        //Retrieve the Proxy URL for Firefox via the prefs file
        public static List<ConfigPair> GetFirefoxProxy()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            List<ConfigPair> ret = new List<ConfigPair>();
            try
            {
                string profiles = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +
                                  "\\Mozilla\\Firefox\\Profiles\\";
                if (Directory.Exists(profiles))
                {
                    //Firefox is installed. Will also try to get the system proxy and use the firefox UA
                    try
                    {
                        Uri site_to_check = new Uri("https://www.google.com");
                        Uri proxy = System.Net.WebRequest.GetSystemWebProxy().GetProxy(site_to_check);
                        if (proxy != null && proxy != site_to_check)
                        {
                            if (!ret.Any(x => x.URL.Equals(proxy)))
                            {
                                ret.Add(new ConfigPair { URL = proxy, UserAgent = UserAgents.FFUA });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
#if DEBUG
                        Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
                    }

                    //Have a look at the profiles
                    foreach (string dir in Directory.GetDirectories(profiles))
                    {
                        string proxyAddress = "";
                        string proxyPort = "";
                        string proxySslAddress = "";
                        string proxySslPort = "";
                        string prefFile = string.Format("{0}\\{1}", dir, "prefs.js");
#if DEBUG
                        Console.WriteLine("\tPrefs file: {0}", prefFile);
#endif
                        if (File.Exists(prefFile))
                        {
                            string[] readText = File.ReadAllLines(prefFile);
                            foreach (string line in readText)
                            {
                                if (line.Contains("network.proxy.http\""))
                                {
                                    proxyAddress = line.Split(',')[1].Trim().Split('"')[1];
                                }

                                if (line.Contains("network.proxy.http_port\""))
                                {
                                    proxyPort = line.Split(',')[1].Trim().Replace(");", "");
                                }

                                if (line.Contains("network.proxy.ssl\""))
                                {
                                    proxySslAddress = line.Split(',')[1].Trim().Split('"')[1];
                                }

                                if (line.Contains("network.proxy.ssl_port\""))
                                {
                                    proxySslPort = line.Split(',')[1].Trim().Replace(");", "");
                                }
                            }

                            if (!(string.IsNullOrEmpty(proxyAddress) || string.IsNullOrEmpty(proxyPort)))
                            {
                                Uri p = string.Format("{0}:{1}", proxyAddress, proxyPort).ToUri();
                                if (!ret.Any(x => x.URL.Equals(p)))
                                {
                                    ret.Add(new ConfigPair { URL = p, UserAgent = UserAgents.FFUA });
                                }
                            }

                            if (!(string.IsNullOrEmpty(proxySslAddress) || string.IsNullOrEmpty(proxySslPort)))
                            {
                                Uri p = string.Format("{0}:{1}", proxySslAddress, proxySslPort).ToUri();
                                if (!ret.Any(x => x.URL.Equals(p)))
                                {
                                    ret.Add(new ConfigPair { URL = p, UserAgent = UserAgents.FFUA });
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }

#if DEBUG
            Console.WriteLine("\t{0} proxies", ret.Count);
            foreach (var proxy in ret)
            {
                Console.WriteLine(proxy);
            }
#endif
            return ret;
        }

        // Retrieve IE, Chrome, Firefox PAC URLs
        public static List<ConfigPair> GetPACURLS()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            //Get all PAC URL's in a list

            List<ConfigPair> PACURL = new List<ConfigPair>();
            var ie = GetIEPAC();
            PACURL.AddRange(ie);
            var ch = GetChromePAC();
            PACURL.AddRange(ch);
            var fx = GetFirefoxPAC();
            PACURL.AddRange(fx);

#if DEBUG
            Console.WriteLine("GetPACURLS: {0} PAC", PACURL.Count);
#endif
            return PACURL;
        }

        //Retrieve all proxies from the PAC URLs
        public static List<ConfigPair> GetProxiesFromPAC()
        {
            List<ConfigPair> ret = new List<ConfigPair>();
            foreach (ConfigPair conf in GetPACURLS())
            {
                List<ConfigPair> proxyconfig = GetPAC(conf);
                foreach (ConfigPair proxy in proxyconfig)
                {
                    if (!ret.Any(x => x.URL.Equals(proxy.URL) && x.UserAgent.Equals(proxy.UserAgent)))
                    {
                        ret.Add(proxy);
                    }
                }
            }
            return ret;
        }

        //Process PAC URL and extract proxies
        public static List<ConfigPair> GetPAC(ConfigPair config)
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
            Console.WriteLine("Processing PAC: {0}", config.URL.ToString());
#endif
            List<ConfigPair> ret = new List<ConfigPair>();
            try
            {
                string pacData = GetHTTP(config.URL, null, config.UserAgent);

                if (!pacData.Contains("PROXY "))
                {
                    return ret;
                }

                System.Text.RegularExpressions.Regex
                    rx = new System.Text.RegularExpressions.Regex(@"PROXY (.*?):(\d+)");

                System.Text.RegularExpressions.MatchCollection matches = rx.Matches(pacData);
                foreach (System.Text.RegularExpressions.Match match in matches)
                {
                    Uri srv = string.Format("{0}:{1}", match.Groups[1].Value, match.Groups[2].Value).ToUri();
                    if (!ret.Any(x => x.URL.Equals(srv)))
                    {
                        //if winhttp convert to IE
                        if (config.UserAgent.Equals(UserAgents.WHUA))
                            config.UserAgent = UserAgents.EDUA;
                        ret.Add(new ConfigPair { URL = srv, UserAgent = config.UserAgent });
                    }
                }
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }
#if DEBUG
            Console.WriteLine("\tProxies: {0}", ret.Count);
            foreach (var proxy in ret)
            {
                Console.WriteLine("{0}", proxy);
            }
#endif
            return ret;
        }

        //Get proxies for Chrome, Firefox, IE
        public static List<ConfigPair> GetProxies()
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            //Get all Proxies in a list

            List<ConfigPair> proxies = new List<ConfigPair>();
            try
            {
                proxies.AddRange(GetChromeProxy());
                proxies.AddRange(GetFirefoxProxy());
                proxies.AddRange(GetIEProxy());
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }
#if DEBUG
            Console.WriteLine("GetProxies: {0}", proxies.Count);
#endif
            return proxies;
        }

        //Extract proxy configuration from commandline
        private static string GetCommandLine(this System.Diagnostics.Process process)
        {
            try
            {
                string cmdLine = null;
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    string.Format("SELECT CommandLine FROM Win32_Process WHERE ProcessId = {0}", process.Id)))
                {
                    var matchEnum = searcher.Get().GetEnumerator();
                    if (matchEnum.MoveNext())
                    {
                        cmdLine = matchEnum.Current["CommandLine"]?.ToString();
                    }
                }
                if (cmdLine != null && cmdLine.Contains("proxy"))
                {
                    System.Text.RegularExpressions.Regex pattern =
                        new System.Text.RegularExpressions.Regex(@"proxy-server=[^\s]*");
                    System.Text.RegularExpressions.Match match = pattern.Match(cmdLine);
#if DEBUG
                    Console.WriteLine("\tProxy from cmd: {0}", match.ToString().TrimStart('"').TrimEnd('"'));
#endif
                    return match.ToString().Replace("proxy-server=", "").TrimStart('"').TrimEnd('"');
                }
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }

            return "";
        }

        public static string GetHTTP(Uri url, ConfigPair config)
        {
            return GetHTTP(url, config.URL, config.UserAgent);
        }

        //Do HTTP requests
        public static string GetHTTP(Uri url, Uri proxySrv = null, string userAgent = "")
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
            Console.WriteLine("\tProxy to use: {0}", proxySrv);
            Console.WriteLine("\tUA to use: {0}", userAgent);
#endif

            try
            {
                //var target = url;
                System.Net.ServicePointManager.ServerCertificateValidationCallback +=
                    new System.Net.Security.RemoteCertificateValidationCallback(ValidateRemoteCertificate);

                System.Net.IWebProxy proxy = null;

                if (proxySrv == null)
                {
                    proxy = new System.Net.WebProxy();
                }
                else
                {
                    proxy = new System.Net.WebProxy(proxySrv);
                }

                var credentials = System.Net.CredentialCache.DefaultCredentials;
                proxy.Credentials = credentials; //Set credentials for passthrough auth to proxy

                System.Net.HttpWebRequest request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
                request.Proxy = proxy;
                if (!string.IsNullOrEmpty(userAgent))
                {
                    request.UserAgent = userAgent;
                }

                request.Credentials = System.Net.CredentialCache.DefaultCredentials;
                request.Timeout = 15000;

                System.Net.HttpWebResponse response = (System.Net.HttpWebResponse)request.GetResponse();
                Stream resStream = response.GetResponseStream();
                StreamReader readStream = new StreamReader(resStream, Encoding.UTF8);
                var data = readStream.ReadToEnd();
                response.Close();
                readStream.Close();
                if (!string.IsNullOrEmpty(data))
                {
#if DEBUG
                    Console.WriteLine("\tResponse Data: {0}", data);
#endif
                    return data;
                }
            }
            catch (System.Net.WebException ex)
            {
#if DEBUG
                Console.WriteLine("\tHTTP Error: {0}", ex.Message);
#endif
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
            }
            return "";
        }

        public static bool DoHTTP(Uri url, string response, string info, ConfigPair config)
        {
#if DEBUG
            Console.WriteLine(System.Reflection.MethodBase.GetCurrentMethod().Name);
#endif
            try
            {
                Uri urlrequest = new Uri(string.Format("{0}?{1}", url.ToString(), info));
                var resp = GetHTTP(urlrequest, config.URL, config.UserAgent);
                if (!string.IsNullOrEmpty(resp))
                {
                    if (resp.Contains(response))
                    {
#if DEBUG
                        Console.WriteLine("\tCanTalk: true");
#endif
                        return true;
                    }
                    else
                    {
#if DEBUG
                        Console.WriteLine("\tConnection success, but response not the same.");
#endif
                        return false;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
#if DEBUG
                Console.WriteLine("[*] An exception occured: {0}", ex);
#endif
                return false;
            }
        }

        // Accept all certificates
        private static bool ValidateRemoteCertificate(object sender,
            System.Security.Cryptography.X509Certificates.X509Certificate certificate,
            System.Security.Cryptography.X509Certificates.X509Chain chain,
            System.Net.Security.SslPolicyErrors policyErrors)
        {
            return true;
        }

    }
}