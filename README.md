# AggressiveProxy
AggressiveProxy is a combination of a .NET 3.5 binary (**LetMeOutSharp**) and a Cobalt Strike aggressor script (**AggressiveProxy.cna**). Once LetMeOutSharp is executed on a workstation, it will try to enumerate all available proxy configurations and try to communicate with the Cobalt Strike server over HTTP(s) using the identified proxy configurations.

The story behind the tool can be found at [EncodeGroup's Medium](https://medium.com/encode-threat-labs/aggressiveproxy-a-tale-of-two-proxies-and-a-sad-beacon-43042a04a0d0)

## Requirements
* CobaltStrike 4.1
* Mono Framework

## Instructions
* Modify the `$msbuild` value in AggressiveProxy.cna to point to the path of msbuild executable which is part of the Mono Framework
* Click on the *Proxy Handler->Start Handler* menu item. At this point the script will request the listener, the proxy handler URL and the expected response content settings.
* Once these values have been set, the script will then:
	* Replace `%C2URL%` and `%RESPONSE%` placeholders inside `Program_template.cs` and create the `Program.cs` file
	* Invoke MSBuild in order to build the .NET binary LetMeOutSharp
* The script will then create a web page at the provided `Check URL`. Once a hit has been made to the specific URL from LetMeOutSharp, it will then:
	* Try to decode the base64 parameters of the GET request and extract the proxy address:port, the UserAgent and the architecture (x86/x64).
	* Try to match the UserAgent it received and pick a proper Malleable variant. If you want the generated shellcode to use the appropriate User-Agent, you will need to create the following variants:
	  * "chrome"
	  * "firefox"
	  * "edge"
	
	If there are no variants configured, the default one should be used. The new variants should have **exactly the same configuration** as the variant your listener is/will be using, with the addition of the appropriate `header "User-Agent"` line in the `client` part.
	For example if your listener is using the following profile:
```
http-get {
  set uri "/test/";
  set verb "GET";
  client {
    header "Accept" "*/*";
    header "Accept-Encoding" "gzip, deflate";
    metadata {
      base64url;
      prepend "user=";
      header "Cookie";
    }
  }
  server {
    header "Server" "Server";
	header "Content-Type" "application/text";
	header "Connection" "keep-alive";
	output {
	  print;
	}
  }
}
```
You will need to define the following variants:
```
http-get "chrome" {
  ..<same as the main profile>..
  client {
    ..<same as the main profile>..
    header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36";
    ..<same as the main profile>..
  }
  server {
    ..<same as the main profile>..
  }
}
http-get "firefox" {
  ..<same as the main profile>..
  client {
    ..<same as the main profile>..
    header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0";
    ..<same as the main profile>..
  }
  server {
    ..<same as the main profile>..
  }
}
http-get "edge" {
  ..<same as the main profile>..
  client {
    ..<same as the main profile>..
    header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36 Edge/86.0.622.51";
    ..<same as the main profile>..
  }
  server {
    ..<same as the main profile>..
  }
}
```

* AggressiveProxy.cna will then setup a new temporary listener with the custom proxy configuration. The following exception will be logged: `java.lang.RuntimeException: Another Beacon listener exists on your cobalt console`. This is normal and we will be using the temporary listener in order to create the shellcode with the custom proxy configuration. After generating the shellcode, the listener will be deleted.
* A new URL will be created which will host the shellcode which is XOR encrypted and in HEX form.
* LetMeOutSharp, will then fetch the shellcode and try to inject it to a new process. Currently as a POC, LetMeOutSharp will perform a QueueUserAPC injection to a newly spawned process of our favorite process `notepad.exe`. Feel free to modify `Injector.cs` to your taste.

## Menu options
The CNA will create a menu with the following items:
  * *Start Handler* is responsible for defining the listener that LetMeOutSharp will try to communicate to, the URL that will try to reach as well as the expected response from the web server. After defining the settings, it will host the proxy handling URL on the Cobalt Strike web server.
  * *Stop Handler* will remove the proxy handling URL and any hosted generated shellcodes.

## Extra Configuration

* By modifying `$buildver` variable in the AggressiveProxy CNA, you can build a Debug version of LetMeOutSharp, which is more verbose and will print out all the relevant information it gathers. This should be used only for testing purposes.
* Currently, AggressiveProxy CNA is using unpenetratable encryption for the hosted shellcode, with the use of a hardcoded XOR key. This can be modified the `$xordata` variable. You should also replace the line `values[i] = (byte)(values[i] ^ 0x2a);` in Program_template.cs

## Notes
An effort has been made to test multiple cases of proxy configurations / technologies. This however does not mean that all cases have been accounted for. If you feel you have found a case, where LetMeOutSharp does not take into account, feel free to open an issue or a merge request.

## Authors

[@cirrusj](https://github.com/cirrusj)

[@leftp](https://github.com/leftp)
