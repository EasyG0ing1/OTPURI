![Banner image](./img/OTPURILogo.png)

OTPURI is a SIMPLE Java library that makes it easy to obtain a properly formatted OTPAuth URI for One Time Password authentication Strings. It follows the defined schema as sated by Google for it's popular Google Authenticator application, though it can be used in ANY One Time Password scenario since this format is universal among all OTP implementations.

## Adding to your project
The Library is available as a Maven dependency on Central. Add the following to your POM file:

```xml
<dependency>
    <groupId>com.simtechdata</groupId>
    <artifactId>OTPURI</artifactId>
    <version>1.0.3</version>
</dependency>
```

Or, if using Gradle to build, add this to your Gradle build file

```groovy
compile group: 'com.simtechdata', name: 'OTPURI', version: 1.0.3
```

You can even use it from a Groovy script!

```groovy
@Grapes(
  @Grab(group='com.simtechdata', module='OTPURI', version=1.0.3)
)
```

### Modular Apps
If your app is modular, then add this to your ```module-info.java``` file
```Java
requires com.simtechdata.otpuri;
```

## Usage

The library uses standard Builder style to create your OTPAuth String either by passing in
a completely populated or partially populated OTPAuth String, or by specifying each element
of the String. You can even leave elements out and the library will always give you back a
**properly formatted, fully populated** URI String.

These three elements are recommended as a minimum amount of information for a given OTPAuth String so that you can quickly find that Auth code for whatever site you need to log into:
- Issuer
- Account Name
- Secret

The only MANDATORY field is the secret field. If that field has no data in it, the library will throw a RuntimeException error.

```Java
OTPURI otpuri = new OTPURI.Builder()
                    .issuer("Some Company Or Web Site")
                    .accountName("MyLoginName")
                    .secret("MySecret")
                    .build();
System.out.println(otpuri.getOTPAuthString());
System.out.println(otpuri.getOTPAuthStringDecoded());
```
Returns:
```
otpauth://totp/Some%20Company%20Or%20Web%20Site:MyLoginName?secret=MySecret&issuer=Some%20Company%20Or%20Web%20Site&algorithm=SHA1&digits=6&period=30
otpauth://totp/Some Company Or Web Site:MyLoginName?secret=MySecret&issuer=Some Company Or Web Site&algorithm=SHA1&digits=6&period=30
```
Calling ```getOTPAuthString()``` returns the URI properly formatted for web page insertion or for other apps that can accept a properly formatted OTPAuth String.

Calling ```getOTPAuthStringDecoded()``` returns the URI formatted without the %Hex codes for easier readability.

When you enable 2FA on an account, the website sometimes provides a QR code that you can scan into Google Authenticator or any app that can use the information. 
The contents of that QR code is simply an OTPAuth String, and there is rarely any consistency among websites in their generation of that String. 
OTPURI can accept that String from ANY sites generated QR code and it will automatically populate any missing elements with the defaults and then return a fully populated and properly formatted URI String.

So lets say that we scanned some QR codes and these Strings were the result of those scans:
```
otpauth://totp/Some%20Company:MyLoginName?secret=MySecret
otpauth://totp/MyLoginName?secret=MySecret&issuer=Some%20Company
otpauth://totp/?secret=MySecret
```
OTPURI will handle all three of those Strings, even though they have minimal or missing information, and any other possibilities will contain even more information so naturally those will be handled properly as well.

There are two places where the issuer can be named; At the start of the String after ```totp/``` (referred to as the label) and at the end of the String in the parameters section. 
If one location has the issuer stated, but the other location is missing, OTPURI will simply fill it in with the same name as the one given. 
If NO issuer is provided, then the library will fill in those fields with ```Unknown Company``` followed by four random numbers so that you can at least get some way to sort multiple OTPAuth Strings.

If the username is missing, the library will simply fill that spot with ```UnknownUsername```.

If the secret is missing, the library will throw a RuntimeException. The secret is the only mandatory piece of information necessary before you can obtain an OTPAuth String. 

If an OTP secret was generated with Googles Authenticator API, then it will have a format that looks like this ```LIPQ6VSFGS9KQA5M```, but I have seen many secrets generated from different web sites that do not follow that format, but they are all equally valid secrets. Secrets will never contain any characters in them that will be converted by encoding or decoding the string for web page formatting.

## OTP URI Schema
The official schema of the URI String follows this model:
```
<Resource>://<Protocol>/<LABEL>?<Parameters>
```
Where Label contains one or both of these fields
```
<Issuer>/<UserName>
```
If only one element is provided in the Label, OTPURI assumes it is the UserName and if none are given, then it makes up those fields as stated in the section above.

Parameters **must have a secret stated**, but can also have one or more of these fields: 
```
&secret=MySecret
&issuer=Some Company
&algorithm=SHA1
&digits=6
&period=30
```
It cannot duplicate fields. If there are duplicates, the library will take the last one given as the one that counts, since it uses a loop with a switch() to identify the fields provided.

Algorithm can be: ```SHA1``` (default), ```SHA256``` or ```SHA512``` and when specifying the algorithm manually, they are given as an enum (example below).

Period can be either **15**, **30** (default) or **60**, and that specifies the time frame window a user has to enter the one time password.

Digits can be **6 (default)**, **7**, or **8** - this value specifies how many characters should be returned from the websites OTP generator when it generates the One Time Password. I have always seen One Time Passwords expressed as only 6 digits, but 7 and 8 digits are also possible and if an OTPAuth String had 7 or 8 specified, then apps like Google Authenticator would show you a 7 or 8 digit One Time Password for that specific website.

The point of these options, is mainly so that you can pull those values in any app you might be writing where you generate your own one time password and need it to be synchronized with a website. 
When the OTPAuth String given from the QR code is missing either the algorithm, digits or period, that web site will always defer to the defaults as specified in the schema. 
So then when you instantiate a OTPURI object using the OTPAuth String given by the QR code, you can trust the values that the library gives back as being accurate.
## Public Getters
You can pull those values individually using these methods:
```Java
otpURI.getAlgorithm() //Returns a String of either SHA1, SHA256 or SHA512.
otpURI.getDigits() //Returns an int with a value of 6, 7, or 8.
otpURI.getPeriod() //Returns an int with a value of 15, 30 or 60.
```

You can also pull any of the other fields directly from the library
```Java
otpURI.getAccountName(); //Returns a String
otpURI.getIssuer(); //Returns a String
otpURI.getSecret(); //Returns a String
```

## Builder Setters
It needs to be mentioned that there are two different locations where you can provide the issuer of the OTPAuth String. I am not 100% sure as to why there are two issuer locations within the String. I have muy theories,
but it doesn't matter. The fact is that the schema calls for two different issuer fields and we can set **both of them** with a single Builder statement:

```Java
.issuer(String)
```

Alternatively, you can set just the **Label issuer** or the **Parameter issuer** from the Builder class as follows:

```Java
.labelIssuer(String)
.paramIssuer(String)
```
If you load the library from a QR scanned OTPAuth String, the library will properly fill these fields or default them as described above.

### Manually Building OTPURI instance
When engaging the Builder class and manually specifying each field in the library, Everything needs to be provided as a String, with these exceptions:

### Algorithm

The Algorithm is passed by an enum. There are only three possible algorithms and here is how you would state either of them using the Builder class:
```Java
.algorithm(Algorithm.SHA1) //Default
.algorithm(Algorithm.SHA256)
.algorithm(Algorithm.SHA512)
```

### Integers
The only other two options that are not passed in by Strings are
```Java
.digits(int)
.period(int)
```
Where digits can **ONLY** have one of three values: **6**, **7** or **8**. Any other values passed into that statement will cause a RuntimeException to be thrown.

The period can **ONLY** take one of three values: **15**, **30** or **60** - same deal on throwing the exception as above.

## toString()
You can rely on the libraries default toString() ```@Override``` when passing an instance into a method that accepts Strings, WITHOUT needing to type .toString() as Java String arguments will automatically take the ```@Override```toString() method.

toString() will return the URI in its encoded format for web pages.

## Conclusion

That's all there is to this library. It is very simple, but it can be very handy if you're into apps that rely on OTPAuth Strings.

I was unable to find a library that did what this one does, so I decided to write it myself and hopefully others will benefit from the work.

Thank you for using OTPURI,

Mike Sims

[sims.mike@gmail.com](mailto:sims.mike@gmail.com)

This library was compiled in Java 19. If you need an earlier version, fork the repository, modify as needed and compile into a jar file then import into your project.

---

Version Update Notes
---
* **1.0.3**
    * Fixed bug in Issuer balancing logic

* **1.0.2**
    * Changed getAuthStringDecoded to getOTPAuthStringDecoded

* **1.0.1**
    * First Release
