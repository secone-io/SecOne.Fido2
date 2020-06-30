using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

//https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#authenticator-api
namespace SecOne.Fido2.Test
{
    struct MakeCredentialResult
    {
        public string PublicKey;
        public string CredentialId;
    }

    struct AssertionResult
    {
        public byte[] HmacSecret;
        public bool Valid;
        public string PublicKey;
    }

    class Program
    {
        //Client data hash. 
        private static readonly byte[] Cdh = {
            0xf9, 0x64, 0x57, 0xe7, 0x2d, 0x97, 0xf6, 0xbb,
            0xdd, 0xd7, 0xfb, 0x06, 0x37, 0x62, 0xea, 0x26,
            0x20, 0x44, 0x8e, 0x69, 0x7c, 0x03, 0xf2, 0x31,
            0x2f, 0x99, 0xdc, 0xaf, 0x3e, 0x8a, 0x91, 0x6b,
        };

        private static readonly byte[] UserId = {
            0x78, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
            0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
            0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
            0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,

        };

        private static readonly byte[] Salt = {
            0x78, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
            0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
            0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
            0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,

        };

        private static readonly byte[] Salt2 = {
            0x79, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
            0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
            0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
            0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,

        };


        static void Main(string[] args)
        {
            //Outputs debug messages to the console
            //Fido2Settings.Flags = FidoFlags.Debug;

            var lastDevicePath = "";
            var hasUserPresence = false;
            var hasPin = false;
            var hasBiometric = false;

            //1. Get all devices
            using (var devlist = new FidoDeviceInfoList(64))
            {
                foreach (var di in devlist)
                {
                    Console.WriteLine(di);
                    lastDevicePath = di.Path;

                    Console.WriteLine($"GOT PATH:{di.Path}");
                }
            }

            //2. Get the device info for any fido2 compliant device, check if it has a PIN set.
            if (string.IsNullOrEmpty(lastDevicePath))
            {
                Console.WriteLine("No devices found. Check process is administrator, and that key is inserted correctly.");
                Console.ReadKey();
                return;
            } 
            else
            {
                using (var dev = new FidoDevice())
                {
                    dev.Open(lastDevicePath);

                    using (var ci = dev.GetCborInfo())
                    {
                        Console.WriteLine(dev);
                        Console.WriteLine(ci);

                        foreach (var option in ci.Options)
                        {
                            Console.WriteLine($"Option {option.Key}: {option.Value}");
                        }

                        //Check the clientPin paramater (true/false if set, not foudn if not capable)
                        try
                        {
                            hasPin = ci.Options["clientPin"];
                            Console.WriteLine($"Security Key has pin set: {hasPin}");
                        }
                        catch
                        {
                            Console.WriteLine($"Error detecting pin.");
                        }

                        //Check the user presence paramater (true/false if set, not found if not capable)
                        try
                        {
                            hasUserPresence = ci.Options["up"];
                            Console.WriteLine($"User presence set: {hasUserPresence}");
                        }
                        catch
                        {
                            Console.WriteLine($"Error detecting user presence parameter.");
                        }


                        //Check the user verification paramater (true/false if set, not found if not capable)
                        try
                        {
                            hasBiometric = ci.Options["uv"];
                            Console.WriteLine($"Biometric set: {hasBiometric}");
                        }
                        catch
                        {
                            Console.WriteLine($"Error detecting biometric (user verification) parameter.");
                        }

                        if (hasPin)
                        {
                            Console.WriteLine($"Pin retry count set to: {dev.RetryCount}");
                            Console.WriteLine();
                        }
                    }

                    dev.Close();
                }
            }

            //Optional. Reset the device
            //The actual user-flow to perform a reset is outside the scope of the FIDO2 specification, and may therefore vary depending on the authenticator. 
            //Yubico authenticators do not allow resets after 5 seconds from power-up, and expect a reset to be confirmed by the user through touch within 30 seconds.

            //using (var dev = new FidoDevice())
            //{
            //    Console.WriteLine("To reset the device, remove and re-insert the device, then press any key within 5 seconds.");
            //    Console.ReadLine();

            //    dev.Open(lastDevicePath);
            //    dev.Reset();

            //    Console.WriteLine("Touch the device to confirm within 30 seconds.");
            //    dev.Close();
            //}

            //Optional. Set the pin to 1234
            //if (!hasPin)
            //{ 
            //   using (var dev = new FidoDevice())
            //    {
            //        Console.WriteLine("Press any key to set the pin.");
            //        Console.ReadLine();

            //        dev.Open(lastDevicePath);
            //        {
            //            dev.SetPin(null, "1234");
            //            hasPin = true;

            //            dev.Close();
            //        }
            //    }
            //}

            Console.WriteLine("Press any key to make a credential");
            Console.ReadLine();

            Console.WriteLine("Touch the device if requested ...");

            //3. Make a credential on the device.
            //Pin may be null if not required

            //https://groups.google.com/a/fidoalliance.org/forum/#!topic/fido-dev/L2K5fBm8Sh0
            var useHmacExtension = true;

            var credential = MakeDeviceCredential(lastDevicePath, useHmacExtension, FidoCose.ES256, null, (hasPin) ? "1234" : null, hasBiometric);

            Console.WriteLine($"Created credential id: {credential.CredentialId}");

            Console.WriteLine("Press any key to make another credential");
            Console.ReadLine();

            Console.WriteLine("Touch the device if requested ...");

            //Test making another credential to test multiple credential scenarios
            var credential2 = MakeDeviceCredential(lastDevicePath, useHmacExtension, FidoCose.ES256, null, (hasPin) ? "1234" : null, hasBiometric);

            Console.WriteLine($"Created credential id: {credential2.CredentialId}");

            //4. Try a sample assertion
            Console.WriteLine("Press any key to assert this credential");
            Console.ReadLine();

            Console.WriteLine("Touch the device if requested (to assert)...");

            var assertionResult = DoAssertion(lastDevicePath, useHmacExtension, "relyingparty", FidoCose.ES256, (hasPin) ? "1234" : null, credential2, credential, Salt2, Salt, hasUserPresence, hasBiometric);

            //5. Try a sample assertion
            Console.WriteLine("Press to do another assertion");
            Console.ReadLine();

            Console.WriteLine("Touch the device if requested (to assert again) ...");

            var assertionResult2 = DoAssertion(lastDevicePath, useHmacExtension, "relyingparty", FidoCose.ES256, (hasPin) ? "1234" : null, credential2, credential, Salt2, Salt, hasUserPresence, hasBiometric);

            if (useHmacExtension)
            {
                Console.WriteLine($"Hmac Secrets Match: {assertionResult.HmacSecret.SequenceEqual(assertionResult2.HmacSecret)}");
            }

            Console.WriteLine("Press any key to close.");
            Console.ReadLine();
        }

        //View the c# versions of the c examples from Yubico here:
        //https://github.com/borrrden/Fido2Net/blob/master/Examples/assert/Assert/Program.cs
        //This will help explain how to eg retrieve hmac secrets
        private static AssertionResult DoAssertion(string devicePath, bool useHmacExtension, string rp, FidoCose algorithmType, string pin, MakeCredentialResult credential, MakeCredentialResult credential2, byte[] salt, byte[] salt2, bool requireUp, bool requireUv)
        {
            var ext = useHmacExtension ? FidoExtensions.HmacSecret : FidoExtensions.None;

            using (var assert = new FidoAssertion())
            {
                using (var dev = new FidoDevice())
                {
                    dev.Open(devicePath);

                    if (credential.CredentialId != null)
                    {
                        assert.AllowCredential(Convert.FromBase64String(credential.CredentialId));
                    }

                    if (credential2.CredentialId != null)
                    {
                        assert.AllowCredential(Convert.FromBase64String(credential2.CredentialId));
                    }

                    assert.ClientDataHash = Cdh;
                    assert.Rp = rp;
                    assert.SetExtensions(ext);

                    if (useHmacExtension)
                    {
                        assert.SetHmacSalt(salt, 0);
                        if (credential2.CredentialId != null) assert.SetHmacSalt(salt2, 1);
                    }

                    if (requireUv) assert.SetOptions(requireUp, requireUv);

                    dev.GetAssert(assert, pin);
                    dev.Close();                    
                }

                if (assert.Count != 1)
                {
                    throw new Exception($"{assert.Count} signatures required");
                }

                var authData = assert[0].AuthData;
                var signature = assert[0].Signature;
                var verifiedKey = "";

                using (var verify = new FidoAssertion())
                {
                    verify.ClientDataHash = Cdh;
                    verify.Rp = rp;
                    verify.Count = 1;
                    verify.SetAuthData(authData, 0);
                    verify.SetExtensions(ext);

                    if (requireUv) verify.SetOptions(requireUp, requireUv);
                    
                    verify.SetSignature(signature, 0);

                    
                    //Try verify both ways
                    try
                    {
                        verify.Verify(0, algorithmType, Convert.FromBase64String(credential.PublicKey));
                        verifiedKey = credential.PublicKey;
                    }
                    catch
                    {
                        try
                        {
                            verify.Verify(0, algorithmType, Convert.FromBase64String(credential2.PublicKey));
                            verifiedKey = credential2.PublicKey;
                        }
                        catch
                        {

                        }
                    }
                }

                AssertionResult result;

                result.HmacSecret = (useHmacExtension) ? assert[0].HmacSecret.ToArray() : new Byte[] { };
                result.Valid = !String.IsNullOrEmpty(verifiedKey);
                result.PublicKey = verifiedKey;

                return result;
            }
        }

        //Note: Registering a security key like this would usually happen in the browser via javascript extension
        //It could be done on behalf of the user via the MMC snapin
        private static MakeCredentialResult MakeDeviceCredential(string devicePath, bool useHmacExtension, FidoCose algorithmType, List<string> excludedCredentials, string pin, bool requireUv)
        {
            //Use these values on the commandline when manually creating a credentail using fido2-token in the Yubico libfido2 toolkit
            //var base64cdh = Convert.ToBase64String(Cdh);
            //var base64UserId = Convert.ToBase64String(UserId);

            var ext = useHmacExtension ? FidoExtensions.HmacSecret : FidoExtensions.None;

            //Instructs the authenticator to store the key material on the device. Default false in the spec.
            //var residentKey = false;

            //Instructs the authenticator to require a gesture that verifies the user to complete the request. 
            //Examples of such gestures are fingerprint scan or a PIN.  Default false in the spec.
            //var userVerificationRequired = false;

            using (var cred = new FidoCredential())
            {
                using (var dev = new FidoDevice())
                {
                    dev.Open(devicePath);

                    //if (excludedCredentials != null)
                    //{
                    //    foreach (var excludedCredential in excludedCredentials)
                    //    {
                    //        var credId = Convert.FromBase64String(excludedCredential);
                    //        cred.Exclude(credId);
                    //    }
                    //}

                    cred.SetType(algorithmType);

                    cred.ClientDataHash = Cdh;

                    cred.Rp = new FidoCredentialRp
                    {
                        Id = "relyingparty",
                        //Name = "sweet home localhost"
                    };

                    cred.SetUser(new FidoCredentialUser
                    {
                        Id = UserId,
                        //DisplayName = "john smith",
                        Name = "johnsmith2"
                        //Icon = "http://secone.io/logo.png"
                    });

                    cred.SetExtensions(ext);
                    
                    //Only set these options if we have the capability
                    if (requireUv) cred.SetOptions(false, true);

                    //Make the credential, including the device pin if required
                    dev.MakeCredential(cred, pin);

                    //Seems like we are forcing a close asap even though we have a using
                    dev.Close();
                }

                //Now verify the credential was created successfully, and write out the public key information and credential id

                MakeCredentialResult result;

                using (var verify = new FidoCredential())
                {
                    verify.SetType(algorithmType);

                    verify.ClientDataHash = Cdh;
                    verify.Rp = new FidoCredentialRp
                    {
                        Id = "relyingparty",
                        //Name = "sweet home localhost"
                    };

                    verify.AuthData = cred.AuthData;
                    verify.SetExtensions(ext);

                    if (requireUv) verify.SetOptions(false, true);
                    
                    verify.SetX509(cred.X5C);
                    verify.Signature = cred.Signature;
                    verify.Format = cred.Format;

                    //Throws a CtapException if it fails.
                    verify.Verify();

                    //Now write out the information, because we need the public key created by the device for future assertions
                    result.PublicKey = Convert.ToBase64String(verify.PublicKey.ToArray());
                    result.CredentialId = Convert.ToBase64String(verify.Id.ToArray());
                }

                //Also bang this out to file for future reference
                var builder = new StringBuilder();
                builder.AppendLine($"CredentialId:{result.CredentialId}");
                builder.AppendLine($"PublicKey:{result.PublicKey}");

                File.WriteAllText($"Credential.txt", builder.ToString());

                return result;
            }
        }
    }
}
