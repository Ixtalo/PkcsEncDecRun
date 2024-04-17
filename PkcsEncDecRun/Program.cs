namespace PkcsEncDecRun
{
    using System;
    using System.Collections.Generic;
    using System.CommandLine;
    using System.Configuration;
    using System.Diagnostics;
    using System.IO;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Net.Pkcs11Interop.Common;
    using Net.Pkcs11Interop.HighLevelAPI;

    /// <summary>
    /// Starts processes where the command and its arguments are encrypted using a smartcard/PKCS#11.
    /// </summary>
    internal static class Program
    {
        private static readonly string PIN_ENV_NAME = "PKCS_PIN";
        private static readonly string EXEARGSDELIMITER = "|~|";
        private static readonly Pkcs11InteropFactories Factories = new Pkcs11InteropFactories();
        private static string pkcs11LibraryPath;
        private static string tokenSerial;
        private static string keyId;
        private static string tokenPin;

        /// <summary>
        /// CLI main program entry.
        /// </summary>
        /// <param name="args">CLI arguments.</param>
        /// <returns>exit code.</returns>
        public static async Task<int> Main(string[] args)
        {
#if DEBUG
            // if in DEBUG mode
            // and debugger is active (e.g. Visual Studio)
            // and no args are given
            // then provide args here
            if (Debugger.IsAttached && args.Length != 2)
#pragma warning disable S125 // Sections of code should not be commented out
            {
                args = new string[] { "enc", new string('a', 300) };
                // "ttJHsA5MDLvNx..." == "a"
                // args = new string[] { Mode.DECODE, "ttJHsA5MDLvNx92tICFk5pFkKHZpxCzZkxdJNNtZF+THlquiWzuUokXqkEvUbINMy+qJ2aKUpaLLaJu+T8thVCciV7p34tADKDgn02sZyGIpMrkQE47tcVndpiFf/OLHkS3QOB6zZo5b/fnUzhnJxpf7NThwieeJ+hVAYlX0jwNjQPgzXfru1X18r/MI7XHj9+m+I/WwmVEvaZtzO6+sag=="};
                // args = new string[] { "info" };
            }
#pragma warning restore S125 // Sections of code should not be commented out
#endif

            // PIN - can be given as an environemt variable; if so then no user prompt will be shown.
            var pinStr = Environment.GetEnvironmentVariable(PIN_ENV_NAME);
            tokenPin = null;
            if (!string.IsNullOrEmpty(pinStr))
            {
                tokenPin = pinStr;
            }

            // configuration from App.config
            pkcs11LibraryPath = ConfigurationManager.AppSettings["Pkcs11LibraryPath"] ?? @"c:\SoftHSM2\lib\softhsm2.dll";
            tokenSerial = ConfigurationManager.AppSettings["TokenSerial"];
            keyId = ConfigurationManager.AppSettings["KeyIdString"];

            if (string.IsNullOrWhiteSpace(pkcs11LibraryPath)
                || string.IsNullOrWhiteSpace(tokenSerial)
                || string.IsNullOrWhiteSpace(keyId))
            {
                Console.Error.WriteLine("Invalid configuration (missing values)!");
                return -1;
            }

            var rootCommand = new RootCommand("PkcsEncDecRun");

            var infoCommand = new Command("info", "Information about token and keys.");
            rootCommand.Add(infoCommand);
            infoCommand.SetHandler(() => ShowInfo());

            var encryptCommand = new Command("enc", "Encrypt data.");
            rootCommand.Add(encryptCommand);
            encryptCommand.AddAlias("encrypt");
            Argument<string> encryptDataArgument = new Argument<string>(name: "data", description: "Plain text data (string).");
            encryptCommand.AddArgument(encryptDataArgument);
            encryptCommand.SetHandler((data) =>
            {
                byte[] value = Encrypt(data);
                if (value.Length > 0)
                    Console.WriteLine(ConvertUtils.BytesToBase64String(value));
            }, encryptDataArgument);

            Argument<string> decryptDataArgument = new Argument<string>(name: "data", description: "base64-encrypted data.");
            var decryptCommand = new Command("dec", "Decrypt data.");
            rootCommand.Add(decryptCommand);
            decryptCommand.AddAlias("decrypt");
            decryptCommand.AddArgument(decryptDataArgument);
            decryptCommand.SetHandler((data) =>
            {
                byte[] bytes = null;
                try
                {
                    bytes = ConvertUtils.Base64StringToBytes(data);
                }
                catch (FormatException ex)
                {
                    Console.Error.WriteLine($"Invalid input: {ex.Message}");
                }
                if (bytes != null)
                {
                    string value = Decrypt(bytes);
                    if (value.Length > 0)
                        Console.WriteLine(value);
                }
            }, decryptDataArgument);

            var runCommand = new Command("run", "Decrypt data and use it as command line to run.");
            rootCommand.Add(runCommand);
            runCommand.AddArgument(decryptDataArgument);
            runCommand.SetHandler((data) =>
            {
                byte[] bytes = null;
                try
                {
                    bytes = ConvertUtils.Base64StringToBytes(data);
                }
                catch (FormatException ex)
                {
                    Console.Error.WriteLine($"Invalid input: {ex.Message}");
                }
                if (bytes != null)
                {
                    string value = Decrypt(bytes);
                    if (value.Length > 0)
                        StartProcess(value);
                }
            }, decryptDataArgument);

            return await rootCommand.InvokeAsync(args);
        }

        /// <summary>
        /// Starts a new process.
        /// </summary>
        /// <param name="cmd">Command, i.e. EXE filename with path plus, optionally, parameters separated by |~|. Example: calc.exe|~|/foobar</param>
        public static void StartProcess(string cmd)
        {
            string exe;
            string args = null;
            if (cmd.Contains(EXEARGSDELIMITER))
            {
                var fields = cmd.Split(new string[] { EXEARGSDELIMITER }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length != 2)
                    throw new InvalidOperationException("Invalid command string! Too many delimiters?");
                exe = fields[0];
                args = fields[1];
            }
            else
            {
                exe = cmd;
            }
            Process.Start(exe, args);
        }

        /// <summary>
        /// Show various information about the unmanaged library, slots, tokens and mechanisms.
        /// </summary>
        public static void ShowInfo()
        {
            using (IPkcs11Library pkcs11Library = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Show general information about loaded library
                ILibraryInfo libraryInfo = pkcs11Library.GetInfo();

                Console.WriteLine("Library");
                Console.WriteLine("  Manufacturer:       " + libraryInfo.ManufacturerId);
                Console.WriteLine("  Description:        " + libraryInfo.LibraryDescription);
                Console.WriteLine("  Version:            " + libraryInfo.LibraryVersion);

                // Get list of all available slots
                foreach (ISlot slot in pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    // Show basic information about slot
                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    Console.WriteLine();
                    Console.WriteLine("Slot");
                    Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
                    Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
                    Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        // Show basic information about token present in the slot
                        ITokenInfo tokenInfo = slot.GetTokenInfo();

                        Console.WriteLine("Token");
                        Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                        Console.WriteLine("  Model:              " + tokenInfo.Model);
                        Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                        Console.WriteLine("  Label:              " + tokenInfo.Label);

                        // Show list of mechanisms (algorithms) supported by the token
                        Console.WriteLine("Supported mechanisms: ");
                        foreach (CKM mechanism in slot.GetMechanismList())
                            Console.WriteLine("  " + mechanism);

                        // look for suitable keys
                        try
                        {
                            using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                            {
                                // search attributes/parameters
                                List<IObjectAttribute> searchParams = new List<IObjectAttribute>
                                {
                                    // must not be private (login would be required for that!)
                                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                                    // suitable for encrryption
                                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                                    // RSA key
                                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                                };
                                var foundObjects = session.FindAllObjects(searchParams);
                                Console.WriteLine($"Found {foundObjects.Count} suitable key(s).");

                                foreach (var obj in foundObjects)
                                {
                                    List<CKA> attributesToRead = new List<CKA>
                                    {
                                        CKA.CKA_LABEL,
                                        CKA.CKA_ID,
                                    };
                                    List<IObjectAttribute> objectAttributes = session.GetAttributeValue(obj, attributesToRead);
                                    string label = objectAttributes[0].GetValueAsString();
                                    string id_str = ConvertUtils.BytesToHexString(objectAttributes[1].GetValueAsByteArray());
                                    Console.WriteLine($"Key: label='{label}', id='{id_str}'");
                                }
                            }
                        }
                        catch (Pkcs11Exception ex)
                        {
                            if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED)
                                throw;
                        }

                    } // if slot TokenPresent
                } // foreach slot
            }
        }

        /// <summary>
        /// Asymetric (hybrid) encryption using RSA to encrypt key and AES for message encryption.
        /// </summary>
        /// <param name="data">plain text data (string).</param>
        /// <returns>encrypted data.</returns>
        public static byte[] Encrypt(string data)
        {
            byte[] encryptedData;

            using (IPkcs11Library pkcs11Library = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, pkcs11LibraryPath, AppType.SingleThreaded))
            {
                ISlot slot = GetUsableSlot(pkcs11Library, tokenSerial);
                if (slot == null)
                {
                    Console.Error.WriteLine("Could not find a usable PKCS token! (Is the smartcard present, is the serial number correct?)");
                    return new byte[0];
                }
                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                {
                    // key encryption is done using the RSA public key
                    var pubkey = GetPublicKey(session, keyId)
                        ?? throw new InvalidOperationException($"Could not get public key - check the ID! (key id={keyId})");

                    // any random key works because we encrypt this key for transport using RSA
                    byte[] mykey = session.GenerateRandom(32);

                    // encrypt key with RSA (this is the important step!)
                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
                    byte[] encryptedKey = session.Encrypt(mechanism, pubkey, mykey);

                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = mykey;
                        aes.IV = session.GenerateRandom(aes.IV.Length);

                        // write data to memory
                        using (MemoryStream stream = new MemoryStream())
                        {
                            // (unencrypted) IV transport: prepend to stream
                            stream.Write(aes.IV, 0, aes.IV.Length);

                            // (unencrypted) write of encrypted (!) key
                            stream.Write(encryptedKey, 0, encryptedKey.Length);

                            // now encrypt data
                            using (CryptoStream cryptoStream = new CryptoStream(stream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                            using (StreamWriter encryptWriter = new StreamWriter(cryptoStream))
                            {
                                // encrypt data (AES)
                                encryptWriter.Write(data);
                            }
                            encryptedData = stream.ToArray();
                        }
                    }
                } // session
            } // lib
            return encryptedData;
        }

        /// <summary>
        /// Asymetric (hybrid) decryption.
        /// </summary>
        /// <param name="encryptedData">data as encrypted byte array.</param>
        /// <returns>decrypted data.</returns>
        public static string Decrypt(byte[] encryptedData)
        {
            string decryptedData;

            using (IPkcs11Library pkcs11Library = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, pkcs11LibraryPath, AppType.SingleThreaded))
            {
                ISlot slot = GetUsableSlot(pkcs11Library, tokenSerial);
                if (slot == null)
                {
                    Console.Error.WriteLine("Could not find a usable PKCS token! (Is the smartcard present, is the serial number correct?)");
                    return string.Empty;
                }
                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                {
                    session.Login(CKU.CKU_USER, tokenPin);

                    var privkey = GetPrivateKey(session, keyId)
                        ?? throw new InvalidOperationException($"Could not get private key - provide PIN and check ID! (key id={keyId})");
                    var pubkey = GetPublicKey(session, keyId)
                        ?? throw new InvalidOperationException($"Could not get public key - check the ID! (key id={keyId})");

                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);

                    using (Aes aes = Aes.Create())
                    using (MemoryStream stream = new MemoryStream(encryptedData))
                    {
                        // read IV (n bytes) at the beginning of the stream
                        byte[] iv = new byte[aes.IV.Length];
                        int bytesReadIV = stream.Read(iv, 0, aes.IV.Length);
                        if (bytesReadIV != aes.IV.Length)
                            throw new InvalidOperationException($"Invalid IV length! (expected: {aes.IV.Length}, actual:{bytesReadIV})");

                        // determine the size of the key which has been used for encryption (it was the RSA public key)
                        List<CKA> attributesToRead = new List<CKA>
                        {
                            CKA.CKA_MODULUS_BITS,
                        };
                        List<IObjectAttribute> objectAttributes = session.GetAttributeValue(pubkey, attributesToRead);
                        int keyLength = (int)objectAttributes[0].GetValueAsUlong() / 8;    // bit to bytes

                        // read the encrypted key
                        byte[] encryptedKey = new byte[keyLength];
                        int bytesReadKey = stream.Read(encryptedKey, 0, keyLength);
                        if (bytesReadKey != keyLength)
                            throw new InvalidOperationException($"Invalid key length! (expected: {keyLength}, actual:{bytesReadKey})");

                        // decrypt key (this is where the real encryption-decryption-magic happens)
                        byte[] key = null;
                        try
                        {
                            key = session.Decrypt(mechanism, privkey, encryptedKey);
                        }
                        catch (Pkcs11Exception)
                        {
                            Console.Error.WriteLine("Could not decrypt! Perhaps wrong key?");
                            throw;
                        }

                        // use decrypted key and IV to decrypt the data
                        using (CryptoStream cryptoStream = new CryptoStream(stream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                        using (StreamReader decryptReader = new StreamReader(cryptoStream))
                        {
                            decryptedData = decryptReader.ReadToEnd();
                        }
                    }

                    session.Logout();
                } // session
            } // lib

            return decryptedData;
        }

        private static byte[] ConvertKeyIdStringToBytes(string keyIdString) => ConvertUtils.HexStringToBytes(keyIdString.Replace(" ", string.Empty).Trim());

        private static IObjectHandle GetKey(ISession session, string keyIdString, bool cka_private)
        {
            byte[] id = ConvertKeyIdStringToBytes(keyIdString);
            List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, id),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, cka_private),
            };
            var foundObjects = session.FindAllObjects(objectAttributes);
            if (foundObjects != null && foundObjects.Count > 0)
            {
                // take the first found element
                return foundObjects[0];
            }
            return null;
        }

        private static IObjectHandle GetPrivateKey(ISession session, string keyIdString) => GetKey(session, keyIdString, true);

        private static IObjectHandle GetPublicKey(ISession session, string keyIdString) => GetKey(session, keyIdString, false);

        /// <summary>
        /// Finds slot containing the token that matches criteria specified in Settings class.
        /// </summary>
        /// <param name='pkcs11Library'>Initialized PKCS11 wrapper.</param>
        /// <returns>Slot containing the token that matches criteria.</returns>
        private static ISlot GetUsableSlot(IPkcs11Library pkcs11Library, string serial = null)
        {
            List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

            if (slots.Count == 0)
                return null;

            // take 1st slot
            ISlot matchingSlot = slots[0];

            if (!string.IsNullOrEmpty(serial))
            {
                matchingSlot = null;
                foreach (ISlot slot in slots)
                {
                    ITokenInfo tokenInfo = null;
                    try
                    {
                        tokenInfo = slot.GetTokenInfo();
                    }
                    catch (Pkcs11Exception ex)
                    {
                        if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                            throw;
                    }
                    if (tokenInfo == null)
                        continue;
                    if (string.Compare(serial, tokenInfo.SerialNumber, StringComparison.Ordinal) == 0)
                    {
                        matchingSlot = slot;
                        break;
                    }
                }
            }
            return matchingSlot;
        }

    } // class
} // namespace
