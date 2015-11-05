using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace globalplatform.net
{
    /// <summary>
    /// An implementation of Global Platform services. It is designed to be used for indirect 
    /// and asyncronous management of Global Platform compliant cards.
    /// </summary>
    public class GlobalPlatform
    {
        #region Constant Fields

        /// <summary>
        /// Global Platform CLA
        /// </summary>
        public const byte CLA_GP = 0x80;

        /// <summary>
        /// Global Platform secure messaging CLA
        /// </summary>
        public const byte CLA_SECURE_GP = 0x84;


        /// <summary>
        /// Card default secure channel protocol
        /// </summary>
        public const int SCP_ANY = 0x00;

        /// <summary>
        /// SCP '01' Secure channel protocol identifier
        /// </summary>
        public const int SCP_01 = 0x01;

        /// <summary>
        /// SCP '01' Secure channel protocol identifier
        /// </summary>
        public const int SCP_02 = 0x02;

        /// <summary>
        /// Card default secure channel implementation option
        /// </summary>
        public const int IMPL_OPTION_ANY = 0x00;

        /// <summary>
        /// Implementation option "i" = '04': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, no ICV encryption, 1 
        /// Secure Channel base key.
        /// </summary>
        public const int IMPL_OPTION_I_04 = 0x04;

        /// <summary>
        /// Implementation option "i" = '05': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, no ICV encryption, 3 
        /// Secure Channel Keys.
        /// </summary>
        public const int IMPL_OPTION_I_05 = 0x05;

        /// <summary>
        /// Implementation option "i" = '0A': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, no ICV 
        /// encryption, 1 Secure Channel base key.
        /// </summary>
        public const int IMPL_OPTION_I_0A = 0x0A;

        /// <summary>
        /// Implementation option "i" = '0B': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, no ICV 
        /// encryption, 3 Secure Channel Keys.
        /// </summary>
        public const int IMPL_OPTION_I_0B = 0x0B;

        /// <summary>
        /// Implementation option "i" = '14': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption for 
        /// C-MAC session, 1 Secure Channel base key.
        /// </summary>
        public const int IMPL_OPTION_I_14 = 0x14;

        /// <summary>
        /// Implementation option "i" = '15': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption for C-MAC session, 3 
        /// Secure Channel Keys.
        /// </summary>
        public const int IMPL_OPTION_I_15 = 0x15;

        /// <summary>
        /// "i" = '1A': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, ICV 
        /// encryption for C-MAC session, 1 Secure Channel base key.
        /// </summary>
        public const int IMPL_OPTION_I_1A = 0x1A;

        /// <summary>
        /// "i" = '1B': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, ICV 
        /// encryption for C-MAC session,3 Secure Channel Keys. 
        /// </summary>
        public const int IMPL_OPTION_I_1B = 0x1B;


        /// <summary>
        /// INITIALIZE UPDATE Command
        /// </summary>
        public const byte INS_INIT_UPDATE = 0x50;

        /// <summary>
        /// EXTERNAL AUTHENTICATE Command
        /// </summary>
        public const byte INS_EXT_AUTH = 0x82;

        /// <summary>
        /// PUT KEY Command
        /// </summary>
        public const byte INS_PUT_KEY = 0xD8;
        /// <summary>
        /// Format 1 for PUT Key command
        /// </summary>
        public const int KEY_FORMAT_1 = 0x01;

        /// <summary>
        /// Format 2 for PUT Key command. It is reserved for future use.
        /// </summary>
        public const int KEY_FORMAT_2 = 0x02;

        private static readonly byte[] CONSTANT_MAC_0101 = new byte[] {0x01, 0x01};
        private static readonly byte[] CONSTANT_RMAC_0102 = new byte[] {0x01, 0x02};
        private static readonly byte[] CONSTANT_ENC_0182 = new byte[] {0x01, 0x82};
        private static readonly byte[] CONSTANT_DEK_0181 = new byte[] {0x01, 0x81};

        #endregion

        #region Private Fields

        private SecureChannel mSecureChannel;

        private KeySet mSessionKeys;

        private byte[] mHostChallenge;

        private KeySet mStaticKeys;

        private int mSecurityLevel;

        private int mSCPIdentifier;

        private int mSCPImplementationOption;

        private byte[] mInitUpdateResponse = new byte[28];

        #endregion

        #region Public Properties

        /// <summary>
        /// Secure Channel
        /// </summary>
        public SecureChannel SecureChannel
        {
            get { return mSecureChannel; }
        }

        #endregion

        #region Private Methods

        private void checkResponse(int sw1, int sw2, string message)
        {
            if (sw1 != 0x90 && sw2 != 0x00)
                throw new Exception(message);
        }

        private KeySet GenerateSessionKeysSCP01(byte[] cardResponse)
        {
            KeySet sessionKeySet = new KeySet();
            byte[] derivationData = new byte[16];

            System.Array.Copy(cardResponse, 16, derivationData, 0, 4);
            System.Array.Copy(mHostChallenge, 0, derivationData, 4, 4);
            System.Array.Copy(cardResponse, 12, derivationData, 8, 4);
            System.Array.Copy(mHostChallenge, 4, derivationData, 12, 4);

            sessionKeySet.EncKey =
                new Key(CryptoUtil.TripleDESECB(new Key(mStaticKeys.EncKey.BuildTripleDesKey()), derivationData,
                    CryptoUtil.MODE_ENCRYPT));
            sessionKeySet.MacKey =
                new Key(CryptoUtil.TripleDESECB(new Key(mStaticKeys.MacKey.BuildTripleDesKey()), derivationData,
                    CryptoUtil.MODE_ENCRYPT));
            sessionKeySet.KekKey = new Key(mStaticKeys.KekKey.Value);

            return sessionKeySet;
        }

        private KeySet GenerateSessionKeysSCP02(byte[] sequenceCoutner)
        {
            KeySet sessionKeySet = new KeySet();
            byte[] derivationData = new byte[16];
            System.Array.Copy(sequenceCoutner, 0, derivationData, 2, 2);
            System.Array.Clear(derivationData, 4, 12);


            // Todo: consider implicit case

            // Derivate session MAC key
            System.Array.Copy(CONSTANT_MAC_0101, 0, derivationData, 0, 2);
            sessionKeySet.MacKey =
                new Key(CryptoUtil.TripleDESCBC(new Key(mStaticKeys.MacKey.BuildTripleDesKey()),
                    CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, derivationData, CryptoUtil.MODE_ENCRYPT));

            // Derivate session R-MAC key
            // To build R-MAC key static MAC key is used.
            System.Array.Copy(CONSTANT_RMAC_0102, 0, derivationData, 0, 2);
            sessionKeySet.RmacKey =
                new Key(CryptoUtil.TripleDESCBC(new Key(mStaticKeys.MacKey.BuildTripleDesKey()),
                    CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, derivationData, CryptoUtil.MODE_ENCRYPT));

            // Derivate session ENC key
            System.Array.Copy(CONSTANT_ENC_0182, 0, derivationData, 0, 2);
            sessionKeySet.EncKey =
                new Key(CryptoUtil.TripleDESCBC(new Key(mStaticKeys.EncKey.BuildTripleDesKey()),
                    CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, derivationData, CryptoUtil.MODE_ENCRYPT));

            // Derivate session KEK key
            System.Array.Copy(CONSTANT_DEK_0181, 0, derivationData, 0, 2);
            sessionKeySet.KekKey =
                new Key(CryptoUtil.TripleDESCBC(new Key(mStaticKeys.KekKey.BuildTripleDesKey()),
                    CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, derivationData, CryptoUtil.MODE_ENCRYPT));


            return sessionKeySet;
        }

        private byte[] EncodeKeyData(Key key, Key kek, bool addKCV, int keyFormat)
        {
            MemoryStream keyData = new MemoryStream();
            if (keyFormat == KEY_FORMAT_1)
            {
                // Key encryption algorithm
                keyData.WriteByte(CryptoUtil.ALG_DES);

                // Encrypted key data length
                keyData.WriteByte(0x10);

                byte[] encryptedKey = CryptoUtil.TripleDESECB(kek, key.Value, CryptoUtil.MODE_ENCRYPT);
                keyData.Write(encryptedKey, 0, encryptedKey.Length);

                if (addKCV)
                {

                    // KCV length
                    keyData.WriteByte(0x03);

                    // Calculate KCV
                    byte[] kcv = CryptoUtil.TripleDESECB(new Key(key.BuildTripleDesKey()),
                        CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK,
                        CryptoUtil.MODE_ENCRYPT);
                    keyData.Write(kcv, 0, 3);
                }
                else
                {
                    keyData.WriteByte(0x00);
                }
            }

            return keyData.ToArray();
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Generates INITIALIZE UPDATE command with specified static key set.
        /// </summary>
        /// <param name="staticKeySet">Secure channel static key set</param>
        /// <param name="securityLevel">Security level. It must be a valid combination of 
        /// security level bit pattern defined in <see cref="SecurityLevel"/>.</param>
        /// <param name="scpIdentifier">Secure Channel Identifier according to Global Platform 2.1.1 Card Spec section 8.6.
        /// Currently SCP '01' and SCP '02' is supported. Use <see cref="SCP_ANY"/> if you are not sure.</param>
        /// <param name="scpImplementationOption">Secure Channel Implementation Option according to
        /// Global Platform 2.1.1 Card Spec section D.1.1 for SCP '01' or section E.1.1 for SCP '02'. Use <see cref="IMPL_OPTION_ANY"/> 
        /// along with <see cref="SCP_ANY"/> for Secure Channel Identifier, if you are not sure.</param>
        /// <returns>CommandAPDU for INITIALIZE UPDATE command for specified static key set</returns>
        public CommandAPDU CreateInitUpdateCommand(KeySet staticKeySet, int securityLevel, int scpIdentifier,
            int scpImplementationOption)
        {
            // Validate Secure Channel Identifier
            if ((scpIdentifier != SCP_01) && (scpIdentifier != SCP_02) && (scpIdentifier != SCP_ANY))
                throw new Exception(
                    "Invalid secure channel protocol identifier. Currently SCP 01 (0x01) and SCP 02 (0x02) are valid." +
                    " See Global Platform 2.1.1 Card Spec section 8.6.");

            //Validate Secure Channel Implementation Option
            if (scpImplementationOption == IMPL_OPTION_ANY && scpIdentifier != SCP_ANY)
                throw new Exception(
                    "Secure Channel Implementation Option IMPL_OPTION_ANY can only be used along with Secure Channel Identifier SCP_ANY.");


            if (scpIdentifier == SCP_ANY)
            {
                if (scpImplementationOption != IMPL_OPTION_I_05 && scpImplementationOption != IMPL_OPTION_I_15 &&
                    scpImplementationOption != IMPL_OPTION_ANY)
                    throw new Exception(
                        "Invalid implementation option. Only IMPL_OPTION_I_05, IMPL_OPTION_I_15 or IMPL_OPTION_ANY can be used along with SCP_ANY.");
            }

            // Validate Secure Channel Implementation Option for SCP 01
            if (scpIdentifier == SCP_01)
                if ((scpImplementationOption != IMPL_OPTION_I_05) && (scpImplementationOption != IMPL_OPTION_I_15))
                    throw new Exception(
                        "Invalid implementation option for SCP 01. See Global Platform 2.1.1 Card Spec section D.1.1.");

            // Validate Secure Channel Implementation Option for SCP 02
            if (scpIdentifier == SCP_02)
            {
                if ((scpImplementationOption != IMPL_OPTION_I_04) && (scpImplementationOption != IMPL_OPTION_I_05) &&
                    (scpImplementationOption != IMPL_OPTION_I_0A) && (scpImplementationOption != IMPL_OPTION_I_0B) &&
                    (scpImplementationOption != IMPL_OPTION_I_14) && (scpImplementationOption != IMPL_OPTION_I_15) &&
                    (scpImplementationOption != IMPL_OPTION_I_1A) && (scpImplementationOption != IMPL_OPTION_I_1B))
                    throw new Exception(
                        "Invalid implementation option for SCP 02. See Global Platform 2.1.1 Card Spec section E.1.1.");

                if ((scpImplementationOption == IMPL_OPTION_I_0A) || (scpImplementationOption == IMPL_OPTION_I_0B) ||
                    (scpImplementationOption == IMPL_OPTION_I_1A) || (scpImplementationOption == IMPL_OPTION_I_1B))
                    throw new Exception("Implicit secure channel can't be initialized explicitly.");
            }


            mSCPIdentifier = scpIdentifier;
            mSCPImplementationOption = scpImplementationOption;
            mStaticKeys = staticKeySet;
            mSecurityLevel = securityLevel;


            // C-DECRYPTION allways come with C-MAC
            if ((securityLevel & SecurityLevel.C_DECRYPTION) != 0)
                securityLevel |= SecurityLevel.C_MAC;

            // Validate security level
            if (securityLevel != (SecurityLevel.NO_SECURITY_LEVEL) &&
                securityLevel != (SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC | SecurityLevel.R_MAC) &&
                securityLevel != (SecurityLevel.C_MAC | SecurityLevel.R_MAC) &&
                securityLevel != (SecurityLevel.R_MAC) &&
                securityLevel != (SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC) &&
                securityLevel != (SecurityLevel.C_MAC))

                throw new Exception(
                    "Invalid security level. See Global Platform 2.1.1 Card Spec section E.5.2.3 or section D.4.2.3.");

            // Host challenge
            mHostChallenge = new byte[8];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(mHostChallenge);

            // Build INITIALIZE UPDATE command
            CommandAPDU initUpdate = new CommandAPDU(CLA_GP, INS_INIT_UPDATE, staticKeySet.KeyVersion,
                staticKeySet.KeyId, mHostChallenge, 0x00);
            return initUpdate;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="response"></param>

        public void ProcessInitUpdateResponse(ResponseAPDU response)
        {
            checkResponse(response.SW1, response.SW2, "INITIALIZE UPDATE command failed.");

            // Check response length it should always be 28 bytes
            if (response.Data.Length != 28)
                throw new Exception("Wrong INIT UPDATE response length.");

            System.Array.Copy(response.Data, mInitUpdateResponse, 28);

            if (mSCPIdentifier == SCP_ANY)
            {
                mSCPIdentifier = mInitUpdateResponse[11] == SCP_02 ? SCP_02 : SCP_01;
                if (mSCPImplementationOption == IMPL_OPTION_ANY)
                    mSCPImplementationOption = mSCPIdentifier == SCP_02 ? IMPL_OPTION_I_15 : IMPL_OPTION_I_05;
            }

            if (mSCPIdentifier != mInitUpdateResponse[11])
                throw new Exception("Secure channel identifier specified does not match to card");

            // If we use SPC '01' then clear R_MAC bit
            if (mSCPIdentifier == SCP_01)
                mSecurityLevel &= ~SecurityLevel.R_MAC;

            // derivate session keys
            if (mSCPIdentifier == SCP_01)
                mSessionKeys = GenerateSessionKeysSCP01(mInitUpdateResponse);
            else if (mSCPIdentifier == SCP_02)
            {
                byte[] sequenceCoutner = new byte[2];
                System.Array.Copy(mInitUpdateResponse, 12, sequenceCoutner, 0, 2);
                mSessionKeys = GenerateSessionKeysSCP02(sequenceCoutner);
            }

            MemoryStream memStream = new MemoryStream();
            memStream.Write(mHostChallenge, 0, mHostChallenge.Length);
            memStream.Write(mInitUpdateResponse, 12, 8);

            byte[] calculatedCryptogram = CryptoUtil.FullTripleDESMAC(mSessionKeys.RetrieveKey(Key.KEY_TYPE_ENC),
                CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, CryptoUtil.DESPad(memStream.ToArray()));

            byte[] cardCryptogram = new byte[8];
            System.Array.Copy(mInitUpdateResponse, 20, cardCryptogram, 0, 8);
            if (!Enumerable.SequenceEqual(cardCryptogram, calculatedCryptogram))
                throw new Exception("Invalid cryptogram.");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public CommandAPDU CreateExternalAuthCommand()
        {
            MemoryStream memStream = new MemoryStream();
            memStream.Write(mInitUpdateResponse, 12, 8);
            memStream.Write(mHostChallenge, 0, mHostChallenge.Length);

            byte[] hostCryptogram = CryptoUtil.FullTripleDESMAC(mSessionKeys.RetrieveKey(Key.KEY_TYPE_ENC),
                CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, CryptoUtil.DESPad(memStream.ToArray()));
            int P1 = mSecurityLevel;

            CommandAPDU externalAuth = new CommandAPDU(CLA_SECURE_GP, INS_EXT_AUTH, P1, 0x00, hostCryptogram);
            mSecureChannel = new SecureChannel(mSessionKeys, SecurityLevel.C_MAC, mSCPIdentifier,
                mSCPImplementationOption, CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK);
            externalAuth = mSecureChannel.wrap(externalAuth);
            return externalAuth;
        }

        public void ProcessExternalAuthResponse(ResponseAPDU response)
        {
            checkResponse(response.SW1, response.SW2, "EXTERNAL AUTHENTICATE command failed.");
            mSecureChannel.SecurityLevel = mSecurityLevel;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keys"></param>
        /// <param name="replaceExisting"></param>
        /// <param name="keyFormat"></param>
        /// <returns></returns>
        public CommandAPDU CreatePutKeyCommand(List<Key> keys, bool replaceExisting, bool addKCV, int keyFormat)
        {
            int p1;
            int p2;
            if (keyFormat == KEY_FORMAT_2)
                throw new Exception("Format 2 is reserved for futrue use.");
            if (keyFormat != KEY_FORMAT_1)
                throw new Exception("Unknown format");

            int prevId = -1;
            for (int i = 0; i < keys.Count; i++)
            {
                Key key = keys[i];
                if (i > 1)
                    if (key.KeyId != prevId + 1)
                        throw new Exception("Key Identifiers must sequentially increment. See See Global Platform 2.1.1 Card Spec section 9.8.2.3.1");
                prevId = key.KeyId;
            }

            if (replaceExisting)
                p1 = keys[0].KeyVersion;
            else
            {
                p1 = 0;
            }

            p2 = keys[0].KeyId;

            // Multiple keys
            if (keys.Count > 1)
                p2 |= 0x80;

            Key kek = null;
            if (mSCPIdentifier == SCP_01)
                kek = new Key(mStaticKeys.KekKey.BuildTripleDesKey());
            else if(mSCPIdentifier == SCP_02)
            {
                kek = new Key(mSessionKeys.KekKey.BuildTripleDesKey());
            }

            MemoryStream allKeyData = new MemoryStream();
            allKeyData.WriteByte((byte)keys[0].KeyVersion);
            for (int i = 0; i < keys.Count; i++)
            {
                Key key = keys[i];
                byte[] keyDataBytes = EncodeKeyData(key, kek, addKCV, keyFormat);
                allKeyData.Write(keyDataBytes, 0, keyDataBytes.Length);
                
            }
            CommandAPDU putKeyCommand = new CommandAPDU(CLA_GP, INS_PUT_KEY, p1, p2, allKeyData.ToArray(), 0x00);
            putKeyCommand = mSecureChannel.wrap(putKeyCommand);
            return putKeyCommand;
        }



        #endregion
    }
}
