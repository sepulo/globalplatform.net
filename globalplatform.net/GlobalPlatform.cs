using System;
using System.Collections.Generic;
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
        #region Static Fields
        
        /// <summary>
        /// Global Platform CLA
        /// </summary>
        public static byte CLA_GP = 0x80;


        /// <summary>
        /// Card default secure channel protocol
        /// </summary>
        public static int SCP_ANY = 0x00;

        /// <summary>
        /// SCP '01' Secure channel protocol identifier
        /// </summary>
        public static int SCP_01 = 0x01;

        /// <summary>
        /// SCP '01' Secure channel protocol identifier
        /// </summary>
        public static int SCP_02 = 0x02;

        /// <summary>
        /// Implementation option "i" = '04': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, no ICV encryption, 1 
        /// Secure Channel base key.
        /// </summary>
        public static int IMPL_OPTION_I_04 = 0x04;

        /// <summary>
        /// Implementation option "i" = '05': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, no ICV encryption, 3 
        /// Secure Channel Keys.
        /// </summary>
        public static int IMPL_OPTION_I_05 = 0x05;

        /// <summary>
        /// Implementation option "i" = '0A': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, no ICV 
        /// encryption, 1 Secure Channel base key.
        /// </summary>
        public static int IMPL_OPTION_I_0A = 0x0A;

        /// <summary>
        /// Implementation option "i" = '0B': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, no ICV 
        /// encryption, 3 Secure Channel Keys.
        /// </summary>
        public static int IMPL_OPTION_I_0B = 0x0B;

        /// <summary>
        /// Implementation option "i" = '14': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption for 
        /// C-MAC session, 1 Secure Channel base key.
        /// </summary>
        public static int IMPL_OPTION_I_14 = 0x14;

        /// <summary>
        /// Implementation option "i" = '15': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption for C-MAC session, 3 
        /// Secure Channel Keys.
        /// </summary>
        public static int IMPL_OPTION_I_15 = 0x15;

        /// <summary>
        /// "i" = '1A': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, ICV 
        /// encryption for C-MAC session, 1 Secure Channel base key.
        /// </summary>
        public static int IMPL_OPTION_I_1A = 0x1A;

        /// <summary>
        /// "i" = '1B': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, ICV 
        /// encryption for C-MAC session,3 Secure Channel Keys. 
        /// </summary>
        public static int IMPL_OPTION_I_1B = 0x1B;

        
        /// <summary>
        /// INITIALIZE UPDATE Command
        /// </summary>
        public static byte INS_INIT_UPDATE = 0x50;

        #endregion
        #region Private Fields
        
        private SecureChannel mSecureChannel;
        
        private byte[] mHostChallenge;

        private int mSecurityLevel;

        private int mSCPIdentifier;

        private int mSCPImplementationOption;
        
        #endregion
        
        #region Public Properties
        
        /// <summary>
        /// Secure Channel
        /// </summary>
        public SecureChannel SecureChannel {get{return mSecureChannel;}}
        
        #endregion
        
        #region Public Methods

        /// <summary>
        /// Generates INITIALIZE UPDATE command with specified static key set.
        /// </summary>
        /// <param name="staticKeySet">Secure channel static key set</param>
        /// <returns>CommandAPDU for INITIALIZE UPDATE command for specified static key set</returns>
        public CommandAPDU CreateInitUpdateCommand(KeySet staticKeySet, int securityLevel, int scpIdentifier, int scpImplementationOption)
        {
            // Validate Secure Channel Identifier
            if ((scpIdentifier != SCP_01) && (scpIdentifier != SCP_02))
                throw new Exception("Invalid secure channel protocol identifier. Currently SCP 01 (0x01) and SCP 02 (0x02) are valid." +
                                     " See Global Platform 2.1.1 Card Spec section 8.6.");

            // Validate Secure Channel Implementation Option for SCP 01
            if (scpIdentifier == SCP_01)
                if ((scpImplementationOption != IMPL_OPTION_I_05) && (scpImplementationOption != IMPL_OPTION_I_15))
                    throw new Exception("Invalid implementation option for SCP 01. See Global Platform 2.1.1 Card Spec section D.1.1.");

            // Validate Secure Channel Implementation Option for SCP 02
            if (scpIdentifier == SCP_02)
            {
                if ((scpImplementationOption != IMPL_OPTION_I_04) && (scpImplementationOption != IMPL_OPTION_I_05) &&
                    (scpImplementationOption != IMPL_OPTION_I_0A) && (scpImplementationOption != IMPL_OPTION_I_0B) &&
                    (scpImplementationOption != IMPL_OPTION_I_14) && (scpImplementationOption != IMPL_OPTION_I_15) &&
                    (scpImplementationOption != IMPL_OPTION_I_1A) && (scpImplementationOption != IMPL_OPTION_I_1B))
                    throw new Exception("Invalid implementation option for SCP 02. See Global Platform 2.1.1 Card Spec section E.1.1.");

                if((scpImplementationOption == IMPL_OPTION_I_0A) || (scpImplementationOption == IMPL_OPTION_I_0B) ||
                   (scpImplementationOption == IMPL_OPTION_I_1A) || (scpImplementationOption == IMPL_OPTION_I_1B))
                    throw new Exception("Implicit secure channel can't be initialized explicitly.");
            }


            mSCPIdentifier = scpIdentifier;
            mSCPImplementationOption = scpImplementationOption;


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

                throw new Exception("Invalid security level. See Global Platform 2.1.1 Card Spec section E.5.2.3 or section D.4.2.3.");

            // Host challenge
            mHostChallenge = new byte[8];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(mHostChallenge);

            // Build INITIALIZE UPDATE command
            CommandAPDU initUpdate = new CommandAPDU(CLA_GP, INS_INIT_UPDATE, staticKeySet.KeyVersion, staticKeySet.KeyID, mHostChallenge, 0x00);
            return initUpdate;
        }


        public void ProcessInitUpdateResponse(ResponseAPDU response)
        {
            if (response.Data.Length != 28)
                throw new Exception("Wrong INI UPDATE response length.");

            
        }

        public CommandAPDU CreateExternalAuthCommand()
        {
            return null;
        }

        public void ProcessExternalAuthResponse(ResponseAPDU response)
        {

        }
        #endregion

    }
}
