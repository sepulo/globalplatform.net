using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace globalplatform.net
{
    public class SecureChannel
    {
        #region Private Fields
        private int mSecurityLevel;
        private KeySet mSessionKeys;
        private int mSCPIdentifier;
        private byte[] mICV;
        private byte[] mRICV;
        private bool mApplyToModifiedAPDU;
        private bool mICVEncryption;
        private MemoryStream mRMACStream;
        private bool mSecurityLevelSet;
        private bool mFirstCommandInChain;

        #endregion

        #region Public Properties
        /// <summary>
        /// Security level of establisged secure channel 
        /// </summary>
        public int SecurityLevel { get { return mSecurityLevel; }
            set
            {
                if (!mSecurityLevelSet)
                {
                    mSecurityLevel = value;
                    if ((mSecurityLevel & net.SecurityLevel.R_MAC) != 0)
                        System.Array.Copy(mICV, mRICV, 8);
                    mSecurityLevelSet = true;
                } else
                    throw new Exception("Security level can be set just once and automatically by CreateExternalAuthCommand() method " +
                                        "after a successful EXTERNAL AUTHENTICATE command.");
            }
        }

        /// <summary>
        /// Secure channel session key set
        /// </summary>
        public KeySet SessionKeys
        {
            get { return mSessionKeys; }
        }


        #endregion

        #region Private Methods
        private void ConfigureImplementation(int scpImplementationOption)
        {
            switch (scpImplementationOption)
            {
                case GlobalPlatform.IMPL_OPTION_I_1B:
                case GlobalPlatform.IMPL_OPTION_I_1A:
                case GlobalPlatform.IMPL_OPTION_I_15:
                case GlobalPlatform.IMPL_OPTION_I_14:
                    mICVEncryption = true;
                    break;
                default:
                    mICVEncryption = false;
                    break;
            }

            switch (scpImplementationOption)
            {
                case GlobalPlatform.IMPL_OPTION_I_0A:
                case GlobalPlatform.IMPL_OPTION_I_0B:
                case GlobalPlatform.IMPL_OPTION_I_1A:
                case GlobalPlatform.IMPL_OPTION_I_1B:
                    mApplyToModifiedAPDU = false;
                    break;
                default:
                    mApplyToModifiedAPDU = true;
                    break;
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs a secure channel
        /// </summary>
        /// <param name="sessionKeys">Session Keys</param>
        /// <param name="securityLevel">Security Level</param>
        /// <param name="scpIdentifier">Secure Channel Identifer: either <see cref="GlobalPlatform.SCP_01"/> or 
        /// <see cref="GlobalPlatform.SCP_02"/>.</param>
        /// <param name="scpImplementationOption">Secure Channel Implementation Option: See GlobalPlatform.IMPL_OPTION_* </param>
        /// <param name="icv">Initial Chaining Vector</param>
        /// <param name="ricv">Response Initial Chaingin Vector</param>
        public SecureChannel(KeySet sessionKeys, int securityLevel, int scpIdentifier,
            int scpImplementationOption, byte[] icv, byte[] ricv)
        {
            mSessionKeys = sessionKeys;
            mSecurityLevel = securityLevel;
            mSCPIdentifier = scpIdentifier;
            mICV = icv;
            mRICV = ricv;
            mFirstCommandInChain = true;

            ConfigureImplementation(scpImplementationOption);

        }

        public CommandAPDU wrap(CommandAPDU command)
        {
            // Apply R-MAC
            if ((mSecurityLevel & net.SecurityLevel.R_MAC) != 0)
            {
                if(mRMACStream != null)
                    throw new Exception("There exists an unwrapped response while R-MAC security level set. Secure channel can only work correctly if " +
                                        "for each wrapped command the corresponding response be unwrapped immediately.");
                mRMACStream = new MemoryStream();

                //Clear 3 LSB of CLA
                mRMACStream.WriteByte((byte)(command.CLA & ~0x07));
                mRMACStream.WriteByte((byte) command.INS);
                mRMACStream.WriteByte((byte) command.P1);
                mRMACStream.WriteByte((byte) command.P2);
                if (command.LC > 0)
                {
                    mRMACStream.WriteByte((byte) command.LC);
                    mRMACStream.Write(command.Data, 0, command.Data.Length);
                }

            }

            if ((mSecurityLevel & (net.SecurityLevel.C_MAC | net.SecurityLevel.C_DECRYPTION)) == 0)
                return command;

            int secureCLA = command.CLA;
            byte[] wrappedData = null;
            int wrappedDataSize = command.LC;

            MemoryStream commandStream = new MemoryStream();

            int maxCommandSize = 255;
            if ((mSecurityLevel & net.SecurityLevel.C_MAC) != 0)
                maxCommandSize -= 8;
            if ((mSecurityLevel & net.SecurityLevel.C_DECRYPTION) != 0)
                maxCommandSize -= 8;
            if(command.LC > maxCommandSize)
                throw new Exception("APDU command too large. Max command length = 255 - 8(for C-MAC if present) - 8(for C-DECRYTPION padding if present).");

            if ((mSecurityLevel & net.SecurityLevel.C_MAC) != 0)
            {
                if (mFirstCommandInChain)
                    mFirstCommandInChain = false;
                else if(mICVEncryption)
                {
                    if (mSCPIdentifier == GlobalPlatform.SCP_01)
                    {
                        mICV = CryptoUtil.TripleDESECB(new Key(mSessionKeys.MacKey.BuildTripleDesKey()), mICV,
                            CryptoUtil.MODE_ENCRYPT);
                    }
                    else
                    {
                        mICV = CryptoUtil.DESECB(new Key(mSessionKeys.MacKey.BuildDesKey()), mICV,
                            CryptoUtil.MODE_ENCRYPT);
                    }
                } // If ICV Encryption

                if (mApplyToModifiedAPDU)
                {
                    secureCLA = command.CLA | 0x04;
                    wrappedDataSize += 8;
                }

                commandStream.WriteByte((byte) secureCLA);
                commandStream.WriteByte((byte) command.INS);
                commandStream.WriteByte((byte) command.P1);
                commandStream.WriteByte((byte) command.P2);
                commandStream.WriteByte((byte) wrappedDataSize);
                commandStream.Write(command.Data, 0, command.Data.Length);
                if (mSCPIdentifier == GlobalPlatform.SCP_01)
                {
                    mICV = CryptoUtil.FullTripleDESMAC(mSessionKeys.MacKey, mICV, CryptoUtil.DESPad(commandStream.ToArray()));
                }
                else
                {
                    mICV = CryptoUtil.SingleDESFullTripleDESMAC(mSessionKeys.MacKey, mICV, CryptoUtil.DESPad(commandStream.ToArray()));
                }

                if (!mApplyToModifiedAPDU)
                {
                    secureCLA = command.CLA | 0x04;
                    wrappedDataSize += 8;
                }
                wrappedData = command.Data;
                commandStream = new MemoryStream();
            } // If C-MAC

            if (((mSecurityLevel & net.SecurityLevel.C_DECRYPTION) != 0) && command.LC > 0)
            {
                if (mSCPIdentifier == GlobalPlatform.SCP_01)
                {
                    if ((command.LC + 1)%8 != 0)
                    {
                        commandStream.WriteByte((byte) command.LC);
                        commandStream.Write(command.Data, 0, command.Data.Length);
                        byte[] paddedData = CryptoUtil.DESPad(commandStream.ToArray());
                        commandStream = new MemoryStream();
                        commandStream.Write(paddedData, 0, paddedData.Length);
                    }
                    else
                    {
                        commandStream.WriteByte((byte)command.LC);
                        commandStream.Write(command.Data, 0, command.Data.Length);
                    }
                } // If SCP '01'
                else
                {
                    byte[] paddedData = CryptoUtil.DESPad(command.Data);
                    commandStream.Write(paddedData, 0, paddedData.Length);
                }
                wrappedDataSize += (int)(commandStream.Length - command.Data.Length);
                wrappedData = CryptoUtil.TripleDESCBC(new Key(mSessionKeys.EncKey.BuildTripleDesKey()),
                    CryptoUtil.BINARY_ZEROS_8_BYTE_BLOCK, commandStream.ToArray(), CryptoUtil.MODE_ENCRYPT);
                commandStream = new MemoryStream();
            }  // If C-DECRYPTION
            commandStream.WriteByte((byte) secureCLA);
            commandStream.WriteByte((byte) command.INS);
            commandStream.WriteByte((byte) command.P1);
            commandStream.WriteByte((byte) command.P2);
            if (wrappedDataSize > 0)
            {
                commandStream.WriteByte((byte) wrappedDataSize);
                commandStream.Write(wrappedData, 0, wrappedData.Length);
            }

            if((mSecurityLevel & net.SecurityLevel.C_MAC) != 0)
                commandStream.Write(mICV, 0, mICV.Length);
            if(command.LE > 0)
                commandStream.WriteByte((byte) command.LE);
 
            return new CommandAPDU(commandStream.ToArray());
        }

        public ResponseAPDU unwrap(ResponseAPDU response)
        {
            if ((mSecurityLevel & net.SecurityLevel.R_MAC) != 0)
            {
                if(response.Data.Length < 8)
                    throw new Exception("Response data length must be at least 8 bytes.");

                if (mRMACStream == null)
                    throw new Exception("No corresponding wrapped command found while R-MAC security level set. Secure channel can only work correctly if " +
                                        "for each wrapped command the corresponding response be unwrapped immediately.");
                int realResponseLength = response.Data.Length - 8;
                mRMACStream.WriteByte((byte) realResponseLength);
                mRMACStream.Write(response.Data, 0, realResponseLength);
                mRMACStream.WriteByte((byte) response.SW1);
                mRMACStream.WriteByte((byte) response.SW2);

                mRICV = CryptoUtil.SingleDESFullTripleDESMAC(mSessionKeys.RmacKey, mRICV, CryptoUtil.DESPad(mRMACStream.ToArray()));

                byte[] realMac = new byte[8];
                System.Array.Copy(response.Data, realResponseLength, realMac, 0, 8);
                if(Enumerable.SequenceEqual(realMac, mRICV))
                    throw new Exception("Invalid R-MAC.");
                mRMACStream = null;
                response = new ResponseAPDU(response.SW1, response.SW2, CryptoUtil.SubArray(response.Data, 0, realResponseLength));
            }
            return response;
        }


        #endregion
    }
}
