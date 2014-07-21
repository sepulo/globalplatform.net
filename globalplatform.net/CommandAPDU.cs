using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace globalplatform.net
{
    /// <summary>
    /// Represents a command APDU.
    /// </summary>
    /// ToDo: Support Extended APDU
    class CommandAPDU
    {
        #region Static Fields
        /// <summary>
        /// CLA offset in APDU
        /// </summary>
        public static byte OFFSET_CLA   = 0x0;
        /// <summary>
        /// INS offset in APDU
        /// </summary>
        public static byte OFFSET_INS   = 0x1;
        /// <summary>
        /// P1 offset in APDU
        /// </summary>
        public static byte OFFSET_P1    = 0x2;
        /// <summary>
        /// P2 offset in APDU
        /// </summary>
        public static byte OFFSET_P2    = 0x3;
        /// <summary>
        /// LC offset in APDU
        /// </summary>
        public static byte OFFSET_LC    = 0x4;
        /// <summary>
        /// DATA offset in APDU
        /// </summary>
        public static byte OFFSET_CDATA = 0x5;
        #endregion

        #region Private Fields
        private int mCLA;
        private int mINS;
        private int mP1;
        private int mP2;
        private int mLC;
        private int mLE;
        private byte[] mData;
        #endregion

        #region Public Properties
        /// <summary>
        /// CLA
        /// </summary>
        public int CLA { get{ return mCLA; } }
        /// <summary>
        /// INS
        /// </summary>
        public int INS { get { return mINS; } }
        /// <summary>
        /// P1
        /// </summary>
        public int P1 { get { return mP1; } }
        /// <summary>
        /// P2
        /// </summary>
        public int P2 { get { return mP2; } }
        /// <summary>
        /// LC
        /// </summary>
        public int LC { get { return mLC; } }
        /// <summary>
        /// LE
        /// </summary>
        public int LE { get { return mLE; } }
        /// <summary>
        /// APDU data
        /// </summary>
        public byte[] Data { get { return mData; } }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs CommandAPDU from cla, ins, p1, p2, data and le. LC is 
        /// taken from data.Length
        /// </summary>
        /// <param name="cla">CLA</param>
        /// <param name="ins">INS</param>
        /// <param name="p1">P1</param>
        /// <param name="p2">P2</param>
        /// <param name="le">LE; -1 means no LE</param>
        /// <param name="data">Data</param>
        public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data, int le)
        {
            mCLA = cla;
            mINS = ins;
            mP1 = p1;
            mP2 = p2;
            if (data != null)
            {
                mLC = data.Length;
                mData = new byte[data.Length];
                System.Array.Copy(data, mData, mData.Length);
            }
            else
            {
                mLC = 0;
                mData = new byte[mLC];
            }
            mLE = le;
        }

        /// <summary>
        /// Constructs CommandAPDU from cla, ins, p1, p2 and data. It sets -1 for
        /// LE that means no LE.
        /// </summary>
        /// <param name="cla">CLA</param>
        /// <param name="ins">INS</param>
        /// <param name="p1">P1</param>
        /// <param name="p2">P2</param>
        /// <param name="data">Data</param>
        public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data)
            : this(cla, ins, p1, p2, data, -1)
        {
            
        }

        /// <summary>
        /// Constructs CommandAPDU from raw APDU.
        /// </summary>
        /// <param name="apdu">Raw APDU</param>
        /// <exception cref="Exception">
        /// * If apdu.Length is less than 5
        /// * If LC is not equal to (apdu.Length - 5) or (apdu.Length - 5 - 1)
        /// </exception>
        public CommandAPDU(byte[] apdu)
        {
            if (apdu.Length < 5)
                throw new Exception("Wrong APDU length.");

            mCLA = apdu[OFFSET_CLA];
            mINS = apdu[OFFSET_INS];
            mP1 = apdu[OFFSET_P1];
            mP2 = apdu[OFFSET_P2];
            mLC = apdu[OFFSET_LC];
            if (mLC == apdu.Length - 5)
                mLE = -1;
            else if (mLC == apdu.Length - 5 - 1)
                mLE = apdu[apdu.Length - 1];
            else
                throw new Exception("Wrong LC value.");
            mData = new byte[mLC];
            System.Array.Copy(apdu, OFFSET_CDATA, mData, 0, mData.Length);
        }
        #endregion

        #region Pubic Methods
        /// <summary>
        /// Converts CommandAPDU to corresponding byte array.
        /// </summary>
        /// <returns>Byte array corresponding to this CommandAPDU</returns>
        public byte[] ToByteArray()
        {
            int resultSize = mData.Length + 5;
            if (mLE != -1)
                resultSize += 1;
            byte[] result = new byte[resultSize];
            result[OFFSET_CLA] = (byte)mCLA;
            result[OFFSET_INS] = (byte)mINS;
            result[OFFSET_P1] = (byte)mP1;
            result[OFFSET_P2] = (byte)mP2;
            result[OFFSET_LC] = (byte)mLC;
            System.Array.Copy(mData, 0, result, OFFSET_CDATA, mData.Length);
            if (mLE != -1)
                result[result.Length - 1] = (byte)mLE;
            return result;

        }
        #endregion


    }
}
