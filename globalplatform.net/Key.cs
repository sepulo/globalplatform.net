using System;

namespace globalplatform.net
{
    public class Key
    {
        #region Constant Fields

        public const int KEY_TYPE_ENC = 0x01;
        public const int KEY_TYPE_MAC = 0x02;
        public const int KEY_TYPE_KEK = 0x03;
        public const int KEY_TYPE_RMAC = 0x04;

        #endregion

        #region Private Fields

        private byte[] mValue;
        private readonly int mKeyId;
        private readonly int mKeyVersion;

        #endregion

        #region Public Properties

        /// <summary>
        /// Key value
        /// </summary>
        public byte[] Value
        {
            get { return mValue; }
        }

        /// <summary>
        /// Key version
        /// </summary>
        public int KeyVersion
        {
            get { return mKeyVersion; }
        }

        /// <summary>
        /// Key Id
        /// </summary>
        public int KeyId
        {
            get { return mKeyId; }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs a key from byte array
        /// </summary>
        /// <param name="value">Key value</param>
        /// <param name="keyId">Key Id</param>
        /// <param name="keyVersion">Key Version</param>
        public Key(byte[] value, int keyId = 0, int keyVersion = 0)
        {
            this.mValue = value;
            mKeyId = keyId;
            mKeyVersion = keyVersion;
        }

        /// <summary>
        /// Constructs a key from hex string represntation
        /// </summary>
        /// <param name="value">Key value</param>
        /// <param name="keyId">Key Id</param>
        /// <param name="keyVersion">Key Version</param>
        public Key(string value, int keyId = 0, int keyVersion = 0)
        {
            string hex = value;
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars/2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i/2] = Convert.ToByte(hex.Substring(i, 2), 16);

            this.mValue = bytes;
            mKeyId = keyId;
            mKeyVersion = keyVersion;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Builds 3DES key from this key value
        /// </summary>
        /// <returns></returns>
        public byte[] BuildTripleDesKey()
        {
            byte[] tdesKey = new byte[24];
            System.Array.Copy(mValue, 0, tdesKey, 0, 16);
            System.Array.Copy(mValue, 0, tdesKey, 16, 8);
            return tdesKey;
        }

        /// <summary>
        /// Builds DES key from this key value
        /// </summary>
        /// <returns></returns>
        public byte[] BuildDesKey()
        {
            byte[] desKey = new byte[8];
            System.Array.Copy(mValue, 0, desKey, 0, 8);
            return desKey;
        }

        #endregion
    }
}