using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace globalplatform.net
{
    /// <summary>
    /// A set of keys associated with a card or a secure channel
    /// </summary>
    public class KeySet
    {
        #region Static Fields
        #endregion

        #region Private Fields
        private readonly int mKeyVersion;
        private readonly int mKeyId;
        private Key mEncKey;
        private Key mMacKey;
        private Key mRmacKey;
        private Key mKekKey;
        #endregion

        #region Public Properties
        /// <summary>
        /// Key Version Number  within an on-card entity may be used to 
        /// differentiate instances or versions of the same key.
        /// </summary>
        public int KeyVersion{get{return mKeyVersion;}}

        /// <summary>
        /// ENC Key
        /// </summary>
        public Key EncKey
        {
            get { return mEncKey; }
            set { mEncKey = value; }
        }

        /// <summary>
        /// C-MAC Key
        /// </summary>
        public Key MacKey
        {
            get { return mMacKey; }
            set { mMacKey = value; }
        }

        /// <summary>
        /// R-MAC Key
        /// </summary>
        public Key RmacKey
        {
            get { return mRmacKey; }
            set { mRmacKey = value; }
        }

        /// <summary>
        /// KEK Key
        /// </summary>
        public Key KekKey
        {
            get { return mKekKey; }
            set { mKekKey = value; }
        }
        /// <summary>
        /// Key Identifier which identifies each key within an on-card entity.
        /// </summary>
        public int KeyId { get { return mKeyId; } }
        #endregion


        #region Public Methods

        /// <summary>
        /// Retrives key of the specified type.
        /// </summary>
        /// <param name="keyType">Key type:
        /// * <see cref="Key.KEY_TYPE_ENC"/>
        /// * <see cref="Key.KEY_TYPE_MAC"/>
        /// * <see cref="Key.KEY_TYPE_RMAC"/>
        /// * <see cref="Key.KEY_TYPE_KEK"/>
        /// </param>
        /// <returns>Retrieved key</returns>
        public Key RetrieveKey(int keyType)
        {
            Key key = null;
            switch (keyType)
            {
                case Key.KEY_TYPE_ENC:
                    key = mEncKey;
                    break;
                case Key.KEY_TYPE_MAC:
                    key = mMacKey;
                    break;
                case Key.KEY_TYPE_RMAC:
                    key = mRmacKey;
                    break;
                case Key.KEY_TYPE_KEK:
                    key = mKekKey;
                    break;
            }
            return key;
        }
        #endregion
        #region Constructors

        /// <summary>
        /// Constructs key set and sets key id and key version
        /// </summary>
        /// <param name="keyId">Key Id</param>
        /// <param name="keyVersion">Key version</param>

        public KeySet(int keyId = 0, int keyVersion = 0)
        {
            mKeyVersion = keyVersion;
            mKeyId = keyId;
        }

        #endregion

    }
}
