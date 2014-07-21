using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace globalplatform.net
{
    class KeySet
    {
        #region Static Fields
        #endregion
        #region Privare Fields
        private byte mKeyVersion;
        private byte mKeyID;
        #endregion
        #region Public Properties
        public byte KeyVersion{get{return mKeyVersion;}}
        public byte KeyID { get { return mKeyID; } }
        #endregion
        #region Public Methods
        #endregion
    }
}
