using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace globalplatform.net
{
    class SecureChannel
    {
        #region Private Fields
        private int mSecurityLevel;
        #endregion

        #region Public Properties
        /// <summary>
        /// Security level of establisged secure channel 
        /// </summary>
        public int SecurityLevel { get { return mSecurityLevel; } }

        #endregion
    }
}
