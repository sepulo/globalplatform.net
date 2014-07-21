using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace globalplatform.net
{
    class SecurityLevel
    {
        #region Static Fields

        /// <summary>
        /// NO SECURITY LEVEL
        /// </summary>
        public static int NO_SECURITY_LEVEL = 0x00;

        /// <summary>
        /// C-MAC
        /// </summary>
        public static int C_MAC = 0x01;

        /// <summary>
        /// C-DECRYPTION
        /// </summary>
        public static int C_DECRYPTION = 0x2;

        /// <summary>
        /// R-MAC
        /// </summary>
        public static int R_MAC = 0x10;


        #endregion
    }
}
